// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"cmp"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"maps"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// ---- OIDC sign-in -----------------------------------------------------------

const (
	// oidcCallbackPath is the redirect URI path of the sign-in.
	oidcCallbackPath = "/oidc-callback"
	// oidcMaxDocument is the size limit of a discovery document or JWKS.
	oidcMaxDocument = 1 << 20
	// oidcKeysRefetch is the shortest interval between two fetches of the JWKS.
	oidcKeysRefetch = time.Minute
	// oidcSkew is the clock skew allowed for iat.
	oidcSkew = 2 * time.Minute
)

// oidcAlgorithms are the accepted signature algorithms of an ID token.
var oidcAlgorithms = []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"}

// oidcNameRE matches the characters replaced by a hyphen in a token name made from a user claim.
var oidcNameRE = regexp.MustCompile(`[^a-z0-9]+`)

// oidcDiscovery holds the fields of a discovery document.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcClient serves the OIDC sign-in of the root CA in rootDir, caching the discovery document,
// the JWKS keys by key ID and the used nonces.
type oidcClient struct {
	rootDir   string
	http      *http.Client
	mu        sync.Mutex
	issuer    string
	discovery *oidcDiscovery
	keys      map[string]crypto.PublicKey
	keysAt    time.Time
	nonces    map[string]time.Time
}

// newOIDCClient returns the client of the OIDC sign-in of the root CA in rootDir.
func newOIDCClient(rootDir string) *oidcClient {
	return &oidcClient{rootDir: rootDir, http: &http.Client{Timeout: 10 * time.Second}, nonces: map[string]time.Time{}}
}

// settings returns the resolved oidc section of simple-ca.json, and false when it is off.
func (c *oidcClient) settings() (oidcConfig, bool, error) {
	cfg, err := loadConfig(c.rootDir)
	if err != nil {
		return oidcConfig{}, false, err
	}
	return cfg.OIDC.resolved(cfg.path)
}

// fetch reads the JSON document at url into v, at most oidcMaxDocument bytes.
func (c *oidcClient) fetch(url string, v any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answers %s", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, oidcMaxDocument)).Decode(v); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}

// discover returns the cached discovery document of the issuer of oc, fetching it first; c.mu is
// held.
func (c *oidcClient) discover(oc oidcConfig) (*oidcDiscovery, error) {
	if c.issuer == oc.Issuer && c.discovery != nil {
		return c.discovery, nil
	}
	c.issuer, c.discovery, c.keys, c.keysAt = oc.Issuer, nil, nil, time.Time{}
	var d oidcDiscovery
	if err := c.fetch(strings.TrimSuffix(oc.Issuer, "/")+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	switch {
	case d.Issuer != oc.Issuer:
		return nil, fmt.Errorf("the discovery document of %s names the issuer '%s'", oc.Issuer, d.Issuer)
	case d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "":
		return nil, fmt.Errorf("the discovery document of %s lacks an endpoint or jwks_uri", oc.Issuer)
	}
	c.discovery = &d
	return c.discovery, nil
}

// key returns the JWKS key kid of the provider of oc, or its only key for an empty kid; c.mu is
// held.
func (c *oidcClient) key(oc oidcConfig, kid string) (crypto.PublicKey, error) {
	d, err := c.discover(oc)
	if err != nil {
		return nil, err
	}
	find := func() (crypto.PublicKey, bool) {
		if kid == "" && len(c.keys) == 1 {
			for _, k := range c.keys {
				return k, true
			}
		}
		k, ok := c.keys[kid]
		return k, ok && kid != ""
	}
	if k, ok := find(); ok {
		return k, nil
	}
	if c.keys != nil && time.Since(c.keysAt) < oidcKeysRefetch {
		return nil, apiErr(http.StatusUnauthorized, "invalid ID token: the provider has no key '%s'", kid)
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.fetch(d.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	c.keys, c.keysAt = map[string]crypto.PublicKey{}, time.Now()
	for _, raw := range jwks.Keys {
		var meta struct{ Kid, Use string }
		json.Unmarshal(raw, &meta)
		if meta.Use != "" && meta.Use != "sig" {
			continue
		}
		if pub, _, err := parseJWK(raw); err == nil {
			c.keys[meta.Kid] = pub
		}
	}
	if k, ok := find(); ok {
		return k, nil
	}
	return nil, apiErr(http.StatusUnauthorized, "invalid ID token: the provider has no key '%s'", kid)
}

// checkIDToken verifies the ID token raw of the provider of oc and returns its claims, or an error
// of status 401; it leaves the nonce unused.
func (c *oidcClient) checkIDToken(oc oidcConfig, raw string) (map[string]any, error) {
	invalid := func(reason string) error { return apiErr(http.StatusUnauthorized, "invalid ID token: %s", reason) }
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, invalid("not a JWT")
	}
	header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	var h struct{ Alg, Kid string }
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(header, &h) != nil {
		return nil, invalid("not a JWT")
	}
	if !slices.Contains(oidcAlgorithms, h.Alg) {
		return nil, invalid("the algorithm '" + h.Alg + "' is not accepted")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	pub, err := c.key(oc, h.Kid)
	if err != nil {
		return nil, err
	}
	if verifyJWS(h.Alg, pub, []byte(parts[0]+"."+parts[1]), sig) != nil {
		return nil, invalid("the signature does not verify")
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil, invalid("the claims do not read")
	}
	str := func(name string) string { s, _ := claims[name].(string); return s }
	unix := func(name string) (time.Time, bool) {
		n, ok := claims[name].(float64)
		return time.Unix(int64(n), 0), ok
	}
	var audience []string
	switch aud := claims["aud"].(type) {
	case string:
		audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audience = append(audience, s)
			}
		}
	}
	now := time.Now()
	exp, hasExp := unix("exp")
	iat, hasIat := unix("iat")
	nonce := str("nonce")
	switch {
	case str("iss") != oc.Issuer:
		return nil, invalid("issued by '" + str("iss") + "', not by " + oc.Issuer)
	case !slices.Contains(audience, oc.ClientID):
		return nil, invalid("not issued for the client " + oc.ClientID)
	case str("azp") != "" && str("azp") != oc.ClientID:
		return nil, invalid("authorized for the client '" + str("azp") + "'")
	case !hasExp || !now.Before(exp):
		return nil, invalid("expired")
	case !hasIat || iat.After(now.Add(oidcSkew)):
		return nil, invalid("issued in the future")
	case str("sub") == "":
		return nil, invalid("no subject")
	case nonce == "":
		return nil, invalid("no nonce")
	}
	maps.DeleteFunc(c.nonces, func(_ string, until time.Time) bool { return !now.Before(until) })
	if _, used := c.nonces[nonce]; used {
		return nil, invalid("it has been used")
	}
	return claims, nil
}

// useNonce marks the nonce of claims used until the ID token expires, and reports whether it was
// unused.
func (c *oidcClient) useNonce(claims map[string]any) bool {
	nonce, _ := claims["nonce"].(string)
	exp, _ := claims["exp"].(float64)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.nonces[nonce]; used {
		return false
	}
	c.nonces[nonce] = time.Unix(int64(exp), 0)
	return true
}

// claimValues returns the strings of claims at the dotted paths, CLIENT_ID replaced by clientID.
func claimValues(claims map[string]any, paths claimPaths, clientID string) []string {
	var values []string
	for _, path := range paths {
		var v any = claims
		for _, segment := range strings.Split(path, ".") {
			if segment == "CLIENT_ID" {
				segment = clientID
			}
			m, ok := v.(map[string]any)
			if !ok {
				v = nil
				break
			}
			v = m[segment]
		}
		switch v := v.(type) {
		case string:
			values = append(values, v)
		case []any:
			for _, s := range v {
				if s, ok := s.(string); ok {
					values = append(values, s)
				}
			}
		}
	}
	return values
}

// profileFor returns the profile of the first rule matching the user or a group, else the first
// profile named by a role, else nil.
func (u *oidcUsers) profileFor(user string, groups, roles []string) *oidcProfile {
	find := func(name string) *oidcProfile {
		i := slices.IndexFunc(u.Profiles, func(p oidcProfile) bool { return p.Name == name })
		return &u.Profiles[i]
	}
	for _, r := range u.Rules {
		if slices.Contains(r.Users, user) || slices.ContainsFunc(r.Groups, func(g string) bool { return slices.Contains(groups, g) }) {
			return find(r.Profile)
		}
	}
	for i, p := range u.Profiles {
		if slices.Contains(roles, p.Name) {
			return &u.Profiles[i]
		}
	}
	return nil
}

// prepare returns the token name of the profile from prepareToken, with the tokens defaults of cfg,
// and the key of its CA.
func (p *oidcProfile) prepare(rootDir string, cfg *config, name string) (*apiToken, *rsa.PrivateKey, error) {
	if p.CA != "" && !slices.Contains(caIDs(rootDir), p.CA) {
		return nil, nil, fmt.Errorf("'%s' is not an issuing CA of %s", p.CA, rootDir)
	}
	t, defaults := p.Token, cfg.Tokens
	valid := time.Hour
	if v := cmp.Or(t.Valid, defaults.Valid); v != "" {
		var err error
		if valid, err = time.ParseDuration(v); err != nil {
			return nil, nil, fmt.Errorf("'%s' is not a duration such as 8h", v)
		}
	}
	scopes := slices.Clone(t.Scopes)
	if len(scopes) == 0 {
		scopes = slices.Clone(defaults.Scopes)
	}
	var types, domains, ips []string
	if len(scopes) == 0 || allows(scopes, "sign") {
		types, domains, ips = slices.Clone(t.Types), slices.Clone(t.Domains), slices.Clone(t.IPs)
		if len(types) == 0 {
			types = slices.Clone(defaults.Types)
		}
		if len(domains) == 0 {
			domains = slices.Clone(defaults.Domains)
		}
		if len(ips) == 0 {
			ips = slices.Clone(defaults.IPs)
		}
		if len(types) == 0 {
			types = []string{"server"}
		}
		if t.Localhost || defaults.Localhost {
			domains, ips = append(domains, "localhost"), append(ips, "127.0.0.1")
		}
	}
	clients := append(slices.Clone(t.Hosts), t.Networks...)
	if len(clients) == 0 {
		clients = append(slices.Clone(defaults.Hosts), defaults.Networks...)
	}
	return prepareToken(filepath.Join(rootDir, p.CA), name, valid, scopes, types, domains, ips, clients)
}

// checkOIDC validates the oidc section of cfg and the profiles of oidc-users.json of rootDir.
func checkOIDC(rootDir string, cfg *config) error {
	if _, _, err := cfg.OIDC.resolved(cfg.path); err != nil {
		return err
	}
	users, err := loadOIDCUsers(rootDir)
	if err != nil {
		return err
	}
	for _, p := range users.Profiles {
		if _, _, err := p.prepare(rootDir, cfg, p.Name); err != nil {
			return fmt.Errorf("profile %s of %s: %w", p.Name, users.path, err)
		}
	}
	return nil
}

// configured returns the OIDC settings, or answers with an error and returns false.
func (c *oidcClient) configured(w http.ResponseWriter) (oidcConfig, bool) {
	oc, on, err := c.settings()
	switch {
	case err != nil:
		log.Printf("oidc: %v", err)
		webuiFail(w, http.StatusInternalServerError, "could not read the OIDC settings")
	case !on:
		webuiFail(w, http.StatusNotFound, "the OIDC sign-in is off")
	}
	return oc, err == nil && on
}

// apiSettings answers GET /api/oidc with the settings of the sign-in.
func (c *oidcClient) apiSettings(w http.ResponseWriter, r *http.Request) {
	oc, ok := c.configured(w)
	if !ok {
		return
	}
	c.mu.Lock()
	d, err := c.discover(oc)
	c.mu.Unlock()
	if err != nil {
		log.Printf("oidc: %v", err)
		webuiFail(w, http.StatusBadGateway, "could not read the discovery document of the OIDC provider")
		return
	}
	webuiReply(w, http.StatusOK, map[string]any{"provider": oc.Provider, "label": oc.Label, "client_id": oc.ClientID,
		"scopes": oc.Scopes, "authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint,
		"redirect_path": oidcCallbackPath, "reuse_token": oc.ReuseToken})
}

// apiToken answers POST /api/oidc-token: it exchanges an ID token for the token of its user's
// profile.
func (c *oidcClient) apiToken(w http.ResponseWriter, r *http.Request) {
	oc, ok := c.configured(w)
	if !ok {
		return
	}
	var req struct {
		IDToken string `json:"id_token"`
		Replace bool   `json:"replace"`
		Reuse   bool   `json:"reuse"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, acmeMaxBody))
	dec.DisallowUnknownFields()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		webuiFail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.IDToken) == "" {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object with the ID token")
		return
	}
	switch {
	case req.Replace && req.Reuse:
		webuiFail(w, http.StatusBadRequest, "replace and reuse exclude each other")
		return
	case req.Reuse && !oc.ReuseToken:
		webuiFail(w, http.StatusBadRequest, "reusing the active token is off: oidc.reuse_token is not set")
		return
	}
	client := clientAddr(r)
	fail := func(err error) {
		var refused *apiError
		if errors.As(err, &refused) {
			webuiFail(w, refused.status, refused.msg)
			return
		}
		log.Printf("oidc: %v", err)
		webuiFail(w, http.StatusInternalServerError, "could not make the token")
	}

	var claims map[string]any
	err := guard.attempt(w, client, func() (err error) {
		claims, err = c.checkIDToken(oc, strings.TrimSpace(req.IDToken))
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	users := claimValues(claims, oc.UserClaim, oc.ClientID)
	if len(users) == 0 || users[0] == "" {
		fail(apiErr(http.StatusForbidden, "the ID token has no user claim %s", strings.Join(oc.UserClaim, " or ")))
		return
	}
	user := users[0]
	groups := claimValues(claims, oc.GroupsClaim, oc.ClientID)
	if names, ok := claims["_claim_names"].(map[string]any); ok && names["groups"] != nil && len(groups) == 0 {
		log.Printf("oidc: the ID token of %s has too many groups to hold them; the user is matched by none", user)
	}
	roles := claimValues(claims, oc.RolesClaim, oc.ClientID)
	cfg, err := loadConfig(c.rootDir)
	if err != nil {
		fail(err)
		return
	}
	profiles, err := loadOIDCUsers(c.rootDir)
	if err != nil {
		fail(err)
		return
	}
	profile := profiles.profileFor(user, groups, roles)
	if profile == nil {
		fail(apiErr(http.StatusForbidden, "no profile of %s is given to %s", oidcUsersFile, user))
		return
	}
	name := strings.Trim(oidcNameRE.ReplaceAllString(strings.ToLower(user), "-"), "-")
	if !kebabCaseRE.MatchString(name) {
		fail(apiErr(http.StatusForbidden, "the user %s makes no token name", user))
		return
	}
	tok, caKey, err := profile.prepare(c.rootDir, cfg, name)
	if err != nil {
		fail(fmt.Errorf("profile %s: %w", profile.Name, err))
		return
	}
	if !tok.clientAllowed(client) {
		fail(apiErr(http.StatusForbidden, "the token of %s is not used from %s", user, client))
		return
	}
	sub, _ := claims["sub"].(string)
	tok.OIDC = &tokenOIDC{Issuer: oc.Issuer, Subject: sub, User: user}
	dir := filepath.Join(c.rootDir, profile.CA)

	// Without replace or reuse, an active token of the user is reported instead.
	db, err := loadTokens(dir)
	if err != nil {
		fail(err)
		return
	}
	if old, ok := db.Tokens[name]; ok && old.ownedBy(tok.OIDC) && old.active(time.Now()) && !req.Replace && !req.Reuse {
		webuiReply(w, http.StatusConflict, map[string]any{"error": "the token " + name + " of this user is active",
			"active": map[string]any{"ca": profile.CA, "name": name, "issued": old.Issued, "expires": old.Expires}})
		return
	}
	if !c.useNonce(claims) {
		fail(apiErr(http.StatusUnauthorized, "invalid ID token: it has been used"))
		return
	}
	jwt, given, err := oidcToken(dir, name, tok, caKey, req.Replace, req.Reuse)
	if err != nil {
		fail(err)
		return
	}
	verb := "made"
	if given != tok {
		verb = "given again"
	}
	log.Printf("token %s of %s %s for OIDC user %s from %s", name, dir, verb, user, client)
	webuiReply(w, http.StatusOK, map[string]any{"ca": profile.CA, "name": name, "token": jwt, "scopes": given.scopes()})
}

// callbackPage serves the redirect URI page of the sign-in.
func (c *oidcClient) callbackPage(w http.ResponseWriter, r *http.Request) {
	caCert, err := loadCert(filepath.Join(c.rootDir, "ca_cert.pem"))
	if err != nil {
		log.Printf("%s: %v", r.URL.Path, err)
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplates.ExecuteTemplate(w, "oidc-callback.html", struct {
		Title, Script string
		Theme         template.CSS
	}{caCert.Subject.CommonName, tailwindPath, pageTheme(c.rootDir)}); err != nil {
		log.Printf("%s: %v", r.URL.Path, err)
	}
}
