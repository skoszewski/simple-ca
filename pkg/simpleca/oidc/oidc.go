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

// Package oidc is the OIDC sign-in of simple-ca, which exchanges the ID tokens of an OIDC
// provider for the tokens of the profiles of their users.
package oidc

import (
	"cmp"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/pkg/simpleca/tokens"
)

// The hooks of the sign-in, which the program serving it sets.
var (
	// ClientAddr returns the address of the client of a request.
	ClientAddr func(r *http.Request) netip.Addr
	// StatusError returns the error of a refused request, sent with its HTTP status.
	StatusError func(status int, format string, args ...any) error
	// ErrorStatus returns the status and the message of an error of StatusError, or false.
	ErrorStatus func(err error) (int, string, bool)
	// Reply writes v as the JSON answer with status.
	Reply func(w http.ResponseWriter, status int, v any)
	// Fail writes the error message as the JSON answer with status.
	Fail func(w http.ResponseWriter, status int, message string)
	// Attempt runs try for the client of r unless it is held back, and returns its error.
	Attempt func(w http.ResponseWriter, r *http.Request, dir string, try func() error) error
	// Page writes the redirect URI page of the sign-in of the root CA in rootDir, titled title.
	Page func(w io.Writer, rootDir, title string) error
)

const (
	// CallbackPath is the redirect URI path of the sign-in.
	CallbackPath = "/oidc-callback"
	// oidcMaxDocument is the size limit of a discovery document or JWKS.
	oidcMaxDocument = 1 << 20
	// maxBody is the largest body of a request for a token, in bytes.
	maxBody = 64 << 10
	// keysRefetch is the shortest interval between two fetches of the JWKS.
	keysRefetch = time.Minute
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

// Client serves the OIDC sign-in of the root CA in rootDir, caching the discovery document,
// the JWKS keys by key ID and the used nonces.
type Client struct {
	rootDir   string
	http      *http.Client
	mu        sync.Mutex
	issuer    string
	discovery *oidcDiscovery
	keys      map[string]crypto.PublicKey
	keysAt    time.Time
	nonces    map[string]time.Time
}

// NewClient returns the client of the OIDC sign-in of the root CA in rootDir.
func NewClient(rootDir string) *Client {
	return &Client{rootDir: rootDir, http: &http.Client{Timeout: 10 * time.Second}, nonces: map[string]time.Time{}}
}

// settings returns the resolved oidc section of simple-ca.json, and false when it is off.
func (c *Client) settings() (simpleca.OIDCConfig, bool, error) {
	cfg, err := simpleca.LoadConfig(c.rootDir)
	if err != nil {
		return simpleca.OIDCConfig{}, false, err
	}
	return Resolved(cfg.OIDC, cfg.Path)
}

// fetch reads the JSON document at url into v, at most oidcMaxDocument bytes.
func (c *Client) fetch(url string, v any) error {
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

// discover returns the cached discovery document of the issuer of oc, fetching it first, without
// c.mu held.
func (c *Client) discover(oc simpleca.OIDCConfig) (*oidcDiscovery, error) {
	c.mu.Lock()
	cached := c.discovery
	if c.issuer != oc.Issuer {
		cached = nil
	}
	c.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
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
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("the discovery document of %s names '%s', which is not an http or https URL", oc.Issuer, endpoint)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issuer, c.discovery, c.keys, c.keysAt = oc.Issuer, &d, nil, time.Time{}
	return &d, nil
}

// key returns the JWKS key kid of the provider of oc, or its only key for an empty kid, fetching
// the keys without c.mu held.
func (c *Client) key(oc simpleca.OIDCConfig, kid string) (crypto.PublicKey, error) {
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
	c.mu.Lock()
	k, ok := find()
	fetched := c.keys != nil && time.Since(c.keysAt) < keysRefetch
	c.mu.Unlock()
	switch {
	case ok:
		return k, nil
	case fetched:
		return nil, StatusError(http.StatusUnauthorized, "invalid ID token: the provider has no key '%s'", kid)
	}
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.fetch(d.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, raw := range jwks.Keys {
		var meta struct{ Kid, Use string }
		json.Unmarshal(raw, &meta)
		if meta.Use != "" && meta.Use != "sig" {
			continue
		}
		if pub, _, err := jose.ParseJWK(raw); err == nil {
			keys[meta.Kid] = pub
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys, c.keysAt = keys, time.Now()
	if k, ok := find(); ok {
		return k, nil
	}
	return nil, StatusError(http.StatusUnauthorized, "invalid ID token: the provider has no key '%s'", kid)
}

// checkIDToken verifies the ID token raw of the provider of oc and returns its claims, or an error
// of status 401; it leaves the nonce unused.
func (c *Client) checkIDToken(oc simpleca.OIDCConfig, raw string) (map[string]any, error) {
	invalid := func(reason string) error { return StatusError(http.StatusUnauthorized, "invalid ID token: %s", reason) }
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

	pub, err := c.key(oc, h.Kid)
	if err != nil {
		return nil, err
	}
	if jose.VerifyJWS(h.Alg, pub, []byte(parts[0]+"."+parts[1]), sig) != nil {
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
	c.mu.Lock()
	defer c.mu.Unlock()
	maps.DeleteFunc(c.nonces, func(_ string, until time.Time) bool { return !now.Before(until) })
	if _, used := c.nonces[nonce]; used {
		return nil, invalid("it has been used")
	}
	return claims, nil
}

// useNonce marks the nonce of claims used until the ID token expires, and reports whether it was
// unused.
func (c *Client) useNonce(claims map[string]any) bool {
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
func claimValues(claims map[string]any, paths simpleca.ClaimPaths, clientID string) []string {
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

// prepare returns the token name of the profile from tokens.PrepareToken, with the tokens
// defaults of cfg, and the key of its CA.
func (p *oidcProfile) prepare(rootDir string, cfg *simpleca.Config, name string) (*tokens.APIToken, crypto.Signer, error) {
	if p.CA != "" && !slices.Contains(simpleca.CAIDs(rootDir), p.CA) {
		return nil, nil, fmt.Errorf("'%s' is not an issuing CA of %s", p.CA, rootDir)
	}
	t, defaults := p.Token, cfg.Tokens
	valid := time.Hour
	if v := cmp.Or(t.Valid, defaults.Valid); v != "" {
		var err error
		if valid, err = simpleca.ParseDuration(v); err != nil {
			return nil, nil, err
		}
	}
	scopes := slices.Clone(t.Scopes)
	if len(scopes) == 0 {
		scopes = slices.Clone(defaults.Scopes)
	}
	var types, domains, ips []string
	if len(scopes) == 0 || tokens.Allows(scopes, "sign") {
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
		if t.Localhost {
			domains, ips = append(domains, "localhost"), append(ips, "127.0.0.1")
		}
	}
	clients := append(slices.Clone(t.Hosts), t.Networks...)
	if len(clients) == 0 {
		clients = append(slices.Clone(defaults.Hosts), defaults.Networks...)
	}
	return tokens.PrepareToken(filepath.Join(rootDir, p.CA), name, nil, valid, scopes, types, domains, ips, clients)
}

// Check validates the oidc section of cfg and the profiles of oidc-users.json of rootDir.
func Check(rootDir string, cfg *simpleca.Config) error {
	if _, _, err := Resolved(cfg.OIDC, cfg.Path); err != nil {
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
func (c *Client) configured(w http.ResponseWriter) (simpleca.OIDCConfig, bool) {
	oc, on, err := c.settings()
	switch {
	case err != nil:
		slog.Error("serve.error", "error", err.Error())
		Fail(w, http.StatusInternalServerError, "could not read the OIDC settings")
	case !on:
		Fail(w, http.StatusNotFound, "the OIDC sign-in is off")
	}
	return oc, err == nil && on
}

// APISettings answers GET /api/oidc with the settings of the sign-in.
func (c *Client) APISettings(w http.ResponseWriter, r *http.Request) {
	oc, ok := c.configured(w)
	if !ok {
		return
	}
	d, err := c.discover(oc)
	if err != nil {
		slog.Error("serve.error", "error", err.Error())
		Fail(w, http.StatusBadGateway, "could not read the discovery document of the OIDC provider")
		return
	}
	Reply(w, http.StatusOK, map[string]any{"provider": oc.Provider, "label": oc.Label, "client_id": oc.ClientID,
		"scopes": oc.Scopes, "authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint,
		"redirect_path": CallbackPath, "reuse_token": oc.ReuseToken})
}

// APIToken answers POST /api/oidc-token: it exchanges an ID token for the token of its user's
// profile.
func (c *Client) APIToken(w http.ResponseWriter, r *http.Request) {
	oc, ok := c.configured(w)
	if !ok {
		return
	}
	var req struct {
		IDToken string `json:"id_token"`
		Replace bool   `json:"replace"`
		Reuse   bool   `json:"reuse"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		Fail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	err := dec.Decode(&req)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		Fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the body is larger than %d bytes", maxBody))
		return
	}
	if err != nil || strings.TrimSpace(req.IDToken) == "" {
		Fail(w, http.StatusBadRequest, "the body is not a JSON object with the ID token")
		return
	}
	switch {
	case req.Replace && req.Reuse:
		Fail(w, http.StatusBadRequest, "replace and reuse exclude each other")
		return
	case req.Reuse && !oc.ReuseToken:
		Fail(w, http.StatusBadRequest, "reusing the active token is off: oidc.reuse_token is not set")
		return
	}
	client := ClientAddr(r)
	fail := func(err error) {
		if status, msg, ok := ErrorStatus(err); ok {
			Fail(w, status, msg)
			return
		}
		slog.Error("serve.error", "error", err.Error())
		Fail(w, http.StatusInternalServerError, "could not make the token")
	}

	var claims map[string]any
	err = Attempt(w, r, c.rootDir, func() (err error) {
		claims, err = c.checkIDToken(oc, strings.TrimSpace(req.IDToken))
		return err
	})
	if err != nil {
		fail(err)
		return
	}
	users := claimValues(claims, oc.UserClaim, oc.ClientID)
	if len(users) == 0 || users[0] == "" {
		fail(StatusError(http.StatusForbidden, "the ID token has no user claim %s", strings.Join(oc.UserClaim, " or ")))
		return
	}
	user := users[0]
	groups := claimValues(claims, oc.GroupsClaim, oc.ClientID)
	if names, ok := claims["_claim_names"].(map[string]any); ok && names["groups"] != nil && len(groups) == 0 {
		slog.Warn("oidc.groups", "user", user, "message", "the ID token has too many groups to hold them; "+
			"the user is matched by none")
	}
	roles := claimValues(claims, oc.RolesClaim, oc.ClientID)
	cfg, err := simpleca.LoadConfig(c.rootDir)
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
		fail(StatusError(http.StatusForbidden, "no profile of %s is given to %s", UsersFile, user))
		return
	}
	name := strings.Trim(oidcNameRE.ReplaceAllString(strings.ToLower(user), "-"), "-")
	if !simpleca.KebabCaseRE.MatchString(name) {
		fail(StatusError(http.StatusForbidden, "the user %s makes no token name", user))
		return
	}
	tok, caKey, err := profile.prepare(c.rootDir, cfg, name)
	if err != nil {
		fail(fmt.Errorf("profile %s: %w", profile.Name, err))
		return
	}
	if !tok.ClientAllowed(client) {
		fail(StatusError(http.StatusForbidden, "the token of %s is not used from %s", user, client))
		return
	}
	sub, _ := claims["sub"].(string)
	tok.OIDC = &tokens.TokenOIDC{Issuer: oc.Issuer, Subject: sub, User: user}
	dir := filepath.Join(c.rootDir, profile.CA)

	// Without replace or reuse, an active token of the user is reported instead.
	db, err := tokens.LoadTokens(dir)
	if err != nil {
		fail(err)
		return
	}
	if old, ok := db.Tokens[name]; ok && old.OwnedBy(tok.OIDC) && old.Active(time.Now()) && !req.Replace && !req.Reuse {
		Reply(w, http.StatusConflict, map[string]any{"error": "the token " + name + " of this user is active",
			"active": map[string]any{"ca": profile.CA, "name": name, "issued": old.Issued, "expires": old.Expires}})
		return
	}
	if !c.useNonce(claims) {
		fail(StatusError(http.StatusUnauthorized, "invalid ID token: it has been used"))
		return
	}
	jwt, given, err := oidcToken(dir, name, tok, caKey, req.Replace, req.Reuse)
	if err != nil {
		fail(err)
		return
	}
	action := "made"
	switch {
	case given != tok:
		action = "reused"
	case req.Replace:
		action = "replaced"
	}
	simpleca.Audit(dir, "token.oidc", "name", name, "user", user, "issuer", oc.Issuer, "profile", profile.Name, "action", action,
		"via", "oidc", "actor", user, "client", client.String())
	Reply(w, http.StatusOK, map[string]any{"ca": profile.CA, "name": name, "token": jwt, "scopes": given.EffectiveScopes()})
}

// CallbackPage serves the redirect URI page of the sign-in.
func (c *Client) CallbackPage(w http.ResponseWriter, r *http.Request) {
	caCert, err := simpleca.LoadCert(filepath.Join(c.rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := Page(w, c.rootDir, caCert.Subject.CommonName); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// oidcToken stores tok as the token name of caDir and returns its JWT and the token given; an
// active token of the same user is replaced with replace, or returned with reuse.
func oidcToken(caDir, name string, tok *tokens.APIToken, caKey crypto.Signer, replace, reuse bool) (string, *tokens.APIToken, error) {
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return "", nil, err
	}
	old, ok := db.Tokens[name]
	switch {
	case ok && !old.OwnedBy(tok.OIDC):
		return "", nil, StatusError(http.StatusConflict, "the token '%s' exists and is not the token of this user", name)
	case ok && old.Active(time.Now()) && reuse:
		jwt, err := tokens.SignToken(caKey, name, old)
		return jwt, old, err
	case ok && old.Active(time.Now()) && !replace:
		return "", nil, StatusError(http.StatusConflict, "the token '%s' of this user is active; replace it or use it", name)
	}
	jwt, err := tokens.SignToken(caKey, name, tok)
	if err != nil {
		return "", nil, err
	}
	db.Tokens[name] = tok
	return jwt, tok, db.Save(caDir)
}
