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
	"bytes"
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
	"github.com/skoszewski/simple-ca/src/pkg/weburl"
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
	// Bearer authenticates the bearer token of r, of the root CA in dir or one of its issuing CAs,
	// with the scope, and returns its name, its CA and the token, or answers with the error and
	// returns false.
	Bearer func(w http.ResponseWriter, r *http.Request, dir, scope string) (name, ca string, tok *tokens.APIToken, ok bool)
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

// oidcDiscovery holds the fields of a discovery document; the device authorization endpoint is
// optional.
type oidcDiscovery struct {
	Issuer                      string `json:"issuer"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JWKSURI                     string `json:"jwks_uri"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// idToken is a checked ID token: its claims, the client it was issued for, the key marking it
// used, its nonce or else the SHA-256 of the token, and its expiry.
type idToken struct {
	claims   map[string]any
	clientID string
	useKey   string
	expires  time.Time
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
		return fmt.Errorf("%q answers %q", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, oidcMaxDocument)).Decode(v); err != nil {
		return fmt.Errorf("%q: %w", url, err)
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
		return nil, fmt.Errorf("the discovery document of %q names the issuer %q", oc.Issuer, d.Issuer)
	case d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "":
		return nil, fmt.Errorf("the discovery document of %q lacks an endpoint or jwks_uri", oc.Issuer)
	}
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI, d.DeviceAuthorizationEndpoint} {
		if endpoint == d.DeviceAuthorizationEndpoint && endpoint == "" {
			continue
		}
		if _, err := weburl.Endpoint(endpoint, false); err != nil {
			return nil, fmt.Errorf("the discovery document of %q: %w", oc.Issuer, err)
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
		return nil, StatusError(http.StatusUnauthorized, "invalid ID token: the provider has no key %q", kid)
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
	return nil, StatusError(http.StatusUnauthorized, "invalid ID token: the provider has no key %q", kid)
}

// checkIDToken verifies the ID token raw of the provider of oc, issued for one of clientIDs and
// with a nonce when needNonce, and returns it, or an error of status 401; it leaves it unused.
func (c *Client) checkIDToken(oc simpleca.OIDCConfig, raw string, clientIDs []string, needNonce bool) (*idToken, error) {
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
		return nil, invalid(fmt.Sprintf("the algorithm %q is not accepted", h.Alg))
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
	// The client is the authorized party, else the one client of clientIDs in the audience.
	clientID := str("azp")
	if clientID == "" {
		for _, a := range audience {
			if slices.Contains(clientIDs, a) {
				clientID = a
				break
			}
		}
	}
	quoted := make([]string, len(clientIDs))
	for i, id := range clientIDs {
		quoted[i] = strconv.Quote(id)
	}
	switch {
	case str("iss") != oc.Issuer:
		return nil, invalid(fmt.Sprintf("issued by %q, not by %q", str("iss"), oc.Issuer))
	case clientID == "" || !slices.Contains(audience, clientID):
		return nil, invalid(fmt.Sprintf("not issued for the client %s", strings.Join(quoted, " or ")))
	case !slices.Contains(clientIDs, clientID):
		return nil, invalid(fmt.Sprintf("authorized for the client %q", clientID))
	case !hasExp || !now.Before(exp):
		return nil, invalid("expired")
	case !hasIat || iat.After(now.Add(oidcSkew)):
		return nil, invalid("issued in the future")
	case str("sub") == "":
		return nil, invalid("no subject")
	case nonce == "" && needNonce:
		return nil, invalid("no nonce")
	}
	useKey := "nonce:" + nonce
	if nonce == "" {
		sum := sha256.Sum256([]byte(raw))
		useKey = "sha256:" + hex.EncodeToString(sum[:])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	maps.DeleteFunc(c.nonces, func(_ string, until time.Time) bool { return !now.Before(until) })
	if _, used := c.nonces[useKey]; used {
		return nil, invalid("it has been used")
	}
	return &idToken{claims: claims, clientID: clientID, useKey: useKey, expires: exp}, nil
}

// use marks the ID token used until it expires, and reports whether it was unused.
func (c *Client) use(t *idToken) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.nonces[t.useKey]; used {
		return false
	}
	c.nonces[t.useKey] = t.expires
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

// cliTokenValid is the validity of the token of a sign-in of request-cert.
const cliTokenValid = 10 * time.Minute

// prepare returns the token name of the profile from tokens.PrepareToken, with the tokens
// defaults of cfg, and the key of its CA. A profile that gives a certificate adds the scope
// self-cert, and one that gives no token has it alone; for request-cert, cli, the token has the
// scope self-cert alone and is valid for cliTokenValid.
func (p *oidcProfile) prepare(rootDir string, cfg *simpleca.Config, name string, cli bool) (*tokens.APIToken, crypto.Signer, error) {
	if p.CA != "" && !slices.Contains(simpleca.CAIDs(rootDir), p.CA) {
		return nil, nil, fmt.Errorf("%q is not an issuing CA of %q", p.CA, rootDir)
	}
	var t profileToken
	if p.Token != nil {
		t = *p.Token
	}
	defaults := cfg.Tokens
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
	if cli || !p.givesToken() {
		scopes = nil
	}
	var types, domains, ips []string
	if !cli && p.givesToken() && (len(scopes) == 0 || tokens.Allows(scopes, "sign")) {
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
	// The scope * stands for every scope but self-cert, which is added beside them.
	if p.givesCertificate() {
		switch {
		case slices.Contains(scopes, "*"):
			scopes = slices.DeleteFunc(slices.Clone(tokens.TokenScopes), func(s string) bool { return s == tokens.SelfCert })
		case len(scopes) == 0 && p.givesToken() && !cli:
			scopes = []string{"sign"}
		}
		scopes = append(scopes, tokens.SelfCert)
	}
	if cli {
		valid = cliTokenValid
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
		if _, _, err := p.prepare(rootDir, cfg, p.Name, false); err != nil {
			return fmt.Errorf("profile %s of %q: %w", p.Name, users.path, err)
		}
		switch {
		case p.givesCertificate():
			if _, err := p.certificate(rootDir, cfg, users.userEKUs()); err != nil {
				return fmt.Errorf("profile %s of %q: certificate: %w", p.Name, users.path, err)
			}
		case p.Certificate != nil:
			slog.Warn("oidc.profile", "profile", p.Name, "message", "the certificate has no ca; the profile gives no certificate")
		}
	}
	return nil
}

// certSettings are the settings of the certificate of a profile: the directory of its CA, the
// certificate types it offers, its validity in days, and the domains of its email address, any
// without them.
type certSettings struct {
	caDir        string
	types        []string
	days         int
	emailDomains []string
}

// certificate returns the settings of the certificate of the profile, which gives one, with the
// days.cert default of cfg; each of its types has the user name rules and extended key usages that
// meet rule.
func (p *oidcProfile) certificate(rootDir string, cfg *simpleca.Config, rule *ekuRule) (*certSettings, error) {
	pc := p.Certificate
	if *pc.CA != "" && !slices.Contains(simpleca.CAIDs(rootDir), *pc.CA) {
		return nil, fmt.Errorf("ca %q is not an issuing CA of %q", *pc.CA, rootDir)
	}
	switch {
	case len(pc.Types) == 0:
		return nil, errors.New("types needs a certificate type")
	case pc.Days < 0:
		return nil, errors.New("days must be a positive integer")
	}
	s := &certSettings{caDir: filepath.Join(rootDir, *pc.CA), types: pc.Types, days: cmp.Or(pc.Days, cfg.Days.Cert, 365)}
	types, err := cert.Types(cfg)
	if err != nil {
		return nil, err
	}
	for _, name := range pc.Types {
		def, ok := types[name]
		if !ok {
			return nil, fmt.Errorf("unknown type %q: must be one of %s", name, cert.TypeNames(types))
		}
		oids, err := cert.EKUOIDs(def.ExtKeyUsage)
		switch {
		case err != nil:
			return nil, fmt.Errorf("type %q: %w", name, err)
		case len(oids) == 0:
			return nil, fmt.Errorf("the type %q has no extended key usages", name)
		case def.Names != "user":
			return nil, fmt.Errorf("the type %q has the server name rules; a user certificate needs the user name rules", name)
		case !rule.matches(oids):
			return nil, fmt.Errorf("the extended key usages of the type %q, %s, do not meet user_ekus", name,
				strings.Join(def.ExtKeyUsage, ", "))
		}
	}
	for _, d := range pc.EmailDomains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if !simpleca.IsHostname(d) {
			return nil, fmt.Errorf("email domain %q is not a domain name", d)
		}
		s.emailDomains = append(s.emailDomains, d)
	}
	return s, nil
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
	settings := map[string]any{"provider": oc.Provider, "label": oc.Label, "client_id": oc.ClientID,
		"scopes": oc.Scopes, "authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint,
		"redirect_path": CallbackPath, "reuse_token": oc.ReuseToken}
	if oc.CLIClientID != "" {
		settings["cli_client_id"], settings["cli_scopes"], settings["email_claim"] = oc.CLIClientID, oc.CLIScopes, oc.EmailClaim
		if d.DeviceAuthorizationEndpoint != "" {
			settings["device_authorization_endpoint"] = d.DeviceAuthorizationEndpoint
		}
	}
	Reply(w, http.StatusOK, settings)
}

// decodeBody decodes the JSON body of r, at most maxBody bytes and without unknown keys, into v,
// or answers with an error, malformed for a body that does not decode, and returns false.
func decodeBody(w http.ResponseWriter, r *http.Request, v any, malformed string) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		Fail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		Fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the body is larger than %d bytes", maxBody))
		return false
	case err != nil:
		Fail(w, http.StatusBadRequest, malformed)
		return false
	}
	return true
}

// failer returns the function answering a request with an error: an error of StatusError with
// its status, any other logged and answered as 500 with message.
func failer(w http.ResponseWriter, message string) func(error) {
	return func(err error) {
		if status, msg, ok := ErrorStatus(err); ok {
			Fail(w, status, msg)
			return
		}
		slog.Error("serve.error", "error", err.Error())
		Fail(w, http.StatusInternalServerError, message)
	}
}

// signedIn is the user of a checked ID token: the token, the user claim, the name the user gets
// in a CA, the profile of the user and simple-ca.json.
type signedIn struct {
	token   *idToken
	user    string
	name    string
	profile *oidcProfile
	cfg     *simpleca.Config
}

// signIn checks the ID token raw for the client of r, issued for one of clientIDs and with a
// nonce when needNonce, and returns its user with the profile of oidc-users.json the user gets.
func (c *Client) signIn(w http.ResponseWriter, r *http.Request, oc simpleca.OIDCConfig, raw string, clientIDs []string,
	needNonce bool) (*signedIn, error) {
	var t *idToken
	err := Attempt(w, r, c.rootDir, func() (err error) {
		t, err = c.checkIDToken(oc, raw, clientIDs, needNonce)
		return err
	})
	if err != nil {
		return nil, err
	}
	users := claimValues(t.claims, oc.UserClaim, t.clientID)
	if len(users) == 0 || users[0] == "" {
		claimNames := make([]string, len(oc.UserClaim))
		for i, p := range oc.UserClaim {
			claimNames[i] = strconv.Quote(p)
		}
		return nil, StatusError(http.StatusForbidden, "the ID token has no user claim %s", strings.Join(claimNames, " or "))
	}
	user := users[0]
	groups := claimValues(t.claims, oc.GroupsClaim, t.clientID)
	if names, ok := t.claims["_claim_names"].(map[string]any); ok && names["groups"] != nil && len(groups) == 0 {
		slog.Warn("oidc.groups", "user", user, "message", "the ID token has too many groups to hold them; "+
			"the user is matched by none")
	}
	roles := claimValues(t.claims, oc.RolesClaim, t.clientID)
	cfg, err := simpleca.LoadConfig(c.rootDir)
	if err != nil {
		return nil, err
	}
	profiles, err := loadOIDCUsers(c.rootDir)
	if err != nil {
		return nil, err
	}
	profile := profiles.profileFor(user, groups, roles)
	if profile == nil {
		return nil, StatusError(http.StatusForbidden, "no profile of %s is given to %q", UsersFile, user)
	}
	name := strings.Trim(oidcNameRE.ReplaceAllString(strings.ToLower(user), "-"), "-")
	if !simpleca.KebabCaseRE.MatchString(name) {
		return nil, StatusError(http.StatusForbidden, "the user %q makes no token name", user)
	}
	return &signedIn{token: t, user: user, name: name, profile: profile, cfg: cfg}, nil
}

// APIToken answers POST /api/oidc-token: it exchanges an ID token for a token of its user's
// profile. An ID token of the client of the pages gives the token of the profile; one of the
// client of request-cert, of a profile that gives a certificate, gives the token NAME-cli of the
// scope self-cert alone, valid for cliTokenValid, which replaces the one before it.
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
	if !decodeBody(w, r, &req, "the body is not a JSON object with the ID token") {
		return
	}
	switch {
	case strings.TrimSpace(req.IDToken) == "":
		Fail(w, http.StatusBadRequest, "the body is not a JSON object with the ID token")
		return
	case req.Replace && req.Reuse:
		Fail(w, http.StatusBadRequest, "replace and reuse exclude each other")
		return
	case req.Reuse && !oc.ReuseToken:
		Fail(w, http.StatusBadRequest, "reusing the active token is off: oidc.reuse_token is not set")
		return
	}
	client := ClientAddr(r)
	fail := failer(w, "could not make the token")

	clientIDs := []string{oc.ClientID}
	if oc.CLIClientID != "" {
		clientIDs = append(clientIDs, oc.CLIClientID)
	}
	s, err := c.signIn(w, r, oc, strings.TrimSpace(req.IDToken), clientIDs, false)
	if err != nil {
		fail(err)
		return
	}
	user, name, profile := s.user, s.name, s.profile
	cli := s.token.clientID == oc.CLIClientID
	switch {
	case !cli && !strings.HasPrefix(s.token.useKey, "nonce:"):
		fail(StatusError(http.StatusUnauthorized, "invalid ID token: no nonce"))
		return
	case cli && (req.Replace || req.Reuse):
		fail(StatusError(http.StatusBadRequest, "the token of request-cert is replaced without replace or reuse"))
		return
	case cli && !profile.givesCertificate():
		fail(StatusError(http.StatusForbidden, "the profile %s of %q gives no certificate", profile.Name, user))
		return
	}
	if cli {
		name += "-cli"
	}
	tok, caKey, err := profile.prepare(c.rootDir, s.cfg, name, cli)
	if err != nil {
		fail(fmt.Errorf("profile %s: %w", profile.Name, err))
		return
	}
	if !tok.ClientAllowed(client) {
		fail(StatusError(http.StatusForbidden, "the token of %q is not used from %s", user, client))
		return
	}
	sub, _ := s.token.claims["sub"].(string)
	tok.OIDC = &tokens.TokenOIDC{Issuer: oc.Issuer, Subject: sub, User: user}
	if profile.givesCertificate() {
		tok.OIDC.Profile = profile.Name
		tok.OIDC.Email, tok.OIDC.Name = certIdentity(oc, s.token)
	}
	dir := filepath.Join(c.rootDir, profile.CA)

	// Without replace or reuse, an active token of the user is reported instead.
	db, err := tokens.LoadTokens(dir)
	if err != nil {
		fail(err)
		return
	}
	if old, ok := db.Tokens[name]; !cli && ok && old.OwnedBy(tok.OIDC) && old.Active(time.Now()) && !req.Replace && !req.Reuse {
		Reply(w, http.StatusConflict, map[string]any{"error": "the token " + name + " of this user is active",
			"active": map[string]any{"ca": profile.CA, "name": name, "issued": old.Issued, "expires": old.Expires}})
		return
	}
	if !c.use(s.token) {
		fail(StatusError(http.StatusUnauthorized, "invalid ID token: it has been used"))
		return
	}
	jwt, given, err := oidcToken(dir, name, tok, caKey, req.Replace || cli, req.Reuse)
	if err != nil {
		fail(err)
		return
	}
	action := "made"
	switch {
	case given != tok:
		action = "reused"
	case req.Replace || cli:
		action = "replaced"
	}
	simpleca.Audit(dir, "token.oidc", "name", name, "user", user, "issuer", oc.Issuer, "client_id", s.token.clientID,
		"profile", profile.Name, "action", action, "via", "oidc", "actor", user, "client", client.String())
	Reply(w, http.StatusOK, map[string]any{"ca": profile.CA, "name": name, "token": jwt, "scopes": given.EffectiveScopes(),
		"user": user})
}

// certIdentity returns the email address of the email claim of the ID token, empty when it is no
// email address or is not verified, and the name of its name claim, of the user certificate.
func certIdentity(oc simpleca.OIDCConfig, t *idToken) (email, name string) {
	if emails := claimValues(t.claims, oc.EmailClaim, t.clientID); len(emails) > 0 {
		email = strings.TrimSpace(emails[0])
	}
	if names := claimValues(t.claims, oc.NameClaim, t.clientID); len(names) > 0 {
		name = strings.TrimSpace(names[0])
	}
	if !cert.EmailRE.MatchString(email) || t.claims["email_verified"] == false {
		email = ""
	}
	return email, name
}

// APISelfCert answers POST /api/self-cert: for a bearer token of the scope self-cert, made by the
// OIDC sign-in, it issues the user certificate of the profile the token was made with, named by
// the email address and the name the sign-in recorded, for the public key of a CSR, or for a new
// key it returns in a PKCS#12 bundle.
func (c *Client) APISelfCert(w http.ResponseWriter, r *http.Request) {
	oc, ok := c.configured(w)
	if !ok {
		return
	}
	var req struct {
		CSR      string `json:"csr"`
		Generate bool   `json:"generate"`
		KeyType  string `json:"key_type"`
		Type     string `json:"type"`
	}
	if !decodeBody(w, r, &req, "the body is not a JSON object with csr, or generate") {
		return
	}
	switch {
	case req.CSR != "" && req.Generate:
		Fail(w, http.StatusBadRequest, "csr and generate exclude each other")
		return
	case req.CSR == "" && !req.Generate:
		Fail(w, http.StatusBadRequest, "the body needs a csr, or generate")
		return
	case req.KeyType != "" && !req.Generate:
		Fail(w, http.StatusBadRequest, "key_type needs generate")
		return
	case req.KeyType != "" && req.KeyType != "rsa" && req.KeyType != "ec":
		Fail(w, http.StatusBadRequest, fmt.Sprintf("key_type %q must be rsa or ec", req.KeyType))
		return
	}
	tokName, tokCA, tok, ok := Bearer(w, r, c.rootDir, tokens.SelfCert)
	if !ok {
		return
	}
	client := ClientAddr(r)
	fail := failer(w, "could not issue the certificate")
	who := tok.OIDC
	if who == nil || who.Issuer != oc.Issuer || who.Profile == "" {
		fail(StatusError(http.StatusForbidden, "the token %s was not made by the OIDC sign-in of %q", tokName, oc.Issuer))
		return
	}
	user, email, name := who.User, who.Email, who.Name
	cfg, err := simpleca.LoadConfig(c.rootDir)
	if err != nil {
		fail(err)
		return
	}
	users, err := loadOIDCUsers(c.rootDir)
	if err != nil {
		fail(err)
		return
	}
	i := slices.IndexFunc(users.Profiles, func(p oidcProfile) bool { return p.Name == who.Profile })
	if i == -1 || !users.Profiles[i].givesCertificate() {
		fail(StatusError(http.StatusForbidden, "the profile %s of %q gives no certificate", who.Profile, user))
		return
	}
	profile := &users.Profiles[i]
	set, err := profile.certificate(c.rootDir, cfg, users.userEKUs())
	if err != nil {
		fail(fmt.Errorf("profile %s: %w", profile.Name, err))
		return
	}
	_, domain, _ := strings.Cut(email, "@")
	switch {
	case email == "":
		fail(StatusError(http.StatusForbidden, "the sign-in of %q gave no verified email address of claim %s", user,
			strings.Join(oc.EmailClaim, " or ")))
		return
	case len(set.emailDomains) > 0 && !cert.InDomains(strings.ToLower(domain), set.emailDomains):
		fail(StatusError(http.StatusForbidden, "the email address %q of %q is not in the email_domains of the profile %s", email, user,
			profile.Name))
		return
	}

	// The type: the one of the profile, else the one the request names, which the profile offers.
	certType := req.Type
	switch {
	case certType == "" && len(set.types) == 1:
		certType = set.types[0]
	case certType == "":
		Reply(w, http.StatusConflict, map[string]any{"error": fmt.Sprintf("the profile %s offers the types %s; choose one",
			profile.Name, strings.Join(set.types, ", ")), "types": set.types})
		return
	case !slices.Contains(set.types, certType):
		fail(StatusError(http.StatusForbidden, "the profile %s of %q does not offer the type %q", profile.Name, user, certType))
		return
	}
	subjectName, sans := email, []string(nil)
	if name != "" && !cert.EmailRE.MatchString(name) {
		subjectName, sans = name, []string{email}
	}
	subject, exts, _, err := cert.Names(subjectName, sans, certType, true)
	if err != nil {
		fail(StatusError(http.StatusForbidden, "the name and the email address of %q make no subject: %v", user, err))
		return
	}

	caCert, err := simpleca.LoadCert(filepath.Join(set.caDir, "ca_cert.pem"))
	if err != nil {
		fail(err)
		return
	}
	if err := cert.CheckValidity(caCert, time.Now(), set.days); err != nil {
		fail(fmt.Errorf("profile %s: %w", profile.Name, err))
		return
	}
	var key crypto.Signer
	var pub any
	if req.Generate {
		if key, err = cert.NewKey(cmp.Or(req.KeyType, simpleca.KeyType(caCert.PublicKey))); err != nil {
			fail(err)
			return
		}
		pub = key.Public()
	} else {
		csr, err := cert.ParseCSR([]byte(req.CSR))
		if err != nil {
			fail(StatusError(http.StatusBadRequest, "csr: %v", err))
			return
		}
		pub = csr.PublicKey
	}

	base := strings.TrimSuffix(tokName, "-cli")
	cert.IssueMu.Lock()
	crt, fileName, err := func() (*x509.Certificate, string, error) {
		defer cert.IssueMu.Unlock()
		crt, err := cert.IssueLeaf(set.caDir, certType, set.days, nil, nil,
			&x509.Certificate{Subject: subject, ExtraExtensions: exts}, pub)
		if err != nil {
			return nil, "", err
		}
		fileName, err := cert.CertFile(base + "-" + cert.SerialHex(crt.SerialNumber))
		if err != nil {
			return nil, "", err
		}
		return crt, fileName, cert.StoreCert(set.caDir, filepath.Join(set.caDir, fileName), crt)
	}()
	if err != nil {
		fail(err)
		return
	}
	// The token keeps the serial of the certificate, as a token of the signing API does.
	tokDir := filepath.Join(c.rootDir, tokCA)
	if err := func() error {
		unlock, err := tokens.LockTokens(tokDir)
		if err != nil {
			return err
		}
		defer unlock()
		db, err := tokens.LoadTokens(tokDir)
		if err != nil {
			return err
		}
		if t, ok := db.Tokens[tokName]; ok {
			t.Certs = append(t.Certs, cert.SerialHex(crt.SerialNumber))
		}
		return db.Save(tokDir)
	}(); err != nil {
		slog.Error("serve.error", "error", err.Error())
	}
	via := "webui"
	if strings.HasSuffix(tokName, "-cli") {
		via = "request-cert"
	}
	cert.AuditIssued(set.caDir, crt, certType, "via", via, "actor", tokName, "oidc_user", user, "issuer", oc.Issuer,
		"profile", profile.Name, "generated_key", req.Generate, "client", client.String())

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}))
	chain := certPEM
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	}
	answer := map[string]any{"ca": *profile.Certificate.CA, "name": base, "type": certType, "serial": cert.SerialHex(crt.SerialNumber),
		"certificate": certPEM, "chain": chain}
	if req.Generate {
		password := rand.Text()
		bundle, err := cert.EncodePFXKey(key, crt, set.caDir, password)
		if err != nil {
			fail(err)
			return
		}
		pfxName := strings.TrimSuffix(fileName, "_cert.pem") + ".pfx"
		simpleca.Audit(set.caDir, "cert.pfx", "file", pfxName, "via", via, "actor", tokName, "client", client.String())
		answer["file"], answer["password"], answer["pfx"] = pfxName, password, bundle
	}
	Reply(w, http.StatusOK, answer)
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
		return "", nil, StatusError(http.StatusConflict, "the token %q exists and is not the token of this user", name)
	case ok && old.Active(time.Now()) && reuse:
		jwt, err := tokens.SignToken(caKey, name, old)
		return jwt, old, err
	case ok && old.Active(time.Now()) && !replace:
		return "", nil, StatusError(http.StatusConflict, "the token %q of this user is active; replace it or use it", name)
	}
	jwt, err := tokens.SignToken(caKey, name, tok)
	if err != nil {
		return "", nil, err
	}
	db.Tokens[name] = tok
	return jwt, tok, db.Save(caDir)
}
