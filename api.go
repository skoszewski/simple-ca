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
	"bytes"
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ---- signing API tokens -----------------------------------------------------

const (
	tokensFile          = "tokens-db.json"
	tokensPurgeInterval = 5 * time.Minute
)

// tokensLockWait is how long a command or serve waits for the lock of tokens-db.json.
var tokensLockWait = 10 * time.Second

// tokenScopes are the scopes a token may have: sign for the signing API and the signing form,
// tokens for the token page of serve --webui, certs for its certificate page, and audit for its
// audit page; the scope * is all of them.
var tokenScopes = []string{"sign", "tokens", "certs", "audit"}

// allows reports whether values, the scopes or the certificate types of a token, hold value or *,
// which stands for every value.
func allows(values []string, value string) bool {
	return slices.Contains(values, value) || slices.Contains(values, "*")
}

// checkAll returns an error, naming what values are, when values hold * with other values.
func checkAll(what string, values []string) error {
	if slices.Contains(values, "*") && len(values) > 1 {
		return fmt.Errorf("the %s * stands for every %s and must be given alone", what, what)
	}
	return nil
}

// apiToken is a token of a CA: its JWT ID, its scopes, the certificate types, the domains and the
// IP address prefixes it allows with the scope sign, each "*" for any, the prefixes of the client
// addresses it is used from, any without them, its validity, the serial numbers of the
// certificates issued with it, the setup code it waits for, and the OIDC user it was made for; and
// its token type, empty for api, with the issuer, the audience, the subject, empty for its name,
// and the claims of its JWT. A token without a JWT ID and a setup code is revoked: it expired when
// it was revoked, and is kept to be renewed until it is purged. A token with a setup code is
// pending: it has no JWT until the code is exchanged, and expires with the code.
type apiToken struct {
	ID        string            `json:"id,omitempty"`
	TokenType string            `json:"token_type,omitempty"`
	Issuer    string            `json:"issuer,omitempty"`
	Audience  string            `json:"audience,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Claims    map[string]string `json:"claims,omitempty"`
	Scopes    []string          `json:"scopes,omitempty"`
	Types     []string          `json:"types,omitempty"`
	Domains   []string          `json:"domains,omitempty"`
	IPs       []string          `json:"ips,omitempty"`
	Clients   []string          `json:"clients,omitempty"`
	Issued    time.Time         `json:"issued"`
	Expires   time.Time         `json:"expires"`
	Certs     []string          `json:"certs,omitempty"`
	Setup     *tokenSetup       `json:"setup,omitempty"`
	OIDC      *tokenOIDC        `json:"oidc,omitempty"`
}

// tokenOIDC is the OIDC user a token was made for: issuer, subject and user claim.
type tokenOIDC struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	User    string `json:"user"`
}

// tokenSetup is the one-time setup code a pending token waits for: the SHA-256 of the code, in
// hex, the prefixes of the client addresses it is exchanged from, any without them, and the
// validity of the token, a duration such as 8h, which starts at the exchange.
type tokenSetup struct {
	Code    string   `json:"code"`
	Clients []string `json:"clients,omitempty"`
	Valid   string   `json:"valid"`
}

// tokenSetupValid is the default validity of a setup code.
const tokenSetupValid = 15 * time.Minute

// revoked reports whether the token is revoked, having neither a JWT ID nor a setup code.
func (t *apiToken) revoked() bool {
	return t.ID == "" && t.Setup == nil
}

// pending reports whether the token waits for its setup code.
func (t *apiToken) pending() bool {
	return t.Setup != nil
}

// setupCodeHash returns the hex SHA-256 of the setup code, in upper case without dashes and
// spaces, as it is stored.
func setupCodeHash(code string) string {
	code = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", sum)
}

// newTokenSetup returns, for a setupValid, the setup of a token valid for valid once its new
// setup code is exchanged from the client addresses setupClients, any without them, and the code;
// for no setupValid, nil and no code.
func newTokenSetup(valid, setupValid time.Duration, setupClients []string) (*tokenSetup, string, error) {
	switch {
	case setupValid < 0 || (setupValid == 0 && len(setupClients) > 0):
		return nil, "", errors.New("the validity and the networks of a setup code need a setup code")
	case setupValid == 0:
		return nil, "", nil
	case setupValid < time.Second:
		return nil, "", errors.New("the validity of a setup code must be at least 1s")
	}
	prefixes, err := toPrefixes("setup code network", setupClients, false)
	if err != nil {
		return nil, "", err
	}
	b := make([]byte, 10)
	rand.Read(b)
	s := base32.StdEncoding.EncodeToString(b)
	code := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
	return &tokenSetup{Code: setupCodeHash(code), Clients: prefixes, Valid: valid.String()}, code, nil
}

// toPrefixes returns the addresses and prefixes of values, what they are named in its error, as
// masked prefixes, an address as the prefix of that address alone; with any, "*" is kept.
func toPrefixes(what string, values []string, any bool) ([]string, error) {
	var prefixes []string
	for _, s := range values {
		if s == "*" && any {
			prefixes = append(prefixes, s)
			continue
		}
		prefix, ok := parsePrefix(s)
		if !ok {
			return nil, fmt.Errorf("%s '%s' is not an IP address or a prefix such as 10.0.0.0/8", what, s)
		}
		prefixes = append(prefixes, prefix.String())
	}
	return prefixes, nil
}

// scopes returns the scopes of the token; an entry without them has the scope sign.
func (t *apiToken) scopes() []string {
	if len(t.Scopes) == 0 {
		return []string{"sign"}
	}
	return t.Scopes
}

// hasScope reports whether the token has the scope, named or by the scope *.
func (t *apiToken) hasScope(scope string) bool {
	return allows(t.scopes(), scope)
}

// clientAllowed reports whether the token is used from the address client: one in its client
// prefixes, or any without them.
func (t *apiToken) clientAllowed(client netip.Addr) bool {
	return len(t.Clients) == 0 || slices.ContainsFunc(t.Clients, func(s string) bool {
		prefix, err := netip.ParsePrefix(s)
		return err == nil && prefix.Contains(client)
	})
}

// tokensDB is tokens-db.json of a CA directory, the tokens of its signing API by name.
type tokensDB struct {
	Tokens map[string]*apiToken `json:"tokens"`
}

// jwtClaims are the claims of a token simple-ca reads: its ID, its issuer, its subject, its
// audience, its name when the subject is not its name, its scopes, separated by spaces, and when it
// was issued and expires, in seconds since the epoch.
type jwtClaims struct {
	ID        string `json:"jti"`
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud,omitempty"`
	Token     string `json:"simple_ca_token,omitempty"`
	Scope     string `json:"scope,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// name returns the name of the token of the claims.
func (c *jwtClaims) name() string {
	return cmp.Or(c.Token, c.Subject)
}

// token returns the token the claims hold, without what tokens-db.json alone holds.
func (c *jwtClaims) token() *apiToken {
	t := &apiToken{ID: c.ID, Issuer: c.Issuer, Audience: c.Audience, Scopes: strings.Fields(c.Scope),
		Issued: time.Unix(c.IssuedAt, 0), Expires: time.Unix(c.ExpiresAt, 0)}
	if c.Token != "" {
		t.Subject = c.Subject
	}
	return t
}

// loadTokens reads tokens-db.json of caDir, or returns an empty database when it does not exist.
func loadTokens(caDir string) (*tokensDB, error) {
	db := &tokensDB{Tokens: map[string]*apiToken{}}
	b, err := os.ReadFile(filepath.Join(caDir, tokensFile))
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", filepath.Join(caDir, tokensFile), err)
	}
	if db.Tokens == nil {
		db.Tokens = map[string]*apiToken{}
	}
	return db, nil
}

// save writes the database to tokens-db.json of caDir, readable by its owner alone.
func (db *tokensDB) save(caDir string) error {
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, tokensFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, tokensFile))
}

// lockTokens locks tokens-db.json of caDir for the commands and serve by creating
// tokens-db.json.lock, which one of them at a time can create, holding the PID of the locker. It
// waits up to tokensLockWait for the lock, and returns the function that unlocks it.
func lockTokens(caDir string) (func(), error) {
	path := filepath.Join(caDir, tokensFile+".lock")
	deadline := time.Now().Add(tokensLockWait)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
			if err := cmp.Or(err, f.Close()); err != nil {
				os.Remove(path)
				return nil, err
			}
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			pid, _ := os.ReadFile(path)
			return nil, fmt.Errorf("%s is locked by process %s; remove %s if that process is gone",
				filepath.Join(caDir, tokensFile), strings.TrimSpace(string(pid)), path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// purgeTokens removes from tokens-db.json of caDir, when it exists, the tokens that expired, or
// were revoked, at least kept ago, every expired token for a kept of zero, and returns their count.
func purgeTokens(caDir string, kept time.Duration) (int, error) {
	if !fileExists(filepath.Join(caDir, tokensFile)) {
		return 0, nil
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := len(db.Tokens)
	maps.DeleteFunc(db.Tokens, func(_ string, t *apiToken) bool { return !now.Add(-kept).Before(t.Expires) })
	if n == len(db.Tokens) {
		return 0, nil
	}
	return n - len(db.Tokens), db.save(caDir)
}

// purgeToken removes the token name, expired or revoked, from tokens-db.json of caDir; a token
// still accepted is revoked first.
func purgeToken(caDir, name string) error {
	unlock, err := lockTokens(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return err
	}
	t, ok := db.Tokens[name]
	if !ok {
		return fmt.Errorf("token '%s' not found in %s", name, filepath.Join(caDir, tokensFile))
	}
	if time.Now().Before(t.Expires) {
		return fmt.Errorf("token '%s' is still accepted; revoke it first", name)
	}
	delete(db.Tokens, name)
	return db.save(caDir)
}

// makeToken adds the token name of the token type api to tokens-db.json of the CA in caDir and
// returns its JWT, as addToken does without a setup code.
func makeToken(caDir, name string, valid time.Duration, scopes, certTypes, domains, ips, clients []string) (string, error) {
	return addToken(caDir, name, tokenKind{}, valid, scopes, certTypes, domains, ips, clients, 0, nil)
}

// addToken adds the token name, valid for valid, with the scopes, sign without them, used from
// the client addresses clients, to tokens-db.json of the CA in caDir, and returns its JWT, signed
// with the CA key. With the scope sign, it allows the certificate types certTypes, the domains and
// the IP addresses ips, which belong to that scope alone. A scope, a type, a domain or an IP
// address "*" allows any; an IP address or a client address is an address or a prefix, kept as a
// prefix, and no clients allow any client. With a setupValid, the token is pending instead: it
// gets no JWT, and addToken returns a setup code, valid for setupValid and exchanged from the
// client addresses setupClients, any without them, for the JWT. The token type, the audience and
// the claims of kind shape its JWT.
func addToken(caDir, name string, kind tokenKind, valid time.Duration, scopes, certTypes, domains, ips, clients []string,
	setupValid time.Duration, setupClients []string) (string, error) {
	setup, code, err := newTokenSetup(valid, setupValid, setupClients)
	if err != nil {
		return "", err
	}
	tok, caKey, err := prepareToken(caDir, name, kind, valid, scopes, certTypes, domains, ips, clients)
	if err != nil {
		return "", err
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return "", err
	}
	if _, ok := db.Tokens[name]; ok {
		return "", fmt.Errorf("token '%s' exists", name)
	}

	result := code
	if setup != nil {
		tok.ID, tok.Expires, tok.Setup = "", tok.Issued.Add(setupValid), setup
	} else if result, err = signToken(caKey, name, tok); err != nil {
		return "", err
	}
	db.Tokens[name] = tok
	if err := db.save(caDir); err != nil {
		return "", err
	}
	return result, nil
}

// prepareToken validates and returns the token name of the CA in caDir, of the kind kind, unsaved,
// and the CA key.
func prepareToken(caDir, name string, kind tokenKind, valid time.Duration, scopes, certTypes, domains, ips, clients []string) (*apiToken, *rsa.PrivateKey, error) {
	if valid < time.Second {
		return nil, nil, errors.New("the validity of a token must be at least 1s")
	}
	if !kebabCaseRE.MatchString(name) {
		return nil, nil, fmt.Errorf("token name '%s' is not a kebab-case name, such as web-deploy", name)
	}
	if len(scopes) == 0 {
		scopes = []string{"sign"}
	}
	for _, s := range scopes {
		if s != "*" && !slices.Contains(tokenScopes, s) {
			return nil, nil, fmt.Errorf("unknown scope '%s': must be one of %s or *", s, strings.Join(tokenScopes, ", "))
		}
	}
	if err := cmp.Or(checkAll("scope", scopes), checkAll("type", certTypes)); err != nil {
		return nil, nil, err
	}
	if !slices.Contains(scopes, "*") {
		scopes = slices.DeleteFunc(slices.Clone(tokenScopes), func(s string) bool { return !slices.Contains(scopes, s) })
	}
	switch {
	case !allows(scopes, "sign") && len(certTypes)+len(domains)+len(ips) > 0:
		return nil, nil, errors.New("certificate types, domains, IP addresses and localhost need the scope sign")
	case !allows(scopes, "sign"):
	case len(domains) == 0 && len(ips) == 0:
		return nil, nil, errors.New("a token with the scope sign needs a domain or an IP address")
	}
	var names []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d != "*" && !isHostname(d) {
			return nil, nil, fmt.Errorf("domain '%s' is not a domain name or *", d)
		}
		names = append(names, d)
	}
	prefixes, err := toPrefixes("IP address", ips, true)
	if err != nil {
		return nil, nil, err
	}
	clientPrefixes, err := toPrefixes("client", clients, false)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := loadRootConfig(caDir)
	if err != nil {
		return nil, nil, err
	}
	types, err := cfg.certTypes()
	if err != nil {
		return nil, nil, err
	}
	for _, t := range certTypes {
		if _, ok := types[t]; !ok && t != "*" {
			return nil, nil, fmt.Errorf("unknown type '%s': must be one of %s or *", t, typeNames(types))
		}
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) || !fileExists(caKeyPath) {
		return nil, nil, fmt.Errorf("CA certificate and key not found in %s, which is not a CA directory", caDir)
	}
	caKey, err := loadKey(caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	tokenTypes, err := cfg.tokenTypes()
	if err != nil {
		return nil, nil, err
	}
	_, caID, err := locateCA(caDir)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok := &apiToken{ID: randomID(), Scopes: scopes, Types: certTypes, Domains: names, IPs: prefixes,
		Clients: clientPrefixes, Issued: now, Expires: now.Add(valid)}
	if err := kind.apply(tok, cfg, tokenTypes, caID, name, valid); err != nil {
		return nil, nil, err
	}
	return tok, caKey, nil
}

// active reports whether the token is neither revoked, pending nor expired at now.
func (t *apiToken) active(now time.Time) bool {
	return !t.revoked() && !t.pending() && now.Before(t.Expires)
}

// ownedBy reports whether the token was made for the OIDC user owner.
func (t *apiToken) ownedBy(owner *tokenOIDC) bool {
	return t.OIDC != nil && t.OIDC.Issuer == owner.Issuer && t.OIDC.Subject == owner.Subject
}

// oidcToken stores tok as the token name of caDir and returns its JWT and the token given; an
// active token of the same user is replaced with replace, or returned with reuse.
func oidcToken(caDir, name string, tok *apiToken, caKey *rsa.PrivateKey, replace, reuse bool) (string, *apiToken, error) {
	unlock, err := lockTokens(caDir)
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return "", nil, err
	}
	old, ok := db.Tokens[name]
	switch {
	case ok && !old.ownedBy(tok.OIDC):
		return "", nil, apiErr(http.StatusConflict, "the token '%s' exists and is not the token of this user", name)
	case ok && old.active(time.Now()) && reuse:
		jwt, err := signToken(caKey, name, old)
		return jwt, old, err
	case ok && old.active(time.Now()) && !replace:
		return "", nil, apiErr(http.StatusConflict, "the token '%s' of this user is active; replace it or use it", name)
	}
	jwt, err := signToken(caKey, name, tok)
	if err != nil {
		return "", nil, err
	}
	db.Tokens[name] = tok
	return jwt, tok, db.save(caDir)
}

// signToken returns the JWT of the token name, its claims signed with caKey, its header naming the
// key by its JWK thumbprint. The claims simple-ca writes come first, then those of the token.
func signToken(caKey *rsa.PrivateKey, name string, tok *apiToken) (string, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{"RS256", publicJWK(&caKey.PublicKey).Kid, "JWT"})
	if err != nil {
		return "", err
	}
	tokenName := ""
	if tok.Subject != "" {
		tokenName = name
	}
	claims, err := json.Marshal(struct {
		ID        string `json:"jti"`
		Issuer    string `json:"iss,omitempty"`
		Subject   string `json:"sub"`
		Audience  string `json:"aud,omitempty"`
		Scope     string `json:"scope,omitempty"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Token     string `json:"simple_ca_token,omitempty"`
	}{tok.ID, tok.Issuer, cmp.Or(tok.Subject, name), tok.Audience, strings.Join(tok.Scopes, " "), tok.Issued.Unix(),
		tok.Expires.Unix(), tokenName})
	if err != nil {
		return "", err
	}
	if len(tok.Claims) > 0 {
		custom, err := json.Marshal(tok.Claims)
		if err != nil {
			return "", err
		}
		claims = append(append(claims[:len(claims)-1], ','), custom[1:]...)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, caKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// renewToken renews the token name of the CA in caDir and returns its JWT, as reissueToken does
// without a setup code.
func renewToken(caDir, name string, valid time.Duration) (string, error) {
	return reissueToken(caDir, name, valid, 0, nil)
}

// reissueToken gives the token name of the CA in caDir, revoked, expired or not, a new JWT ID and
// new times, valid for valid from now or, for zero, for as long as it was before, or for the
// default validity of token create when it was revoked, keeping what it allows and where it is
// used from, and returns its JWT. The JWT it had is refused from then on. With a setupValid, the
// token becomes pending instead, as addToken makes it, and reissueToken returns its new setup
// code. A token waiting for a setup code that has not expired is refused.
func reissueToken(caDir, name string, valid, setupValid time.Duration, setupClients []string) (string, error) {
	if valid != 0 && valid < time.Second {
		return "", errors.New("the validity of a token must be at least 1s")
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) || !fileExists(caKeyPath) {
		return "", fmt.Errorf("CA certificate and key not found in %s, which is not a CA directory", caDir)
	}
	caKey, err := loadKey(caKeyPath)
	if err != nil {
		return "", err
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return "", err
	}
	old, ok := db.Tokens[name]
	if !ok {
		return "", fmt.Errorf("token '%s' not found in %s", name, filepath.Join(caDir, tokensFile))
	}
	if old.pending() && time.Now().Before(old.Expires) {
		return "", fmt.Errorf("token '%s' waits for its setup code; revoke it first to renew it", name)
	}
	switch {
	case valid != 0:
	case old.pending():
		// The expiry of a pending token is that of its code; the validity of the token is kept apart.
		if valid, err = time.ParseDuration(old.Setup.Valid); err != nil {
			return "", fmt.Errorf("token '%s': '%s' is not a validity such as 8h", name, old.Setup.Valid)
		}
	case !old.revoked():
		valid = old.Expires.Sub(old.Issued)
	default:
		// A revoked token, whose expiry is when it was revoked, takes the validity token create
		// gives by default.
		cfg, err := loadRootConfig(caDir)
		if err != nil {
			return "", err
		}
		valid = time.Hour
		if cfg.Tokens.Valid != "" {
			if valid, err = time.ParseDuration(cfg.Tokens.Valid); err != nil {
				return "", fmt.Errorf("tokens.valid of %s: '%s' is not a duration such as 8h", cfg.path, cfg.Tokens.Valid)
			}
		}
	}
	if old.TokenType != "" {
		cfg, err := loadRootConfig(caDir)
		if err != nil {
			return "", err
		}
		tokenTypes, err := cfg.tokenTypes()
		if err != nil {
			return "", err
		}
		if err := old.checkValid(tokenTypes, valid); err != nil {
			return "", fmt.Errorf("token '%s': %w", name, err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok := &apiToken{ID: randomID(), TokenType: old.TokenType, Issuer: old.Issuer, Audience: old.Audience,
		Subject: old.Subject, Claims: old.Claims, Scopes: old.Scopes, Types: old.Types, Domains: old.Domains,
		IPs: old.IPs, Clients: old.Clients, Issued: now, Expires: now.Add(valid), OIDC: old.OIDC}
	setup, result, err := newTokenSetup(valid, setupValid, setupClients)
	if err != nil {
		return "", err
	}
	if setup != nil {
		tok.ID, tok.Expires, tok.Setup = "", now.Add(setupValid), setup
	} else if result, err = signToken(caKey, name, tok); err != nil {
		return "", err
	}
	db.Tokens[name] = tok
	if err := db.save(caDir); err != nil {
		return "", err
	}
	return result, nil
}

// listTokens writes the tokens of the CA in caDir to w, one per line, sorted by name.
func listTokens(w io.Writer, caDir string) error {
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) {
		return fmt.Errorf("CA certificate not found in %s, which is not a CA directory", caDir)
	}
	db, err := loadTokens(caDir)
	if err != nil {
		return err
	}
	now := time.Now()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTOKEN TYPE\tEXPIRES\tSCOPES\tCERT TYPES\tDOMAINS\tIPS\tCLIENTS\tCERTS\tOIDC USER")
	for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
		t := db.Tokens[name]
		expires := t.Expires.UTC().Format(displayTimeFormat)
		switch {
		case t.revoked():
			expires = "revoked"
		case t.pending() && !now.Before(t.Expires):
			expires = "setup expired"
		case t.pending():
			expires = "setup until " + expires
		case !now.Before(t.Expires):
			expires += " (expired)"
		}
		user := "-"
		if t.OIDC != nil {
			user = t.OIDC.User
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", name, cmp.Or(t.TokenType, "api"), expires,
			strings.Join(t.scopes(), ","),
			cmp.Or(strings.Join(t.Types, ","), "-"), cmp.Or(strings.Join(t.Domains, ","), "-"),
			cmp.Or(strings.Join(showPrefixes(t.IPs), ","), "-"), cmp.Or(strings.Join(showPrefixes(t.Clients), ","), "any"),
			len(t.Certs), user)
	}
	return tw.Flush()
}

// durationText returns d as a duration is given to the options, without the zero minutes and
// seconds Go adds: 8h for 8h0m0s, 15m for 15m0s.
func durationText(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// describeToken returns the attributes of the token name, each a label and a value, as
// token describe and the setup code page show them; with limits, also what it allows and where it
// is used from, which only tokens-db.json holds, and not its JWT.
func describeToken(name string, t *apiToken, limits bool) [][2]string {
	now := time.Now()
	at := func(when time.Time) string { return when.UTC().Format(displayTimeFormat) }
	list := func(values []string, none string) string { return cmp.Or(strings.Join(values, ", "), none) }
	status := "valid until " + at(t.Expires)
	switch {
	case t.revoked():
		status = "revoked at " + at(t.Expires)
	case t.pending() && !now.Before(t.Expires):
		status = "setup code expired at " + at(t.Expires)
	case t.pending():
		status = "waits for its setup code, until " + at(t.Expires)
	case !now.Before(t.Expires):
		status = "expired at " + at(t.Expires)
	}
	attributes := [][2]string{{"Name", name}, {"Status", status}, {"Issued", at(t.Issued)},
		{"Scopes", list(t.scopes(), "-")}}
	if limits {
		attributes = append(attributes, [2]string{"Token type", cmp.Or(t.TokenType, "api")})
	}
	for _, a := range [][2]string{{"Issuer", t.Issuer}, {"Audience", t.Audience}, {"Subject", t.Subject}} {
		if a[1] != "" {
			attributes = append(attributes, a)
		}
	}
	for _, claim := range slices.Sorted(maps.Keys(t.Claims)) {
		attributes = append(attributes, [2]string{"Claim " + claim, t.Claims[claim]})
	}
	if t.OIDC != nil {
		attributes = append(attributes, [2]string{"OIDC user", t.OIDC.User}, [2]string{"OIDC issuer", t.OIDC.Issuer})
	}
	if !limits {
		return attributes
	}
	if t.hasScope("sign") {
		attributes = append(attributes, [2]string{"Cert types", list(t.Types, "-")},
			[2]string{"Domains", list(t.Domains, "-")}, [2]string{"IP addresses", list(showPrefixes(t.IPs), "-")})
	}
	attributes = append(attributes, [2]string{"Used from", list(showPrefixes(t.Clients), "any client")})
	if t.pending() {
		valid := t.Setup.Valid
		if d, err := time.ParseDuration(valid); err == nil {
			valid = durationText(d)
		}
		attributes = append(attributes, [2]string{"Code usable from", list(showPrefixes(t.Setup.Clients), "any client")},
			[2]string{"Valid after the exchange", valid})
	}
	certs := fmt.Sprint(len(t.Certs))
	if len(t.Certs) > 0 {
		certs += ": " + strings.Join(t.Certs, ", ")
	}
	return append(attributes, [2]string{"Certificates", certs})
}

// revokeToken revokes the token name of the CA in caDir by taking its JWT ID, or its setup code,
// from tokens-db.json and making it expire now; its JWT, or its code, is refused from then on, and
// the token is kept, to be renewed, until it is purged.
func revokeToken(caDir, name string) error {
	unlock, err := lockTokens(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return err
	}
	t, ok := db.Tokens[name]
	if !ok {
		return fmt.Errorf("token '%s' not found in %s", name, filepath.Join(caDir, tokensFile))
	}
	if t.revoked() {
		return fmt.Errorf("token '%s' is revoked already", name)
	}
	t.ID, t.Setup, t.Expires = "", nil, time.Now().UTC().Truncate(time.Second)
	return db.save(caDir)
}

// caIDs returns the IDs of the root CA in rootDir, empty, and of its issuing CAs.
func caIDs(rootDir string) []string {
	ids := []string{""}
	entries, _ := os.ReadDir(rootDir)
	for _, e := range entries {
		if e.IsDir() && kebabCaseRE.MatchString(e.Name()) && fileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
			ids = append(ids, e.Name())
		}
	}
	return ids
}

// exchangeSetupCode exchanges the setup code of a pending token of the root CA in rootDir or of
// one of its issuing CAs, used from the address client, for its JWT, and returns the ID of its
// CA, its name and the JWT. The token is valid from now, and the code works once. The error has
// the status 401 for an unknown, used or expired code, and 403 for a client the code is not
// exchanged from.
func exchangeSetupCode(rootDir, code string, client netip.Addr) (caID, name, jwt string, err error) {
	hash := setupCodeHash(code)
	for _, id := range caIDs(rootDir) {
		dir := filepath.Join(rootDir, id)
		if id, name, jwt, err := func() (string, string, string, error) {
			unlock, err := lockTokens(dir)
			if err != nil {
				return "", "", "", err
			}
			defer unlock()
			db, err := loadTokens(dir)
			if err != nil {
				return "", "", "", err
			}
			for name, t := range db.Tokens {
				if !t.pending() || t.Setup.Code != hash {
					continue
				}
				now := time.Now().UTC().Truncate(time.Second)
				if !now.Before(t.Expires) {
					return "", "", "", apiErr(http.StatusUnauthorized, "the setup code has expired")
				}
				if !(&apiToken{Clients: t.Setup.Clients}).clientAllowed(client) {
					return "", "", "", apiErr(http.StatusForbidden, "the setup code is not usable from %s", client)
				}
				valid, err := time.ParseDuration(t.Setup.Valid)
				if err != nil {
					return "", "", "", fmt.Errorf("token '%s': '%s' is not a validity such as 8h", name, t.Setup.Valid)
				}
				caKey, err := loadKey(filepath.Join(dir, "ca_key.pem"))
				if err != nil {
					return "", "", "", err
				}
				t.ID, t.Setup, t.Issued, t.Expires = randomID(), nil, now, now.Add(valid)
				jwt, err := signToken(caKey, name, t)
				if err != nil {
					return "", "", "", err
				}
				return id, name, jwt, db.save(dir)
			}
			return "", "", "", nil
		}(); err != nil || name != "" {
			return id, name, jwt, err
		}
	}
	return "", "", "", apiErr(http.StatusUnauthorized, "unknown or used setup code")
}

// apiTokenSetup answers POST /api/token-setup, a JSON body {"code": "..."} of at most acmeMaxBody
// bytes from a client behind the trusted proxies, with the CA ID, the name, the JWT and the scopes
// of the token the setup code is exchanged for.
func apiTokenSetup(w http.ResponseWriter, r *http.Request, rootDir string) {
	var req struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, acmeMaxBody))
	dec.DisallowUnknownFields()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		webuiFail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object with the setup code")
		return
	}
	client := clientAddr(r)
	var id, name, jwt string
	err := guard.attempt(w, r, rootDir, func() (err error) {
		id, name, jwt, err = exchangeSetupCode(rootDir, req.Code, client)
		return err
	})
	var refused *apiError
	switch {
	case errors.As(err, &refused):
		webuiFail(w, refused.status, refused.msg)
		return
	case err != nil:
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not set up the token")
		return
	}
	audit(filepath.Join(rootDir, id), "token.setup", "name", name, "via", "setup", "actor", name, "client", client.String())
	scopes := []string{}
	if db, err := loadTokens(filepath.Join(rootDir, id)); err == nil && db.Tokens[name] != nil {
		scopes = db.Tokens[name].scopes()
	}
	webuiReply(w, http.StatusOK, map[string]any{"ca": id, "name": name, "token": jwt, "scopes": scopes})
}

// tokenDescribePage serves /token-describe for the root CA in rootDir and its issuing CAs: GET
// shows the form asking for a token, and POST shows the attributes of the token, as token
// describe --ca-dir shows them with the CA that signed it, or the form again with the error. A
// token refused is counted as on the other pages.
func tokenDescribePage(w http.ResponseWriter, r *http.Request, rootDir string) {
	caCert, err := loadCert(filepath.Join(rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, Error, CA string
		Theme                            template.CSS
		Attributes                       [][2]string
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: r.URL.Path, Theme: pageTheme(rootDir)}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, acmeMaxBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "the form is too large or malformed", http.StatusBadRequest)
			return
		}
		client := clientAddr(r)
		token := strings.TrimSpace(r.PostForm.Get("token"))
		err = apiErr(http.StatusUnauthorized, "a token is required")
		if token == "" {
			auditRefused(r, rootDir, "a token is required", client)
		} else {
			// The token is checked against each CA of the server, as token describe --ca-dir checks it
			// against one, and its entry read from the tokens-db.json of the CA that signed it.
			err = guard.attempt(w, r, rootDir, func() error {
				for _, id := range caIDs(rootDir) {
					dir := filepath.Join(rootDir, id)
					cert, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
					if err != nil {
						continue
					}
					c, err := verifyJWT(cert, token)
					if err != nil {
						continue
					}
					db, err := loadTokens(dir)
					if err != nil {
						return err
					}
					page.CA = "root CA"
					if id != "" {
						page.CA = "issuing CA " + id
					}
					if entry := db.Tokens[c.name()]; entry != nil && entry.ID != "" && entry.ID == c.ID {
						page.Attributes = describeToken(c.name(), entry, true)
					} else {
						page.Attributes = describeToken(c.name(), c.token(), false)
						page.Attributes[1][1] = "refused: the token was renewed, revoked or removed"
					}
					return nil
				}
				return apiErr(http.StatusUnauthorized, "the token is not one of a CA of this server")
			})
		}
		var e *apiError
		switch {
		case errors.As(err, &e):
			status, page.Error = e.status, e.msg
		case err != nil:
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			status, page.Error = http.StatusInternalServerError, "could not read the tokens"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "token-describe.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// tokenSetupPage serves /token-setup for the root CA in rootDir and its issuing CAs: GET shows the
// form asking for a setup code, and POST exchanges the code, as exchangeSetupCode, and shows the
// token once, with its attributes, or the form again with the error. The client is the one
// clientAddr finds with the trusted proxies.
func tokenSetupPage(w http.ResponseWriter, r *http.Request, rootDir string) {
	caCert, err := loadCert(filepath.Join(rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, Error, CA, Name, Token string
		Theme                                         template.CSS
		Attributes                                    [][2]string
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: r.URL.Path, Theme: pageTheme(rootDir)}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, acmeMaxBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "the form is too large or malformed", http.StatusBadRequest)
			return
		}
		client := clientAddr(r)
		code := strings.TrimSpace(r.PostForm.Get("code"))
		err = apiErr(http.StatusUnauthorized, "a setup code is required")
		if code != "" {
			err = guard.attempt(w, r, rootDir, func() (err error) {
				page.CA, page.Name, page.Token, err = exchangeSetupCode(rootDir, code, client)
				return err
			})
		}
		var e *apiError
		switch {
		case errors.As(err, &e):
			status, page.Error = e.status, e.msg
		case err != nil:
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			status, page.Error = http.StatusInternalServerError, "could not set up the token"
		default:
			audit(filepath.Join(rootDir, page.CA), "token.setup", "name", page.Name, "via", "setup", "actor", page.Name,
				"client", client.String())
			if db, err := loadTokens(filepath.Join(rootDir, page.CA)); err == nil && db.Tokens[page.Name] != nil {
				page.Attributes = describeToken(page.Name, db.Tokens[page.Name], true)
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "token-setup.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// ---- /api/sign --------------------------------------------------------------

// apiError is an error of the signing API, sent with its HTTP status.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func apiErr(status int, format string, args ...any) *apiError {
	return &apiError{status, fmt.Sprintf(format, args...)}
}

// checkToken returns the name and the entry in db of the JWT token, signed with the key of
// caCert, and an error of status 401 when the token is malformed, signed by another key,
// unknown, which a revoked token is, or expired.
func checkToken(db *tokensDB, caCert *x509.Certificate, token string) (string, *apiToken, error) {
	c, err := verifyJWT(caCert, token)
	if err != nil {
		return "", nil, err
	}
	return lookupToken(db, c)
}

// otherCAToken returns err, the refusal of token by the CA in caDir, or, for a token another CA of
// the same root CA signed, the error of status 401 naming both CAs, as token describe names the CA.
func otherCAToken(caDir, token string, err error) error {
	rootDir, id, rerr := locateCA(caDir)
	if rerr != nil {
		return err
	}
	role := func(id string) string {
		if id == "" {
			return "the root CA"
		}
		return "the issuing CA " + id
	}
	for _, other := range caIDs(rootDir) {
		if other == id {
			continue
		}
		caCert, cerr := loadCert(filepath.Join(rootDir, other, "ca_cert.pem"))
		if cerr != nil {
			continue
		}
		if _, verr := verifyJWT(caCert, token); verr == nil {
			return apiErr(http.StatusUnauthorized, "the token is one of %s, not of %s", role(other), role(id))
		}
	}
	return err
}

// verifyJWT returns the claims of the JWT token signed with the key of caCert, and an error of
// status 401 when the token is malformed or signed by another key; with no caCert, the signature
// is not checked.
func verifyJWT(caCert *x509.Certificate, token string) (*jwtClaims, error) {
	invalid := apiErr(http.StatusUnauthorized, "invalid token")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid
	}
	header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, invalid
	}
	var h struct{ Alg string }
	if json.Unmarshal(header, &h) != nil || h.Alg != "RS256" {
		return nil, invalid
	}
	if caCert != nil && verifyJWS("RS256", caCert.PublicKey, []byte(parts[0]+"."+parts[1]), sig) != nil {
		return nil, invalid
	}
	var c jwtClaims
	if json.Unmarshal(payload, &c) != nil {
		return nil, invalid
	}
	return &c, nil
}

// lookupToken returns the name and the entry in db of the token with the verified claims c, and
// an error of status 401 when it is unknown, which a revoked token is, or expired.
func lookupToken(db *tokensDB, c *jwtClaims) (string, *apiToken, error) {
	now := time.Now()
	t, ok := db.Tokens[c.name()]
	switch {
	case ok && t.revoked():
		return "", nil, apiErr(http.StatusUnauthorized, "the token has been revoked")
	case !ok || t.pending() || t.ID != c.ID || c.Scope != strings.Join(t.Scopes, " "):
		return "", nil, apiErr(http.StatusUnauthorized, "unknown token")
	case now.Unix() >= c.ExpiresAt || !now.Before(t.Expires):
		return "", nil, apiErr(http.StatusUnauthorized, "the token has expired")
	}
	return c.name(), t, nil
}

// checkCSRNames checks the names of csr against the name rules names, "server" or "user", and the
// domains and IP prefixes of the token tok: the subject holds only a CN and email addresses, and
// the SANs only DNS names, email addresses and IP addresses; with the server rules, the CN, a
// hostname or an IP address, the DNS names and the IP addresses are allowed by the token and there
// are no email addresses; with the user rules, the domains of the email addresses are allowed and
// there are neither DNS names nor IP addresses.
func checkCSRNames(csr *x509.CertificateRequest, names string, tok *apiToken) error {
	domainAllowed := func(name string) bool {
		return slices.Contains(tok.Domains, "*") || inDomains(strings.ToLower(name), tok.Domains)
	}
	ipAllowed := func(addr netip.Addr) bool {
		return slices.ContainsFunc(tok.IPs, func(s string) bool {
			prefix, err := netip.ParsePrefix(s)
			return s == "*" || (err == nil && prefix.Contains(addr.Unmap()))
		})
	}
	var emails []string
	for _, attr := range csr.Subject.Names {
		switch {
		case attr.Type.Equal(oidEmailAddress):
			s, _ := attr.Value.(string)
			emails = append(emails, s)
		case attr.Type.String() != "2.5.4.3":
			return apiErr(http.StatusForbidden, "the subject may hold only CN and emailAddress")
		}
	}
	if san := csrSAN(csr); san != nil {
		var gns []asn1.RawValue
		if rest, err := asn1.Unmarshal(san.Value, &gns); err != nil || len(rest) > 0 {
			return apiErr(http.StatusBadRequest, "the subject alternative names do not parse")
		}
		for _, n := range gns {
			if n.Class != asn1.ClassContextSpecific || (n.Tag != 1 && n.Tag != 2 && n.Tag != 7) {
				return apiErr(http.StatusForbidden,
					"the subject alternative names may be only DNS names, email addresses and IP addresses")
			}
		}
	}
	emails = append(emails, csr.EmailAddresses...)

	if names == "user" {
		if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
			return apiErr(http.StatusForbidden, "a %s certificate has neither DNS names nor IP addresses", names)
		}
		if len(emails) == 0 {
			return apiErr(http.StatusForbidden, "the request has no email address")
		}
		for _, e := range emails {
			_, domain, _ := strings.Cut(e, "@")
			if !emailRE.MatchString(e) || !domainAllowed(domain) {
				return apiErr(http.StatusForbidden, "the token does not allow '%s'", e)
			}
		}
		return nil
	}
	if len(emails) > 0 {
		return apiErr(http.StatusForbidden, "a %s certificate has no email addresses", names)
	}

	// The CN is a hostname, checked with the DNS names, or an IP address, checked with the IP SANs.
	hosts := csr.DNSNames
	var addrs []netip.Addr
	if cn := csr.Subject.CommonName; cn != "" {
		if addr, ok := parseIP(cn); ok {
			addrs = append(addrs, addr)
		} else {
			hosts = append([]string{cn}, hosts...)
		}
	}
	for _, ip := range csr.IPAddresses {
		addr, _ := netip.AddrFromSlice(ip)
		addrs = append(addrs, addr)
	}
	if len(hosts) == 0 && len(addrs) == 0 {
		return apiErr(http.StatusForbidden, "the request has neither a DNS name nor an IP address")
	}
	for _, h := range hosts {
		if !isHostname(strings.TrimPrefix(h, "*.")) || !domainAllowed(h) {
			return apiErr(http.StatusForbidden, "the token does not allow '%s'", h)
		}
	}
	for _, addr := range addrs {
		if !ipAllowed(addr) {
			return apiErr(http.StatusForbidden, "the token does not allow the IP address %s", addr.Unmap())
		}
	}
	return nil
}

// trustedProxies are the proxies whose X-Forwarded-For header names the client, set once by serve.
var trustedProxies []netip.Prefix

// clientAddr returns the address of the client of r: the address the request comes from, or, when
// that is one of trustedProxies, the last address of its X-Forwarded-For headers that is not a
// trusted proxy, the first one when all of them are.
func clientAddr(r *http.Request) netip.Addr {
	isTrusted := func(addr netip.Addr) bool {
		return slices.ContainsFunc(trustedProxies, func(p netip.Prefix) bool { return p.Contains(addr) })
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	client := peer.Addr().Unmap()
	if !isTrusted(client) {
		return client
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	// The addresses are read from the last, which the trusted proxy added; an address that does
	// not read stops the walk at the last one that does.
	for i := len(hops) - 1; i >= 0; i-- {
		addr, ok := parseIP(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		client = addr.Unmap()
		if !isTrusted(client) {
			break
		}
	}
	return client
}

// signWithToken signs the CSR csrData, PEM or DER, with the CA in caDir as a certificate of the
// type certType, valid for days, with the extended key usages ekus and the key usages kus added to
// those of the type, for the JWT token of the CA's tokens-db.json used from the address client,
// which must be in the client prefixes of a token that has them. It writes the certificate to the
// CA directory as the file certFile gives base, replacing an earlier certificate of the name,
// records it in index.txt and in the token's entry, and returns it with the CA certificate and the
// name of its file. The signing form leaves certType, days and base out: the type is then the
// first type of the token, the days those of days.cert, and the file is named after the CN by the
// rules of cert create, or after the serial number for a request without a name. issueMu and the
// lock of tokens-db.json are held from the token check to the writes of the certificate file,
// index.txt and tokens-db.json. With setupCodes, token may be the setup code of a pending token of
// the CA instead, used from a client it is exchanged from: the certificate is signed with the
// limits of that token, which is revoked once it is issued, and a refused request leaves the code
// as it was.
func signWithToken(caDir, token string, client netip.Addr, csrData []byte, certType, base string, days int,
	ekus, kus []string, setupCodes bool) (cert, caCert *x509.Certificate, fileName string, err error) {
	issueMu.Lock()
	defer issueMu.Unlock()
	unlock, err := lockTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	defer unlock()
	caCert, err = loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, nil, "", err
	}
	db, err := loadTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	token = strings.TrimSpace(token)
	var name string
	var tok *apiToken
	if setupCodes && !strings.Contains(token, ".") {
		hash := setupCodeHash(token)
		for n, t := range db.Tokens {
			if t.pending() && t.Setup.Code == hash {
				name, tok = n, t
			}
		}
		switch {
		case tok == nil:
			return nil, nil, "", apiErr(http.StatusUnauthorized, "unknown or used setup code")
		case !time.Now().Before(tok.Expires):
			return nil, nil, "", apiErr(http.StatusUnauthorized, "the setup code has expired")
		case !(&apiToken{Clients: tok.Setup.Clients}).clientAllowed(client):
			return nil, nil, "", apiErr(http.StatusForbidden, "the setup code is not usable from %s", client)
		}
	} else if name, tok, err = checkToken(db, caCert, token); err != nil {
		return nil, nil, "", otherCAToken(caDir, token, err)
	}
	if !tok.clientAllowed(client) {
		return nil, nil, "", apiErr(http.StatusForbidden, "the token is not allowed from %s", client)
	}
	if !tok.hasScope("sign") {
		return nil, nil, "", apiErr(http.StatusForbidden, "the token does not have the scope sign")
	}
	// The default type is the first type of the token, server for the type *.
	if certType == "" && len(tok.Types) > 0 {
		if certType = tok.Types[0]; certType == "*" {
			certType = "server"
		}
	}
	if !allows(tok.Types, certType) {
		return nil, nil, "", apiErr(http.StatusForbidden,
			"the token does not allow the type '%s'; choose a type it allows, %s, or the default, its first type",
			certType, strings.Join(tok.Types, ", "))
	}
	cfg, err := loadRootConfig(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	types, err := cfg.certTypes()
	if err != nil {
		return nil, nil, "", err
	}
	def, ok := types[certType]
	if !ok {
		return nil, nil, "", apiErr(http.StatusBadRequest, "unknown type '%s'", certType)
	}
	csr, err := parseCSR(csrData)
	if err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "csr: %v", err)
	}
	if err := checkCSRNames(csr, def.names, tok); err != nil {
		return nil, nil, "", err
	}

	// The signing form names the file after the CN, else the first DNS name or email address.
	if base == "" {
		cn, email := csr.Subject.CommonName, ""
		if cn == "" && len(csr.DNSNames) > 0 {
			cn = csr.DNSNames[0]
		}
		for _, attr := range csr.Subject.Names {
			if s, ok := attr.Value.(string); ok && attr.Type.Equal(oidEmailAddress) && email == "" {
				email = s
			}
		}
		if email == "" && len(csr.EmailAddresses) > 0 {
			email = csr.EmailAddresses[0]
		}
		base = certFileName(strings.TrimPrefix(cn, "*."), email, def.names == "user")
	}
	if base != "" {
		if fileName, err = certFile(base); err != nil {
			return nil, nil, "", apiErr(http.StatusBadRequest, "name: %v", err)
		}
	}
	if days == 0 {
		days = cmp.Or(cfg.Days.Cert, 365)
	}
	tmpl := &x509.Certificate{RawSubject: csr.RawSubject}
	if san := csrSAN(csr); san != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	if _, _, _, err := parseUsages(append(slices.Clone(def.keyUsage), kus...),
		append(slices.Clone(def.extKeyUsage), ekus...)); err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "%v", err)
	}
	cert, err = issueLeaf(caDir, certType, days, ekus, kus, tmpl, csr.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	serial := serialHex(cert.SerialNumber)
	fileName = cmp.Or(fileName, serial+"_cert.pem")
	if err := storeCert(caDir, filepath.Join(caDir, fileName), cert); err != nil {
		return nil, nil, "", err
	}
	tok.Certs = append(tok.Certs, serial)
	byCode := tok.pending()
	if byCode {
		// The token of a setup code signs this certificate alone.
		tok.Setup, tok.Expires = nil, time.Now().UTC().Truncate(time.Second)
	}
	if err := db.save(caDir); err != nil {
		return nil, nil, "", err
	}
	via := "api"
	if setupCodes {
		via = "form"
	}
	pairs := []any{"setup_code", byCode, "via", via, "actor", name}
	if tok.OIDC != nil {
		pairs = append(pairs, "oidc_user", tok.OIDC.User)
	}
	auditIssued(caDir, cert, certType, append(pairs, "client", client.String())...)
	return cert, caCert, fileName, nil
}

// apiSign serves a POST of /api/sign for the CA in caDir: it signs the CSR of the JSON request
// with the type it names for the bearer token of the request, as signWithToken, for the client
// clientAddr finds with the trusted proxies, and returns the certificate with its chain.
func apiSign(w http.ResponseWriter, r *http.Request, caDir string) {
	if !fileExists(filepath.Join(caDir, "ca_key.pem")) || !fileExists(filepath.Join(caDir, tokensFile)) {
		http.NotFound(w, r)
		return
	}
	var cert, caCert *x509.Certificate
	var req struct {
		CSR  string   `json:"csr"`
		Type string   `json:"type"`
		Name string   `json:"name"`
		Days int      `json:"days"`
		KU   []string `json:"ku"`
		EKU  []string `json:"eku"`
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	dec := json.NewDecoder(io.LimitReader(r.Body, acmeMaxBody))
	dec.DisallowUnknownFields()
	client := clientAddr(r)
	var err error
	switch {
	case strings.TrimSpace(ct) != "application/json":
		err = apiErr(http.StatusUnsupportedMediaType, "the content type must be application/json")
	case !ok:
		err = apiErr(http.StatusUnauthorized, "a bearer token is required")
		auditRefused(r, caDir, "a bearer token is required", client)
	case dec.Decode(&req) != nil:
		err = apiErr(http.StatusBadRequest, "invalid request: the body is not a JSON object of csr, type, name, "+
			"days, ku and eku")
	// The API takes no defaults: the type, the file name and the days are given, as cert sign takes them.
	case strings.TrimSpace(req.Type) == "":
		err = apiErr(http.StatusBadRequest, "type: the certificate type is required")
	case strings.TrimSpace(req.Name) == "" || strings.ContainsAny(req.Name, `/\`):
		err = apiErr(http.StatusBadRequest, "name: the file name of the certificate is required, without a directory")
	case req.Days < 1:
		err = apiErr(http.StatusBadRequest, "days: the validity in days must be a positive integer")
	default:
		err = guard.attempt(w, r, caDir, func() (err error) {
			cert, caCert, _, err = signWithToken(caDir, token, client, []byte(req.CSR), req.Type, req.Name, req.Days,
				req.EKU, req.KU, false)
			return err
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		var e *apiError
		if !errors.As(err, &e) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		if e.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(map[string]string{"error": e.msg})
		return
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	chain := certPEM
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	}
	json.NewEncoder(w).Encode(map[string]string{"serial": serialHex(cert.SerialNumber), "certificate": certPEM, "chain": chain})
}

// ---- /sign ------------------------------------------------------------------

// signPage serves /sign for the CA in caDir, whose page is at path: GET shows the form, and POST
// signs its CSR with its type and token, or setup code, as signWithToken, and sends the
// certificate as a download, or shows the form again with the error. For a CA without its key or
// its tokens-db.json, the page says why it signs no requests, and a POST is 403 Forbidden. The
// client is the one clientAddr finds with the trusted proxies.
func signPage(w http.ResponseWriter, r *http.Request, caDir, path string) {
	caCert, err1 := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	cfg, err2 := loadRootConfig(caDir)
	var types map[string]certTypeDef
	if err := cmp.Or(err1, err2); err == nil {
		types, err1 = cfg.certTypes()
	}
	if err := cmp.Or(err1, err2); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, CSR, Type, Error, Unavailable string
		Theme                                                template.CSS
		Types                                                []struct{ Name, Label string }
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: path, Theme: pageTheme(caDir)}

	// Each type is offered with what its certificates are for: its extended key usages, else its
	// key usages.
	usageWords := map[string]string{"serverAuth": "TLS server", "clientAuth": "TLS client",
		"emailProtection": "e-mail", "codeSigning": "code signing"}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		def := types[name]
		var words []string
		for _, usage := range def.extKeyUsage {
			words = append(words, cmp.Or(usageWords[usage], usage))
		}
		description := "no key usages"
		switch {
		case len(words) > 1:
			description = strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
		case len(words) == 1:
			description = words[0]
		case len(def.keyUsage) > 0:
			description = "key usages " + strings.Join(def.keyUsage, ", ")
		}
		page.Types = append(page.Types, struct{ Name, Label string }{name, name + ": " + description})
	}

	// A CA without its key or its tokens shows why it signs no requests, in place of the form.
	switch {
	case !fileExists(filepath.Join(caDir, "ca_key.pem")):
		page.Unavailable = "No key of this CA on this server"
	case !fileExists(filepath.Join(caDir, tokensFile)):
		page.Unavailable = "This CA has no tokens yet"
	}

	status := http.StatusOK
	switch {
	case page.Unavailable != "" && r.Method == http.MethodPost:
		status = http.StatusForbidden
	case r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, acmeMaxBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "the form is too large or malformed", http.StatusBadRequest)
			return
		}
		page.CSR, page.Type = r.PostForm.Get("csr"), r.PostForm.Get("type")
		client := clientAddr(r)
		var cert *x509.Certificate
		var fileName string
		token := strings.TrimSpace(r.PostForm.Get("token"))
		var err error = apiErr(http.StatusUnauthorized, "a token or a setup code is required")
		if token == "" {
			auditRefused(r, caDir, "a token or a setup code is required", client)
		} else {
			// The form takes the defaults of the type, the days and the file name.
			err = guard.attempt(w, r, caDir, func() (err error) {
				cert, _, fileName, err = signWithToken(caDir, token, client, []byte(page.CSR), page.Type, "", 0, nil, nil, true)
				return err
			})
		}
		if err == nil {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fileName}))
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			return
		}
		var e *apiError
		if !errors.As(err, &e) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		status, page.Error = e.status, e.msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "sign.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}
