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

package simpleca

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// TokensFile is the file of a CA directory holding the tokens of its signing API.
const TokensFile = "tokens-db.json"

// TokensLockWait is how long a command or serve waits for the lock of tokens-db.json.
var TokensLockWait = 10 * time.Second

// TokenScopes are the scopes a token may have: sign for the signing API and the signing form,
// tokens for the token page of serve --webui, certs for its certificate page, audit for its audit
// page, and federate for the JWTs of a token type at /api/federation-token; the scope * is all of
// them.
var TokenScopes = []string{"sign", "tokens", "certs", "audit", "federate"}

// Allows reports whether values, the scopes or the certificate types of a token, hold value or *,
// which stands for every value.
func Allows(values []string, value string) bool {
	return slices.Contains(values, value) || slices.Contains(values, "*")
}

// checkAll returns an error, naming what values are, when values hold * with other values.
func checkAll(what string, values []string) error {
	if slices.Contains(values, "*") && len(values) > 1 {
		return fmt.Errorf("the %s * stands for every %s and must be given alone", what, what)
	}
	return nil
}

// APIToken is a token of a CA: its JWT ID, its scopes, the certificate types, the domains and the
// IP address prefixes it allows with the scope sign, each "*" for any, the prefixes of the client
// addresses it is used from, any without them, its validity, the serial numbers of the
// certificates issued with it, the setup code it waits for, the OIDC user it was made for, and the
// JWT of a token type it gets with the scope federate. A token without a JWT ID and a setup code
// is revoked: it expired when it was revoked, and is kept to be renewed until it is purged. A token
// with a setup code is pending: it has no JWT until the code is exchanged, and expires with the
// code.
type APIToken struct {
	ID       string         `json:"id,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	Types    []string       `json:"types,omitempty"`
	Domains  []string       `json:"domains,omitempty"`
	IPs      []string       `json:"ips,omitempty"`
	Clients  []string       `json:"clients,omitempty"`
	Issued   time.Time      `json:"issued"`
	Expires  time.Time      `json:"expires"`
	Certs    []string       `json:"certs,omitempty"`
	Setup    *TokenSetup    `json:"setup,omitempty"`
	OIDC     *TokenOIDC     `json:"oidc,omitempty"`
	Federate *TokenFederate `json:"federate,omitempty"`
}

// TokenOIDC is the OIDC user a token was made for: issuer, subject and user claim.
type TokenOIDC struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	User    string `json:"user"`
}

// TokenSetup is the one-time setup code a pending token waits for: the SHA-256 of the code, in
// hex, the prefixes of the client addresses it is exchanged from, any without them, and the
// validity of the token, a duration such as 8h, which starts at the exchange.
type TokenSetup struct {
	Code    string   `json:"code"`
	Clients []string `json:"clients,omitempty"`
	Valid   string   `json:"valid"`
}

// Revoked reports whether the token is revoked, having neither a JWT ID nor a setup code.
func (t *APIToken) Revoked() bool {
	return t.ID == "" && t.Setup == nil
}

// Pending reports whether the token waits for its setup code.
func (t *APIToken) Pending() bool {
	return t.Setup != nil
}

// SetupCodeHash returns the hex SHA-256 of the setup code, in upper case without dashes and
// spaces, as it is stored.
func SetupCodeHash(code string) string {
	code = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", sum)
}

// NewTokenSetup returns, for a setupValid, the setup of a token valid for valid once its new
// setup code is exchanged from the client addresses setupClients, any without them, and the code;
// for no setupValid, nil and no code.
func NewTokenSetup(valid, setupValid time.Duration, setupClients []string) (*TokenSetup, string, error) {
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
	return &TokenSetup{Code: SetupCodeHash(code), Clients: prefixes, Valid: DurationText(valid)}, code, nil
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
		prefix, ok := ParsePrefix(s)
		if !ok {
			return nil, fmt.Errorf("%s '%s' is not an IP address or a prefix such as 10.0.0.0/8", what, s)
		}
		prefixes = append(prefixes, prefix.String())
	}
	return prefixes, nil
}

// EffectiveScopes returns the scopes of the token; an entry without them has the scope sign.
func (t *APIToken) EffectiveScopes() []string {
	if len(t.Scopes) == 0 {
		return []string{"sign"}
	}
	return t.Scopes
}

// HasScope reports whether the token has the scope, named or by the scope *.
func (t *APIToken) HasScope(scope string) bool {
	return Allows(t.EffectiveScopes(), scope)
}

// ClientAllowed reports whether the token is used from the address client: one in its client
// prefixes, or any without them.
func (t *APIToken) ClientAllowed(client netip.Addr) bool {
	return len(t.Clients) == 0 || slices.ContainsFunc(t.Clients, func(s string) bool {
		prefix, err := netip.ParsePrefix(s)
		return err == nil && prefix.Contains(client)
	})
}

// TokensDB is tokens-db.json of a CA directory, the tokens of its signing API by name.
type TokensDB struct {
	Tokens map[string]*APIToken `json:"tokens"`
}

// JWTClaims are the claims of a token: its ID, its name, its scopes, separated by spaces, and when
// it was issued and expires, in seconds since the epoch; and the issuer and the audience of a JWT
// of a token type, which a token never has.
type JWTClaims struct {
	ID        string          `json:"jti"`
	Issuer    string          `json:"iss,omitempty"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud,omitempty"`
	Scope     string          `json:"scope,omitempty"`
	IssuedAt  int64           `json:"iat"`
	ExpiresAt int64           `json:"exp"`
}

// Token returns the token the claims hold, without what tokens-db.json alone holds.
func (c *JWTClaims) Token() *APIToken {
	return &APIToken{ID: c.ID, Scopes: strings.Fields(c.Scope), Issued: time.Unix(c.IssuedAt, 0),
		Expires: time.Unix(c.ExpiresAt, 0)}
}

// LoadTokens reads tokens-db.json of caDir, or returns an empty database when it does not exist.
func LoadTokens(caDir string) (*TokensDB, error) {
	db := &TokensDB{Tokens: map[string]*APIToken{}}
	b, err := os.ReadFile(filepath.Join(caDir, TokensFile))
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", filepath.Join(caDir, TokensFile), err)
	}
	if db.Tokens == nil {
		db.Tokens = map[string]*APIToken{}
	}
	return db, nil
}

// Save writes the database to tokens-db.json of caDir, readable by its owner alone.
func (db *TokensDB) Save(caDir string) error {
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, TokensFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, TokensFile))
}

// LockTokens locks tokens-db.json of caDir, as LockFile does.
func LockTokens(caDir string) (func(), error) {
	return LockFile(filepath.Join(caDir, TokensFile))
}

// LockFile locks the file for the commands and serve by creating FILE.lock, which one of them at
// a time can create, holding the PID of the locker. It waits up to TokensLockWait for the lock,
// and returns the function that unlocks it.
func LockFile(file string) (func(), error) {
	path := file + ".lock"
	deadline := time.Now().Add(TokensLockWait)
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
				file, strings.TrimSpace(string(pid)), path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// MakeToken adds the token name to tokens-db.json of the CA in caDir and returns its JWT, as
// AddToken does without a setup code and the scope federate.
func MakeToken(caDir, name string, valid time.Duration, scopes, certTypes, domains, ips, clients []string) (string, error) {
	return AddToken(caDir, name, nil, valid, scopes, certTypes, domains, ips, clients, 0, nil)
}

// AddToken adds the token name, valid for valid, with the scopes, sign without them, used from
// the client addresses clients, to tokens-db.json of the CA in caDir, and returns its JWT, signed
// with the CA key. With the scope sign, it allows the certificate types certTypes, the domains and
// the IP addresses ips, which belong to that scope alone. A scope, a type, a domain or an IP
// address "*" allows any; an IP address or a client address is an address or a prefix, kept as a
// prefix, and no clients allow any client. With a setupValid, the token is pending instead: it
// gets no JWT, and AddToken returns a setup code, valid for setupValid and exchanged from the
// client addresses setupClients, any without them, for the JWT. With the scope federate, fed is
// the JWT of a token type the token gets, which belongs to that scope alone.
func AddToken(caDir, name string, fed *TokenFederate, valid time.Duration, scopes, certTypes, domains, ips, clients []string,
	setupValid time.Duration, setupClients []string) (string, error) {
	setup, code, err := NewTokenSetup(valid, setupValid, setupClients)
	if err != nil {
		return "", err
	}
	tok, caKey, err := PrepareToken(caDir, name, fed, valid, scopes, certTypes, domains, ips, clients)
	if err != nil {
		return "", err
	}
	unlock, err := LockTokens(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := LoadTokens(caDir)
	if err != nil {
		return "", err
	}
	if _, ok := db.Tokens[name]; ok {
		return "", fmt.Errorf("token '%s' exists", name)
	}

	result := code
	if setup != nil {
		tok.ID, tok.Expires, tok.Setup = "", tok.Issued.Add(setupValid), setup
	} else if result, err = SignToken(caKey, name, tok); err != nil {
		return "", err
	}
	db.Tokens[name] = tok
	if err := db.Save(caDir); err != nil {
		return "", err
	}
	return result, nil
}

// PrepareToken validates and returns the token name of the CA in caDir, with the JWT of a token
// type fed of the scope federate, unsaved, and the CA key.
func PrepareToken(caDir, name string, fed *TokenFederate, valid time.Duration, scopes, certTypes, domains, ips, clients []string) (*APIToken, crypto.Signer, error) {
	if valid < time.Second {
		return nil, nil, errors.New("the validity of a token must be at least 1s")
	}
	if !KebabCaseRE.MatchString(name) {
		return nil, nil, fmt.Errorf("token name '%s' is not a kebab-case name, such as web-deploy", name)
	}
	if len(scopes) == 0 {
		scopes = []string{"sign"}
	}
	for _, s := range scopes {
		if s != "*" && !slices.Contains(TokenScopes, s) {
			return nil, nil, fmt.Errorf("unknown scope '%s': must be one of %s or *", s, strings.Join(TokenScopes, ", "))
		}
	}
	if err := cmp.Or(checkAll("scope", scopes), checkAll("type", certTypes)); err != nil {
		return nil, nil, err
	}
	if !slices.Contains(scopes, "*") {
		scopes = slices.DeleteFunc(slices.Clone(TokenScopes), func(s string) bool { return !slices.Contains(scopes, s) })
	}
	switch {
	case !Allows(scopes, "sign") && len(certTypes)+len(domains)+len(ips) > 0:
		return nil, nil, errors.New("certificate types, domains, IP addresses and localhost need the scope sign")
	case !Allows(scopes, "sign"):
	case len(domains) == 0 && len(ips) == 0:
		return nil, nil, errors.New("a token with the scope sign needs a domain or an IP address")
	}
	// A token with the scope federate and no token type gets no JWTs; it grants the scope on the
	// token page.
	if !Allows(scopes, "federate") && fed != nil {
		return nil, nil, errors.New("a token type, an audience and claims need the scope federate")
	}
	var names []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d != "*" && !IsHostname(d) {
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
	cfg, err := LoadRootConfig(caDir)
	if err != nil {
		return nil, nil, err
	}
	types, err := cfg.CertTypes()
	if err != nil {
		return nil, nil, err
	}
	for _, t := range certTypes {
		if _, ok := types[t]; !ok && t != "*" {
			return nil, nil, fmt.Errorf("unknown type '%s': must be one of %s or *", t, TypeNames(types))
		}
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !FileExists(filepath.Join(caDir, "ca_cert.pem")) || !FileExists(caKeyPath) {
		return nil, nil, fmt.Errorf("CA certificate and key not found in %s, which is not a CA directory", caDir)
	}
	caKey, err := LoadKey(caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	if fed != nil {
		_, caID, err := LocateCA(caDir)
		if err != nil {
			return nil, nil, err
		}
		if _, err := fed.Resolve(cfg, caID, name); err != nil {
			return nil, nil, err
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	return &APIToken{ID: RandomID(), Scopes: scopes, Types: certTypes, Domains: names, IPs: prefixes,
		Clients: clientPrefixes, Issued: now, Expires: now.Add(valid), Federate: fed}, caKey, nil
}

// Active reports whether the token is neither revoked, pending nor expired at now.
func (t *APIToken) Active(now time.Time) bool {
	return !t.Revoked() && !t.Pending() && now.Before(t.Expires)
}

// OwnedBy reports whether the token was made for the OIDC user owner.
func (t *APIToken) OwnedBy(owner *TokenOIDC) bool {
	return t.OIDC != nil && t.OIDC.Issuer == owner.Issuer && t.OIDC.Subject == owner.Subject
}

// SignToken returns the JWT of the token name, its claims signed with caKey.
func SignToken(caKey crypto.Signer, name string, tok *APIToken) (string, error) {
	claims, err := json.Marshal(JWTClaims{ID: tok.ID, Subject: name, Scope: strings.Join(tok.Scopes, " "),
		IssuedAt: tok.Issued.Unix(), ExpiresAt: tok.Expires.Unix()})
	if err != nil {
		return "", err
	}
	return signJWT(caKey, claims)
}

// signJWT returns the JWT of the JSON claims signed with caKey, RS256 for an RSA key and ES256 for
// an ECDSA P-256 key, its header naming the key by its JWK thumbprint.
func signJWT(caKey crypto.Signer, claims []byte) (string, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{JWTAlg(caKey.Public()), publicJWK(caKey.Public()).Kid, "JWT"})
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := caKey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		// An ES256 signature is r and s of 32 bytes each, not ASN.1 (RFC 7518 3.4).
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand.Reader, k, digest[:]); err == nil {
			sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	default:
		err = errors.New("the CA key is not an RSA or ECDSA P-256 key")
	}
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWTAlg returns the JWS algorithm of the JWTs the key of pub signs: ES256 for an ECDSA key,
// RS256 for an RSA key.
func JWTAlg(pub crypto.PublicKey) string {
	if KeyType(pub) == "ec" {
		return "ES256"
	}
	return "RS256"
}

// Validity returns the validity a pending token gets at the exchange of its setup code, stored
// as ParseDuration reads it, or as Go writes a duration, such as 1h0m0s, by earlier releases.
func (s *TokenSetup) Validity() (time.Duration, error) {
	d, err := ParseDuration(s.Valid)
	if err != nil {
		if d, goErr := time.ParseDuration(s.Valid); goErr == nil {
			return d, nil
		}
	}
	return d, err
}
