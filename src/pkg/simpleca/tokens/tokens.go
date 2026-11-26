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

// Package tokens holds the tokens of the signing API, their setup codes, and the token types
// of the JWTs for workload identity federation.
package tokens

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/database"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
)

// TokensFile is the file of a CA directory holding the tokens of its signing API.
const TokensFile = "tokens-db.json"

// TokenScopes are the scopes a token may have: sign for the signing API and the signing form,
// SignCA, tokens for the token page of serve --webui, certs for its certificate page, audit for
// its audit page, secrets for its secret page, federate for the JWTs of a token type at
// /api/federation-token, and SelfCert; the scope * is all of them but SignCA and SelfCert.
var TokenScopes = []string{"sign", SignCA, "tokens", "certs", "audit", "secrets", "federate", SelfCert}

// SignCA is the scope of the CA certificates of path length 0 an issuing CA of path length 1
// signs at /CA/api/sign-ca. Only a token of such a CA has it, and the scope * does not stand for it.
const SignCA = "sign-ca"

// SelfCert is the scope of the user certificate of the OIDC user a token was made for, at
// /api/self-cert. The OIDC sign-in alone gives it, and the scope * does not stand for it.
const SelfCert = "self-cert"

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

// TokenOIDC is the OIDC user a token was made for: issuer, subject and user claim, and, of a
// token with the scope self-cert, the profile, the verified email address and the name of the
// user certificate.
type TokenOIDC struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	User    string `json:"user"`
	Profile string `json:"profile,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
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

// SetupCodeHash returns the hex SHA-256 of the setup code, as NormalSetupCode gives it, as it is
// stored.
func SetupCodeHash(code string) string {
	sum := sha256.Sum256([]byte(NormalSetupCode(code)))
	return fmt.Sprintf("%x", sum)
}

// NormalSetupCode returns the setup code in upper case, without dashes and spaces.
func NormalSetupCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
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
	prefixes, err := ToPrefixes("setup code network", setupClients, false)
	if err != nil {
		return nil, "", err
	}
	code := NewSetupCode()
	return &TokenSetup{Code: SetupCodeHash(code), Clients: prefixes, Valid: simpleca.DurationText(valid)}, code, nil
}

// NewSetupCode returns a new one-time code of 80 random bits, such as ABCD-EFGH-IJKL-MNOP, the
// setup code of a token or the code of a secret.
func NewSetupCode() string {
	b := make([]byte, 10)
	rand.Read(b)
	s := base32.StdEncoding.EncodeToString(b)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// ToPrefixes returns the addresses and prefixes of values, what they are named in its error, as
// masked prefixes, an address as the prefix of that address alone; with any, "*" is kept.
func ToPrefixes(what string, values []string, any bool) ([]string, error) {
	var prefixes []string
	for _, s := range values {
		if s == "*" && any {
			prefixes = append(prefixes, s)
			continue
		}
		prefix, ok := simpleca.ParsePrefix(s)
		if !ok {
			return nil, fmt.Errorf("%s %q is not an IP address or a prefix such as 10.0.0.0/8", what, s)
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

// HasScope reports whether the token has the scope, named or by the scope *; SignCA and SelfCert
// only named.
func (t *APIToken) HasScope(scope string) bool {
	if scope == SelfCert || scope == SignCA {
		return slices.Contains(t.Scopes, scope)
	}
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

// tokensTable returns the quoted table of the tokens of caDir and the ID of its CA, or an empty
// table when database.tokens_db of its root CA names none, or caDir holds no CA; an error when the
// table is named and tokens-db.json is still there.
func tokensTable(caDir string) (table, ca string, err error) {
	rootDir, ca, err := simpleca.LocateCA(caDir)
	if err != nil {
		return "", "", nil
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return "", "", err
	}
	if cfg.Database.TokensDB == "" {
		return "", "", nil
	}
	if simpleca.FileExists(filepath.Join(caDir, TokensFile)) {
		return "", "", fmt.Errorf("%q is not migrated to the database; run simple-ca database migrate tokens_db",
			filepath.Join(caDir, TokensFile))
	}
	return database.Table(cfg.Database, cfg.Database.TokensDB), ca, nil
}

// Store names where the tokens of caDir are kept: tokens-db.json, or the table of database.tokens_db.
func Store(caDir string) string {
	if table, _, err := tokensTable(caDir); err == nil && table != "" {
		return "the table " + table
	}
	return fmt.Sprintf("%q", filepath.Join(caDir, TokensFile))
}

// Exists reports whether caDir has tokens: its tokens-db.json, or a row of the table of
// database.tokens_db.
func Exists(caDir string) bool {
	table, ca, err := tokensTable(caDir)
	if err != nil || table == "" {
		return simpleca.FileExists(filepath.Join(caDir, TokensFile))
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return false
	}
	var found bool
	return p.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE ca = $1)", ca).Scan(&found) == nil && found
}

// LoadTokens reads the tokens of caDir from tokens-db.json, or from the table of
// database.tokens_db, an empty database when there are none.
func LoadTokens(caDir string) (*TokensDB, error) {
	db := &TokensDB{Tokens: map[string]*APIToken{}}
	table, ca, err := tokensTable(caDir)
	if err != nil {
		return nil, err
	}
	if table != "" {
		ctx := context.Background()
		p, err := database.Pool(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := p.Query(ctx, "SELECT name, token FROM "+table+" WHERE ca = $1", ca)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			var b []byte
			if err := rows.Scan(&name, &b); err != nil {
				return nil, err
			}
			var t APIToken
			if err := json.Unmarshal(b, &t); err != nil {
				return nil, fmt.Errorf("could not read the token %q of %s: %w", name, table, err)
			}
			db.Tokens[name] = &t
		}
		return db, rows.Err()
	}
	return loadTokensFile(caDir)
}

// loadTokensFile reads tokens-db.json of caDir, an empty database when it does not exist.
func loadTokensFile(caDir string) (*TokensDB, error) {
	db := &TokensDB{Tokens: map[string]*APIToken{}}
	b, err := os.ReadFile(filepath.Join(caDir, TokensFile))
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, fmt.Errorf("could not read %q: %w", filepath.Join(caDir, TokensFile), err)
	}
	if db.Tokens == nil {
		db.Tokens = map[string]*APIToken{}
	}
	return db, nil
}

// Migrated is the count of the tokens a migration moved of the CA of an ID, empty for the root CA.
type Migrated struct {
	CA    string
	Count int
}

// Migrate moves the tokens-db.json files of the root CA in rootDir and its issuing CAs to the table
// of database.tokens_db of cfg, in one transaction refused when the table already holds tokens of
// one of those CAs, renames each file to tokens-db.json.migrated, and returns the counts.
func Migrate(rootDir string, cfg *simpleca.Config) ([]Migrated, error) {
	if cfg.Database.TokensDB == "" {
		return nil, fmt.Errorf("database.tokens_db of %q names no table", cfg.Path)
	}
	table := database.Table(cfg.Database, cfg.Database.TokensDB)
	var dirs []string
	var counts []Migrated
	files := map[string]*TokensDB{}
	for _, id := range simpleca.CAIDs(rootDir) {
		dir := filepath.Join(rootDir, id)
		if !simpleca.FileExists(filepath.Join(dir, TokensFile)) {
			continue
		}
		unlock, err := simpleca.LockFile(filepath.Join(dir, TokensFile))
		if err != nil {
			return nil, err
		}
		defer unlock()
		db, err := loadTokensFile(dir)
		if err != nil {
			return nil, err
		}
		dirs, files[id] = append(dirs, dir), db
		counts = append(counts, Migrated{CA: id, Count: len(db.Tokens)})
	}
	if len(dirs) == 0 {
		return nil, fmt.Errorf("no %s in %q or its issuing CAs", TokensFile, rootDir)
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	for _, m := range counts {
		var found bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE ca = $1)", m.CA).Scan(&found); err != nil {
			return nil, err
		}
		if found {
			return nil, fmt.Errorf("%s already holds tokens of the CA %q; nothing is migrated", table, m.CA)
		}
		for name, t := range files[m.CA].Tokens {
			b, err := json.Marshal(t)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (ca, name, token) VALUES ($1, $2, $3)", m.CA, name, b); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		if err := os.Rename(filepath.Join(dir, TokensFile), filepath.Join(dir, TokensFile+".migrated")); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

// Save writes the tokens of caDir to tokens-db.json, a new file of the private mode, or replaces
// those of its CA in the table of database.tokens_db in one transaction.
func (db *TokensDB) Save(caDir string) error {
	table, ca, err := tokensTable(caDir)
	if err != nil {
		return err
	}
	if table != "" {
		ctx := context.Background()
		p, err := database.Pool(ctx)
		if err != nil {
			return err
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE ca = $1", ca); err != nil {
			return err
		}
		for name, t := range db.Tokens {
			b, err := json.Marshal(t)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (ca, name, token) VALUES ($1, $2, $3)", ca, name, b); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, TokensFile+".tmp")
	os.Remove(tmp)
	if err := simpleca.WritePrivateFile(tmp, append(b, '\n')); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, TokensFile))
}

// LockTokens locks the tokens of caDir: tokens-db.json, as simpleca.LockFile does, or its CA in
// the table of database.tokens_db, with an advisory lock held on a connection of its own, waiting
// as long.
func LockTokens(caDir string) (func(), error) {
	table, ca, err := tokensTable(caDir)
	if err != nil {
		return nil, err
	}
	if table == "" {
		return simpleca.LockFile(filepath.Join(caDir, TokensFile))
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := p.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := database.LockKey(table, ca)
	deadline := time.Now().Add(simpleca.TokensLockWait)
	for {
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
			conn.Release()
			return nil, err
		}
		if locked {
			return func() {
				conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
				conn.Release()
			}, nil
		}
		if time.Now().After(deadline) {
			conn.Release()
			return nil, fmt.Errorf("the tokens of CA %q in %s are locked by another process", ca, table)
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
	if slices.Contains(scopes, SelfCert) {
		return "", errors.New("the scope self-cert is given by the OIDC sign-in alone")
	}
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
		return "", fmt.Errorf("token %q exists", name)
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
	if !simpleca.KebabCaseRE.MatchString(name) {
		return nil, nil, fmt.Errorf("token name %q is not a kebab-case name, such as web-deploy", name)
	}
	if len(scopes) == 0 {
		scopes = []string{"sign"}
	}
	for _, s := range scopes {
		if s != "*" && !slices.Contains(TokenScopes, s) {
			return nil, nil, fmt.Errorf("unknown scope %q: must be one of %s or *", s, strings.Join(TokenScopes, ", "))
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
		if d != "*" && !simpleca.IsHostname(d) {
			return nil, nil, fmt.Errorf("domain %q is not a domain name or *", d)
		}
		names = append(names, d)
	}
	prefixes, err := ToPrefixes("IP address", ips, true)
	if err != nil {
		return nil, nil, err
	}
	clientPrefixes, err := ToPrefixes("client", clients, false)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := simpleca.LoadRootConfig(caDir)
	if err != nil {
		return nil, nil, err
	}
	types, err := cert.Types(cfg)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range certTypes {
		if _, ok := types[t]; !ok && t != "*" {
			return nil, nil, fmt.Errorf("unknown type %q: must be one of %s or *", t, cert.TypeNames(types))
		}
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !simpleca.FileExists(filepath.Join(caDir, "ca_cert.pem")) || !simpleca.FileExists(caKeyPath) {
		return nil, nil, fmt.Errorf("CA certificate and key not found in %q, which is not a CA directory", caDir)
	}
	if slices.Contains(scopes, SignCA) {
		if err := CheckSignCA(caDir); err != nil {
			return nil, nil, err
		}
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return nil, nil, err
	}
	if fed != nil {
		_, caID, err := simpleca.LocateCA(caDir)
		if err != nil {
			return nil, nil, err
		}
		if _, err := fed.Resolve(cfg, caID, name); err != nil {
			return nil, nil, err
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	return &APIToken{ID: simpleca.RandomID(), Scopes: scopes, Types: certTypes, Domains: names, IPs: prefixes,
		Clients: clientPrefixes, Issued: now, Expires: now.Add(valid), Federate: fed}, caKey, nil
}

// CheckSignCA returns an error unless the CA in caDir is an issuing CA whose certificate has the
// path length 1, the CA a token of the scope SignCA belongs to.
func CheckSignCA(caDir string) error {
	_, caID, err := simpleca.LocateCA(caDir)
	if err != nil {
		return err
	}
	crt, err := simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return err
	}
	if caID == "" || crt.MaxPathLen != 1 {
		return fmt.Errorf("the scope %s needs an issuing CA of path length 1, created with ca create --issuing-ca "+
			"--path-length 1 under a root CA of path length 2", SignCA)
	}
	return nil
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
	return jose.SignJWT(caKey, claims)
}

// Validity returns the validity a pending token gets at the exchange of its setup code, stored
// as simpleca.ParseDuration reads it, or as Go writes a duration, such as 1h0m0s, by earlier
// releases.
func (s *TokenSetup) Validity() (time.Duration, error) {
	d, err := simpleca.ParseDuration(s.Valid)
	if err != nil {
		if d, goErr := time.ParseDuration(s.Valid); goErr == nil {
			return d, nil
		}
	}
	return d, err
}
