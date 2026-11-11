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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// loadToken returns the token name of tokens-db.json of caDir.
func loadToken(t *testing.T, caDir, name string) *APIToken {
	t.Helper()
	db, err := LoadTokens(caDir)
	if err != nil || db.Tokens[name] == nil {
		t.Fatalf("the token %s of %s: %v", name, caDir, err)
	}
	return db.Tokens[name]
}

func TestMakeToken(t *testing.T) {
	for _, keyType := range []string{"rsa", "ec"} {
		root := newRoot(t, keyType)
		jwt, err := MakeToken(root.dir, "deploy", time.Hour, nil, []string{"server", "user"}, []string{"Example.COM."}, nil, nil)
		if err != nil {
			t.Fatalf("MakeToken: %v", err)
		}
		info, err := os.Stat(filepath.Join(root.dir, TokensFile))
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, want mode 0600", TokensFile, err)
		}
		if FileExists(filepath.Join(root.dir, TokensFile+".lock")) || FileExists(filepath.Join(root.dir, TokensFile+".tmp")) {
			t.Fatalf("MakeToken left the lock or the temporary file of %s", TokensFile)
		}
		tok := loadToken(t, root.dir, "deploy")
		if !slices.Equal(tok.Domains, []string{"example.com"}) || !slices.Equal(tok.Types, []string{"server", "user"}) ||
			!slices.Equal(tok.Scopes, []string{"sign"}) || tok.Expires.Sub(tok.Issued) != time.Hour || tok.ID == "" ||
			!tok.Active(time.Now()) {
			t.Fatalf("token entry %+v, want the domains, types and validity given and the scope sign", tok)
		}

		// The JWT holds the token, signed with the CA key.
		jwks, err := CAJWKS(root.dir)
		if err != nil {
			t.Fatal(err)
		}
		header, claims := verifyJWT(t, jwt, jwks)
		if header["alg"] != JWTAlg(root.key.Public()) || claims["jti"] != tok.ID || claims["sub"] != "deploy" ||
			claims["scope"] != "sign" || claims["iat"] != float64(tok.Issued.Unix()) ||
			claims["exp"] != float64(tok.Expires.Unix()) || claims["iss"] != nil || claims["aud"] != nil {
			t.Fatalf("JWT %v %v, want the claims of the token deploy", header, claims)
		}
	}
}

func TestMakeTokenRefused(t *testing.T) {
	root := newRoot(t, "ec")
	if _, err := MakeToken(root.dir, "deploy", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	type tokenArgs struct {
		name                                 string
		valid                                time.Duration
		scopes, types, domains, ips, clients []string
	}
	type refusal struct {
		args tokenArgs
		want string
	}
	cases := []refusal{
		{tokenArgs{name: "deploy", types: []string{"server"}, domains: []string{"example.com"}}, "token 'deploy' exists"},
		{tokenArgs{name: "bad name", types: []string{"server"}, domains: []string{"example.com"}}, "kebab-case"},
		{tokenArgs{name: "other", types: []string{"nosuch"}, domains: []string{"example.com"}}, "unknown type 'nosuch'"},
		{tokenArgs{name: "other", types: []string{"server"}}, "needs a domain or an IP address"},
		{tokenArgs{name: "other", types: []string{"server"}, domains: []string{"192.0.2.1"}}, "is not a domain name"},
		{tokenArgs{name: "scoped", scopes: []string{"admin"}}, "unknown scope 'admin'"},
		{tokenArgs{name: "scoped", scopes: []string{"tokens"}, domains: []string{"example.com"}}, "need the scope sign"},
		{tokenArgs{name: "scoped", scopes: []string{"tokens"}, types: []string{"server"}}, "need the scope sign"},
		{tokenArgs{name: "all", scopes: []string{"*", "tokens"}}, "must be given alone"},
		{tokenArgs{name: "all", types: []string{"*", "server"}}, "must be given alone"},
		{tokenArgs{name: "all", scopes: []string{"*"}}, "needs a domain or an IP address"},
		{tokenArgs{name: "ips", domains: []string{"*"}, clients: []string{"*"}}, "client '*'"},
		{tokenArgs{name: "short", valid: time.Millisecond, domains: []string{"example.com"}}, "at least 1s"},
	}
	for _, name := range []string{"Servers", "lab_servers", "lab--servers", "-lab", "lab-", "lab.servers"} {
		cases = append(cases, refusal{tokenArgs{name: name, types: []string{"server"}, domains: []string{"example.com"}}, "kebab-case"})
	}
	for _, ips := range [][]string{{"300.1.2.3"}, {"10.0.0.0/33"}, {"fe80::1%en0"}, {"example.com"}} {
		cases = append(cases,
			refusal{tokenArgs{name: "ips", types: []string{"server"}, ips: ips}, "is not an IP address"},
			refusal{tokenArgs{name: "ips", types: []string{"server"}, domains: []string{"*"}, clients: ips}, "is not an IP address"})
	}
	for _, c := range cases {
		valid := c.args.valid
		if valid == 0 {
			valid = time.Hour
		}
		_, err := MakeToken(root.dir, c.args.name, valid, c.args.scopes, c.args.types, c.args.domains, c.args.ips, c.args.clients)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("MakeToken %+v: %v, want an error with %q", c.args, err, c.want)
		}
	}
	if db, err := LoadTokens(root.dir); err != nil || !slices.Equal(slices.Sorted(maps.Keys(db.Tokens)), []string{"deploy"}) {
		t.Errorf("tokens after the refused ones: %v, want deploy alone", err)
	}
}

func TestMakeTokenScopesAndAddresses(t *testing.T) {
	root := newRoot(t, "ec")
	if _, err := MakeToken(root.dir, "all", time.Hour, []string{"*"}, []string{"*"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("MakeToken --scope * --type *: %v", err)
	}
	if all := loadToken(t, root.dir, "all"); !all.HasScope("certs") || !Allows(all.Types, "user") ||
		!slices.Equal(all.Scopes, []string{"*"}) {
		t.Errorf("the token all: %+v, want every scope and every type", all)
	}
	if _, err := MakeToken(root.dir, "ips", time.Hour, nil, []string{"server"}, []string{"*"},
		[]string{"192.0.2.10", "10.1.2.3/8", "2001:db8::/32", "*"}, []string{"192.168.1.4", "172.16.1.0/12"}); err != nil {
		t.Fatalf("MakeToken with * and IP addresses: %v", err)
	}
	if ips := loadToken(t, root.dir, "ips"); !slices.Equal(ips.IPs, []string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::/32", "*"}) ||
		!slices.Equal(ips.Domains, []string{"*"}) || !slices.Equal(ips.Clients, []string{"192.168.1.4/32", "172.16.0.0/12"}) {
		t.Errorf("token entry %+v, want the IP prefixes and the clients masked and the domain *", ips)
	}

	// Scopes are kept in the order of TokenScopes; a token without sign needs no names.
	if _, err := MakeToken(root.dir, "pages", time.Hour, []string{"audit", "tokens", "certs"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("MakeToken of page scopes: %v", err)
	}
	if pages := loadToken(t, root.dir, "pages"); !slices.Equal(pages.Scopes, []string{"tokens", "certs", "audit"}) ||
		pages.HasScope("sign") {
		t.Errorf("the token pages: %+v, want the scopes tokens, certs and audit", pages)
	}
}

func TestMakeTokenOfIssuingCA(t *testing.T) {
	root := newRoot(t, "rsa")
	issuing := newIssuing(t, root, "lab-servers2", "ec")
	writeConfig(t, root.dir, `{"types": {"web-server": {"key_usage": ["digitalSignature"], "ext_key_usage": ["serverAuth"]}}}`)
	jwt, err := MakeToken(issuing.dir, "web", time.Hour, nil, []string{"web-server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("MakeToken of a type of the root simple-ca.json in an issuing CA: %v", err)
	}
	jwks, err := CAJWKS(issuing.dir)
	if err != nil {
		t.Fatal(err)
	}
	if header, _ := verifyJWT(t, jwt, jwks); header["alg"] != "ES256" {
		t.Errorf("JWT of the issuing CA: %v, want ES256", header)
	}
	loadToken(t, issuing.dir, "web")
	if FileExists(filepath.Join(root.dir, TokensFile)) {
		t.Errorf("the token of the issuing CA is in %s of the root CA", TokensFile)
	}
}

func TestMakeTokenOutsideCA(t *testing.T) {
	if _, err := MakeToken(t.TempDir(), "deploy", time.Hour, nil, nil, []string{"example.com"}, nil, nil); err == nil {
		t.Error("MakeToken outside a CA succeeded, want an error")
	}
	root := newRoot(t, "ec")
	copied := t.TempDir()
	b, err := os.ReadFile(filepath.Join(root.dir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "ca_cert.pem"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MakeToken(copied, "deploy", time.Hour, nil, nil, []string{"example.com"}, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "not a CA directory") {
		t.Errorf("MakeToken with a CA certificate alone: %v, want an error", err)
	}
}

func TestAddTokenSetupCode(t *testing.T) {
	root := newRoot(t, "rsa")
	issuing := newIssuing(t, root, "issuing-ca", "rsa")
	for _, c := range []struct {
		setupValid   time.Duration
		setupClients []string
		want         string
	}{
		{0, []string{"10.0.0.0/8"}, "need a setup code"},
		{-time.Hour, nil, "need a setup code"},
		{500 * time.Millisecond, nil, "at least 1s"},
		{time.Hour, []string{"10.0.0.0/33"}, "setup code network"},
	} {
		if _, err := AddToken(issuing.dir, "bad", nil, time.Hour, nil, nil, []string{"example.com"}, nil, nil,
			c.setupValid, c.setupClients); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("AddToken with a setup code of %v %v: %v, want an error with %q", c.setupValid, c.setupClients, err, c.want)
		}
	}

	// A token with a setup code is pending: it has no JWT ID and expires with the code.
	code, err := AddToken(issuing.dir, "remote", nil, 8*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("AddToken with a setup code: %v", err)
	}
	if ok, _ := regexp.MatchString(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`, code); !ok {
		t.Fatalf("setup code %q, want four groups of four base32 characters", code)
	}
	tok := loadToken(t, issuing.dir, "remote")
	if !tok.Pending() || tok.Revoked() || tok.ID != "" || tok.Setup.Code != SetupCodeHash(code) || tok.Setup.Clients != nil ||
		tok.Setup.Valid != "8h" || tok.Expires.Sub(tok.Issued) != time.Hour || tok.Active(time.Now()) {
		t.Fatalf("the pending token: %+v %+v, want a setup code valid for 1h and no JWT ID", tok, tok.Setup)
	}
	if valid, err := tok.Setup.Validity(); err != nil || valid != 8*time.Hour {
		t.Errorf("the validity after the exchange: %v, %v, want 8h", valid, err)
	}
	if _, err := AddToken(issuing.dir, "far", nil, time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour,
		[]string{"10.1.2.3/8", "192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	if far := loadToken(t, issuing.dir, "far"); !slices.Equal(far.Setup.Clients, []string{"10.0.0.0/8", "192.0.2.7/32"}) {
		t.Errorf("the networks of the setup code: %v, want them masked", far.Setup.Clients)
	}
}

func TestSetupCodeHash(t *testing.T) {
	setup, code, err := NewTokenSetup(2*time.Hour, time.Minute, nil)
	if err != nil || setup == nil || setup.Valid != "2h" {
		t.Fatalf("NewTokenSetup: %+v, %v", setup, err)
	}
	want := setup.Code
	for _, given := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", ""),
		" " + strings.ReplaceAll(code, "-", " ") + " "} {
		if got := SetupCodeHash(given); got != want {
			t.Errorf("SetupCodeHash(%q) = %s, want %s", given, got, want)
		}
	}
	if ok, _ := regexp.MatchString(`^[0-9a-f]{64}$`, want); !ok || SetupCodeHash("AAAA-BBBB-CCCC-DDDD") == want {
		t.Errorf("SetupCodeHash = %s, want the hex SHA-256 of the code alone", want)
	}
	if setup, code, err := NewTokenSetup(time.Hour, 0, nil); setup != nil || code != "" || err != nil {
		t.Errorf("NewTokenSetup without a setup code: %+v, %q, %v, want none", setup, code, err)
	}
}

func TestTokenSetupValidity(t *testing.T) {
	for valid, want := range map[string]time.Duration{"8h": 8 * time.Hour, "30": 30 * time.Minute, "1h0m0s": time.Hour,
		"90m0s": 90 * time.Minute} {
		if got, err := (&TokenSetup{Valid: valid}).Validity(); err != nil || got != want {
			t.Errorf("Validity of %q = %v, %v, want %v", valid, got, err, want)
		}
	}
	if _, err := (&TokenSetup{Valid: "8 hours"}).Validity(); err == nil {
		t.Error("Validity of \"8 hours\" succeeded, want an error")
	}
}

func TestTokenStates(t *testing.T) {
	now := time.Now()
	active := &APIToken{ID: "id", Issued: now.Add(-time.Hour), Expires: now.Add(time.Hour)}
	expired := &APIToken{ID: "id", Issued: now.Add(-2 * time.Hour), Expires: now.Add(-time.Hour)}
	revoked := &APIToken{Expires: now.Add(-time.Minute)}
	pending := &APIToken{Setup: &TokenSetup{Code: "x", Valid: "1h"}, Expires: now.Add(time.Hour)}
	for _, c := range []struct {
		name                     string
		tok                      *APIToken
		active, revoked, pending bool
	}{
		{"active", active, true, false, false},
		{"expired", expired, false, false, false},
		{"revoked", revoked, false, true, false},
		{"pending", pending, false, false, true},
	} {
		if c.tok.Active(now) != c.active || c.tok.Revoked() != c.revoked || c.tok.Pending() != c.pending {
			t.Errorf("the %s token: active %v, revoked %v, pending %v", c.name, c.tok.Active(now), c.tok.Revoked(), c.tok.Pending())
		}
	}

	if !slices.Equal(active.EffectiveScopes(), []string{"sign"}) || !active.HasScope("sign") || active.HasScope("tokens") {
		t.Error("a token without scopes, want the scope sign alone")
	}
	if all := (&APIToken{Scopes: []string{"*"}}); !all.HasScope("audit") || !all.HasScope("federate") {
		t.Error("a token of the scope *, want every scope")
	}
	if certs := (&APIToken{Scopes: []string{"certs"}}); certs.HasScope("sign") || !certs.HasScope("certs") {
		t.Error("a token of the scope certs, want certs alone")
	}
	if !Allows([]string{"server"}, "server") || Allows([]string{"server"}, "user") || !Allows([]string{"*"}, "user") || Allows(nil, "x") {
		t.Error("Allows gives the values and * wrong")
	}

	limited := &APIToken{Clients: []string{"10.0.0.0/8", "2001:db8::/32"}}
	for addr, want := range map[string]bool{"10.1.2.3": true, "192.168.1.1": false, "2001:db8::1": true, "2001:db9::1": false} {
		if got := limited.ClientAllowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("ClientAllowed(%s) = %v, want %v", addr, got, want)
		}
	}
	if !active.ClientAllowed(netip.MustParseAddr("192.168.1.1")) {
		t.Error("a token without clients refuses a client, want any allowed")
	}

	owner := &TokenOIDC{Issuer: "https://idp.example.com", Subject: "alice", User: "alice@example.com"}
	if active.OwnedBy(owner) {
		t.Error("a token without an OIDC user is owned by one")
	}
	made := &APIToken{OIDC: &TokenOIDC{Issuer: owner.Issuer, Subject: owner.Subject, User: "renamed"}}
	if !made.OwnedBy(owner) || made.OwnedBy(&TokenOIDC{Issuer: owner.Issuer, Subject: "bob"}) ||
		made.OwnedBy(&TokenOIDC{Issuer: "https://other.example.com", Subject: "alice"}) {
		t.Error("OwnedBy compares the issuer and the subject wrong")
	}

	claims := &JWTClaims{ID: "id", Subject: "deploy", Scope: "sign tokens", IssuedAt: 1000, ExpiresAt: 4600}
	if tok := claims.Token(); tok.ID != "id" || !slices.Equal(tok.Scopes, []string{"sign", "tokens"}) ||
		tok.Issued.Unix() != 1000 || tok.Expires.Unix() != 4600 {
		t.Errorf("Token of the claims %+v", tok)
	}
}

func TestLoadTokens(t *testing.T) {
	dir := t.TempDir()
	db, err := LoadTokens(dir)
	if err != nil || db.Tokens == nil || len(db.Tokens) != 0 {
		t.Fatalf("LoadTokens without %s: %+v, %v, want an empty database", TokensFile, db, err)
	}
	path := filepath.Join(dir, TokensFile)
	if err := os.WriteFile(path, []byte(`{"tokens": null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if db, err := LoadTokens(dir); err != nil || db.Tokens == nil {
		t.Fatalf("LoadTokens of null tokens: %+v, %v, want an empty map", db, err)
	}
	if err := os.WriteFile(path, []byte(`{"tokens": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("LoadTokens of bad JSON: %v, want an error naming the file", err)
	}

	issued := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	db.Tokens["deploy"] = &APIToken{ID: "id", Scopes: []string{"sign"}, Domains: []string{"example.com"}, Issued: issued,
		Expires: issued.Add(time.Hour), Federate: &TokenFederate{Type: "google", Audience: "aud"}}
	if err := db.Save(dir); err != nil {
		t.Fatal(err)
	}
	if FileExists(path + ".tmp") {
		t.Errorf("Save left %s.tmp", TokensFile)
	}
	if info, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("%s after Save: %v, want mode 0600", TokensFile, err)
	}
	if tok := loadToken(t, dir, "deploy"); tok.ID != "id" || !tok.Issued.Equal(issued) || tok.Federate == nil ||
		tok.Federate.Audience != "aud" {
		t.Errorf("the token saved and read: %+v", tok)
	}
}

func TestLockTokens(t *testing.T) {
	root := newRoot(t, "ec")
	wait := TokensLockWait
	TokensLockWait = 200 * time.Millisecond
	t.Cleanup(func() { TokensLockWait = wait })
	lockPath := filepath.Join(root.dir, TokensFile+".lock")

	unlock, err := LockTokens(root.dir)
	if err != nil {
		t.Fatalf("LockTokens: %v", err)
	}
	if b, err := os.ReadFile(lockPath); err != nil || string(b) != fmt.Sprintf("%d\n", os.Getpid()) {
		t.Fatalf("%s: %q, %v, want the PID of the locker", lockPath, b, err)
	}

	// A held lock makes the others wait and then fail, naming the locker.
	locked := fmt.Sprintf("locked by process %d", os.Getpid())
	if _, err := LockTokens(root.dir); err == nil || !strings.Contains(err.Error(), locked) || !strings.Contains(err.Error(), lockPath) {
		t.Fatalf("LockTokens while locked: %v, want a lock error naming this process and the lock file", err)
	}
	if _, err := MakeToken(root.dir, "deploy", time.Hour, nil, nil, []string{"example.com"}, nil, nil); err == nil ||
		!strings.Contains(err.Error(), locked) {
		t.Fatalf("MakeToken while locked: %v, want a lock error", err)
	}
	unlock()
	if FileExists(lockPath) {
		t.Fatalf("%s left after unlocking", lockPath)
	}
	if _, err := MakeToken(root.dir, "deploy", time.Hour, nil, nil, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("MakeToken after unlocking: %v", err)
	}

	// A lock released while waiting is taken.
	TokensLockWait = 5 * time.Second
	unlock, err = LockTokens(root.dir)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		unlock()
	}()
	again, err := LockTokens(root.dir)
	if err != nil {
		t.Fatalf("LockTokens of a lock released while waiting: %v", err)
	}
	again()
	if _, err := LockFile(filepath.Join(root.dir, "missing", TokensFile)); err == nil || strings.Contains(err.Error(), "locked by") {
		t.Errorf("LockFile in a missing directory: %v, want the error of creating the lock", err)
	}
}

func TestSignToken(t *testing.T) {
	for _, keyType := range []string{"rsa", "ec"} {
		root := newRoot(t, keyType)
		issued := time.Now().UTC().Truncate(time.Second)
		tok := &APIToken{ID: "token-id", Scopes: []string{"sign", "certs"}, Issued: issued, Expires: issued.Add(time.Hour)}
		jwt, err := SignToken(root.key, "deploy", tok)
		if err != nil {
			t.Fatalf("SignToken with an %s key: %v", keyType, err)
		}
		jwks, err := CAJWKS(root.dir)
		if err != nil {
			t.Fatal(err)
		}
		header, claims := verifyJWT(t, jwt, jwks)
		if want := map[string]string{"rsa": "RS256", "ec": "ES256"}[keyType]; header["alg"] != want ||
			JWTAlg(root.key.Public()) != want {
			t.Errorf("the algorithm of an %s key: %v, want %s", keyType, header["alg"], want)
		}
		if claims["jti"] != "token-id" || claims["sub"] != "deploy" || claims["scope"] != "sign certs" ||
			claims["iat"] != float64(issued.Unix()) || claims["exp"] != float64(issued.Add(time.Hour).Unix()) {
			t.Errorf("claims %v, want those of the token", claims)
		}
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignToken(edKey, "deploy", &APIToken{ID: "id"}); err == nil {
		t.Error("SignToken with an Ed25519 key succeeded, want an error")
	}
}

func TestPrepareTokenFederate(t *testing.T) {
	root := newRoot(t, "ec")
	writeConfig(t, root.dir, `{"federation": {"issuer": "https://ca.example.com"}}`)
	azure := &TokenFederate{Type: "azure", Claims: map[string]string{"deploy_env": "prod"}}
	if _, _, err := PrepareToken(root.dir, "wif", azure, time.Hour, []string{"tokens"}, nil, nil, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "need the scope federate") {
		t.Errorf("PrepareToken of a token type without the scope federate: %v, want an error", err)
	}
	tok, key, err := PrepareToken(root.dir, "wif", azure, time.Hour, []string{"federate"}, nil, nil, nil, nil)
	if err != nil || tok.Federate != azure || !slices.Equal(tok.Scopes, []string{"federate"}) || !samePublic(key, root.key) {
		t.Fatalf("PrepareToken of a token type: %+v, %v, want the token and the CA key", tok, err)
	}
	if db, err := LoadTokens(root.dir); err != nil || len(db.Tokens) != 0 {
		t.Errorf("PrepareToken saved the token: %v", err)
	}
	for _, c := range []struct {
		fed  *TokenFederate
		want string
	}{
		{&TokenFederate{Type: "nosuch"}, "unknown token type 'nosuch'"},
		{&TokenFederate{Type: "google"}, "needs an audience"},
		{&TokenFederate{Type: "azure", Claims: map[string]string{"sub": "x"}}, "reserved"},
	} {
		if _, _, err := PrepareToken(root.dir, "wif", c.fed, time.Hour, []string{"federate"}, nil, nil, nil, nil); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("PrepareToken of %+v: %v, want an error with %q", c.fed, err, c.want)
		}
	}
	if _, _, err := PrepareToken(root.dir, "page", nil, time.Hour, []string{"federate"}, nil, nil, nil, nil); err != nil {
		t.Errorf("PrepareToken of the scope federate without a token type: %v", err)
	}
	if _, err := AddToken(root.dir, "wif", azure, time.Hour, []string{"federate"}, nil, nil, nil, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if fed := loadToken(t, root.dir, "wif").Federate; fed == nil || fed.Type != "azure" || fed.Claims["deploy_env"] != "prod" {
		t.Errorf("the token type of the token saved: %+v", fed)
	}
}
