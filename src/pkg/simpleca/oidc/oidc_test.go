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

package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

func TestOIDCKeys(t *testing.T) {
	rootDir := t.TempDir()

	// A test provider, counting the JWKS fetches.
	b64 := base64.RawURLEncoding.EncodeToString
	newKey := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	jwk := func(kid string, k *rsa.PrivateKey) map[string]string {
		return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": "AQAB"}
	}
	key1, key2 := newKey(), newKey()
	var mu sync.Mutex
	keys, fetches := []map[string]string{jwk("k1", key1)}, 0
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/authorize",
				"token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/jwks"})
		case "/jwks":
			mu.Lock()
			fetches++
			json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			mu.Unlock()
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	// idToken returns a valid ID token with claims overridden, signed by key as kid.
	idToken := func(kid string, key *rsa.PrivateKey, claims map[string]any) string {
		t.Helper()
		now := time.Now().Unix()
		c := map[string]any{"iss": idp.URL, "aud": "simple-ca", "sub": "subject-" + fmt.Sprint(claims["preferred_username"]),
			"iat": now, "exp": now + 300, "nonce": simpleca.RandomID()}
		maps.Copy(c, claims)
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
		payload, _ := json.Marshal(c)
		signed := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + b64(sig)
	}
	user := func(name string, more map[string]any) map[string]any {
		c := map[string]any{"preferred_username": name}
		maps.Copy(c, more)
		return c
	}

	cfg := &simpleca.Config{Path: simpleca.ConfigFile, OIDC: simpleca.OIDCConfig{Provider: "entra", Issuer: idp.URL, ClientID: "simple-ca"}}

	// A new JWKS key is fetched after keysRefetch.
	mu.Lock()
	keys = append(keys, jwk("k2", key2))
	before := fetches
	mu.Unlock()
	client := NewClient(rootDir)
	oc, _, _ := Resolved(cfg.OIDC, cfg.Path)
	if _, err := client.checkIDToken(oc, idToken("k1", key1, user("alice@example.com", nil))); err != nil {
		t.Fatalf("checkIDToken: %v", err)
	}
	client.keys = map[string]crypto.PublicKey{"k1": &key1.PublicKey}
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err == nil {
		t.Error("checkIDToken with a key of the JWKS not fetched again yet succeeded, want an error")
	}
	client.keysAt = time.Now().Add(-keysRefetch)
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err != nil {
		t.Errorf("checkIDToken with the new key k2: %v", err)
	}
	mu.Lock()
	if fetches != before+2 {
		t.Errorf("JWKS fetches: %d, want %d", fetches-before, 2)
	}
	mu.Unlock()
}

func TestDiscoverRefusesEndpoints(t *testing.T) {
	for name, endpoints := range map[string][3]string{
		"jwks_uri not a URL":         {"/authorize", "/token", "jwks.example.com"},
		"token_endpoint with a user": {"/authorize", "https://u:p@idp.example.com/token", "/jwks"},
		"authorization_endpoint ftp": {"ftp://idp.example.com/authorize", "/token", "/jwks"},
		"jwks_uri with a line end":   {"/authorize", "/token", "https://idp.example.com/jwks\nforged"},
	} {
		t.Run(name, func(t *testing.T) {
			var idp *httptest.Server
			idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				abs := func(e string) string {
					if strings.HasPrefix(e, "/") {
						return idp.URL + e
					}
					return e
				}
				json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": abs(endpoints[0]),
					"token_endpoint": abs(endpoints[1]), "jwks_uri": abs(endpoints[2])})
			}))
			defer idp.Close()
			_, err := NewClient(t.TempDir()).discover(simpleca.OIDCConfig{Issuer: idp.URL, ClientID: "simple-ca"})
			want := fmt.Sprintf("the discovery document of %q: ", idp.URL)
			if err == nil || !strings.HasPrefix(err.Error(), want) || strings.Contains(err.Error(), "\n") {
				t.Errorf("discover: %v, want %s and the endpoint quoted", err, want)
			}
		})
	}
}

func TestOIDCCheck(t *testing.T) {
	rootDir := t.TempDir()
	if err := cert.MakeCA(rootDir, "Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(rootDir, "Clients CA", 0, "clients", "", "rsa"); err != nil {
		t.Fatalf("makeCA clients: %v", err)
	}

	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(simpleca.ConfigFile, `{"oidc": {"provider": "entra", "issuer": "https://idp.example.com", "client_id": "simple-ca"}}`)
	write(UsersFile, `{
  "profiles": [
    {"name": "ca-admin", "token": {"valid": "8h", "scopes": ["tokens", "certs"]}},
    {"name": "web-signer", "ca": "clients", "token": {"scopes": ["sign"], "domains": ["example.com"]}},
    {"name": "viewer", "ca": "clients", "token": {"scopes": ["certs"], "networks": ["10.0.0.0/8"]}}
  ],
  "rules": [
    {"users": ["alice@example.com", "henry@example.com"], "profile": "ca-admin"},
    {"groups": ["web-team"], "profile": "web-signer"}
  ]
}`)
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(rootDir, cfg); err != nil {
		t.Fatalf("checkOIDC: %v", err)
	}

	// Invalid settings and profiles.
	for name, c := range map[string]string{
		"an unknown provider": `{"oidc": {"provider": "other", "issuer": "https://idp.example.com", "client_id": "x"}}`,
		"no client ID":        `{"oidc": {"issuer": "https://idp.example.com"}}`,
		"an issuer not a URL": `{"oidc": {"issuer": "idp.example.com", "client_id": "x"}}`,
	} {
		cfg := &simpleca.Config{Path: simpleca.ConfigFile}
		if err := json.Unmarshal([]byte(c), cfg); err != nil {
			t.Fatal(err)
		}
		if err := Check(rootDir, cfg); err == nil {
			t.Errorf("checkOIDC with %s succeeded, want an error", name)
		}
	}
	for name, users := range map[string]string{
		"an unknown CA":       `{"profiles": [{"name": "a", "ca": "nowhere", "token": {"scopes": ["certs"]}}]}`,
		"a profile name":      `{"profiles": [{"name": "CA Admin", "token": {"scopes": ["certs"]}}]}`,
		"a profile twice":     `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}, {"name": "a", "token": {"scopes": ["certs"]}}]}`,
		"keep_expired":        `{"profiles": [{"name": "a", "token": {"scopes": ["certs"], "keep_expired": "1h"}}]}`,
		"sign without names":  `{"profiles": [{"name": "a", "token": {"scopes": ["sign"]}}]}`,
		"an unknown profile":  `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}], "rules": [{"users": ["x"], "profile": "b"}]}`,
		"a rule without whom": `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}], "rules": [{"profile": "a"}]}`,
		"an unknown key":      `{"profiles": [], "groups": []}`,
	} {
		write(UsersFile, users)
		if err := Check(rootDir, cfg); err == nil {
			t.Errorf("checkOIDC with %s in %s succeeded, want an error", name, UsersFile)
		}
	}
}
