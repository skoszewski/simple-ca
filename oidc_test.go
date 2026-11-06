package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOIDC(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(rootDir, "Clients CA", 3650, "clients", ""); err != nil {
		t.Fatalf("makeCA clients: %v", err)
	}

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
	key1, key2, stranger := newKey(), newKey(), newKey()
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
			"iat": now, "exp": now + 300, "nonce": randomID()}
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

	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	do := func(method, target, token string, body any) (int, map[string]any) {
		t.Helper()
		j, _ := json.Marshal(body)
		req, err := http.NewRequest(method, server.URL+target, bytes.NewReader(j))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	signIn := func(raw string) (int, map[string]any) {
		t.Helper()
		return do("POST", "/api/oidc-token", "", map[string]string{"id_token": raw})
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Without oidc in simple-ca.json, the sign-in is off.
	if status, _ := do("GET", "/api/oidc", "", nil); status != http.StatusNotFound {
		t.Errorf("GET /api/oidc without oidc: %d, want 404", status)
	}
	if status, _ := signIn(idToken("k1", key1, user("alice@example.com", nil))); status != http.StatusNotFound {
		t.Errorf("POST /api/oidc-token without oidc: %d, want 404", status)
	}

	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	write(oidcUsersFile, `{
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
	cfg, err := loadConfig(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOIDC(rootDir, cfg); err != nil {
		t.Fatalf("checkOIDC: %v", err)
	}
	status, answer := do("GET", "/api/oidc", "", nil)
	if status != http.StatusOK || answer["label"] != "Entra ID" || answer["client_id"] != "simple-ca" ||
		answer["authorization_endpoint"] != idp.URL+"/authorize" || answer["token_endpoint"] != idp.URL+"/token" ||
		answer["redirect_path"] != "/oidc-callback" || fmt.Sprint(answer["scopes"]) != "[openid profile email]" {
		t.Errorf("GET /api/oidc: %d %v, want the settings of the Entra ID sign-in", status, answer)
	}

	// A user of a rule gets the token of its profile, and the ID token works once.
	alice := idToken("k1", key1, user("alice@example.com", nil))
	status, answer = signIn(alice)
	if status != http.StatusOK || answer["ca"] != "" || answer["name"] != "alice-example-com" ||
		fmt.Sprint(answer["scopes"]) != "[tokens certs]" {
		t.Fatalf("sign-in of alice: %d %v, want the token alice-example-com of the root CA", status, answer)
	}
	first := fmt.Sprint(answer["token"])
	status, answer = do("GET", "/tokens/api/cas", first, nil)
	if user, _ := answer["user_token"].(map[string]any); status != http.StatusOK || answer["user"] != "alice-example-com" ||
		fmt.Sprint(user["oidc"]) != fmt.Sprintf("map[issuer:%s subject:subject-alice@example.com user:alice@example.com]", idp.URL) {
		t.Errorf("GET /tokens/api/cas with the token of alice: %d %v, want alice-example-com of OIDC user alice", status, answer)
	}
	if status, _ := signIn(alice); status != http.StatusUnauthorized {
		t.Errorf("a used ID token: %d, want 401", status)
	}

	// An active token is reported, then replaced or reused.
	again := idToken("k1", key1, user("alice@example.com", nil))
	status, answer = signIn(again)
	if active, _ := answer["active"].(map[string]any); status != http.StatusConflict || active["name"] != "alice-example-com" ||
		active["ca"] != "" || active["expires"] == nil {
		t.Errorf("second sign-in of alice: %d %v, want 409 naming the active token", status, answer)
	}
	if status, _ := do("GET", "/tokens/api/cas", first, nil); status != http.StatusOK {
		t.Errorf("the token of the first sign-in after a sign-in not replacing it: %d, want 200", status)
	}
	signInWith := func(raw string, choice map[string]any) (int, map[string]any) {
		t.Helper()
		body := map[string]any{"id_token": raw}
		maps.Copy(body, choice)
		return do("POST", "/api/oidc-token", "", body)
	}
	if status, _ := signInWith(again, map[string]any{"reuse": true}); status != http.StatusBadRequest {
		t.Errorf("reusing the token without reuse_token: %d, want 400", status)
	}
	if status, _ := signInWith(again, map[string]any{"replace": true, "reuse": true}); status != http.StatusBadRequest {
		t.Errorf("replace and reuse together: %d, want 400", status)
	}
	status, answer = signInWith(again, map[string]any{"replace": true})
	if status != http.StatusOK {
		t.Fatalf("second sign-in of alice replacing the token: %d %v, want 200", status, answer)
	}
	second := fmt.Sprint(answer["token"])
	if status, _ := do("GET", "/tokens/api/cas", first, nil); status != http.StatusUnauthorized {
		t.Errorf("the replaced token of the first sign-in: %d, want 401", status)
	}
	if status, _ := signInWith(again, map[string]any{"replace": true}); status != http.StatusUnauthorized {
		t.Errorf("the ID token of the replacing sign-in again: %d, want 401", status)
	}
	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca", "reuse_token": true}}`)
	if status, answer := do("GET", "/api/oidc", "", nil); status != http.StatusOK || answer["reuse_token"] != true {
		t.Errorf("GET /api/oidc with reuse_token: %d %v, want reuse_token true", status, answer)
	}
	status, answer = signInWith(idToken("k1", key1, user("alice@example.com", nil)), map[string]any{"reuse": true})
	if status != http.StatusOK || answer["token"] != second {
		t.Errorf("third sign-in of alice reusing the token: %d %v, want the token of the second sign-in", status, answer)
	}
	if status, _ := do("GET", "/tokens/api/cas", second, nil); status != http.StatusOK {
		t.Errorf("the reused token: %d, want 200", status)
	}
	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)

	// A revoked token of the user is replaced without asking.
	if err := revokeToken(rootDir, "alice-example-com"); err != nil {
		t.Fatal(err)
	}
	if status, answer := signIn(idToken("k1", key1, user("alice@example.com", nil))); status != http.StatusOK {
		t.Errorf("sign-in of alice with the token revoked: %d %v, want 200", status, answer)
	}
	db, _ := loadTokens(rootDir)
	if tok := db.Tokens["alice-example-com"]; tok.OIDC == nil || tok.Expires.Sub(tok.Issued) != 8*time.Hour {
		t.Errorf("the token of alice: %+v, want the OIDC user, valid for 8h", tok)
	}
	if _, err := renewToken(rootDir, "alice-example-com", 0); err != nil {
		t.Fatal(err)
	}
	if db, _ := loadTokens(rootDir); db.Tokens["alice-example-com"].OIDC == nil {
		t.Error("the renewed token of alice lost its OIDC user")
	}

	// A group rule comes before the roles.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	signBody := map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		"type": "server", "name": "web", "days": 30}
	status, answer = signIn(idToken("k1", key1, user("bob@example.com", map[string]any{"groups": []string{"web-team"},
		"roles": []string{"ca-admin"}})))
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "bob-example-com" {
		t.Fatalf("sign-in of bob in web-team: %d %v, want the token of web-signer in clients", status, answer)
	}
	bob := fmt.Sprint(answer["token"])
	if status, answer := do("POST", "/clients/api/sign", bob, signBody); status != http.StatusOK {
		t.Errorf("POST /clients/api/sign with the token of bob: %d %v, want 200", status, answer)
	}
	if status, _ := do("POST", "/api/sign", bob, signBody); status != http.StatusUnauthorized {
		t.Errorf("POST /api/sign of the root CA with the token of bob: %d, want 401", status)
	}

	// Profiles by role, a disallowed client, and a user without a profile.
	status, answer = signIn(idToken("k1", key1, user("carol@example.com", map[string]any{"roles": []string{"viewer", "web-signer", "other"}})))
	if status != http.StatusOK || answer["ca"] != "clients" || fmt.Sprint(answer["scopes"]) != "[sign]" {
		t.Errorf("sign-in of carol with the roles viewer and web-signer: %d %v, want web-signer", status, answer)
	}
	if status, _ := signIn(idToken("k1", key1, user("dave@example.com", map[string]any{"roles": []string{"viewer"}}))); status != http.StatusForbidden {
		t.Errorf("sign-in of dave, viewer from outside its networks: %d, want 403", status)
	}
	if status, _ := signIn(idToken("k1", key1, user("erin@example.com", map[string]any{"roles": []string{"other"}}))); status != http.StatusForbidden {
		t.Errorf("sign-in of erin without a profile: %d, want 403", status)
	}
	if _, err := makeToken(rootDir, "henry-example-com", time.Hour, []string{"tokens"}, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if status, _ := signIn(idToken("k1", key1, user("henry@example.com", nil))); status != http.StatusConflict {
		t.Errorf("sign-in of henry, whose token name is taken: %d, want 409", status)
	}

	// Invalid ID tokens.
	now := time.Now().Unix()
	for name, raw := range map[string]string{
		"another key":    idToken("k1", stranger, user("alice@example.com", nil)),
		"an unknown key": idToken("k9", key1, user("alice@example.com", nil)),
		"another issuer": idToken("k1", key1, user("alice@example.com", map[string]any{"iss": "https://elsewhere.example.com"})),
		"another client": idToken("k1", key1, user("alice@example.com", map[string]any{"aud": []string{"other"}})),
		"another azp":    idToken("k1", key1, user("alice@example.com", map[string]any{"azp": "other"})),
		"expired":        idToken("k1", key1, user("alice@example.com", map[string]any{"exp": now - 1})),
		"future":         idToken("k1", key1, user("alice@example.com", map[string]any{"iat": now + 600})),
		"no nonce":       idToken("k1", key1, user("alice@example.com", map[string]any{"nonce": ""})),
		"not a JWT":      "not-a-jwt",
	} {
		if status, answer := signIn(raw); status != http.StatusUnauthorized {
			t.Errorf("an ID token of %s: %d %v, want 401", name, status, answer)
		}
	}

	// A new JWKS key is fetched after oidcKeysRefetch.
	mu.Lock()
	keys = append(keys, jwk("k2", key2))
	before := fetches
	mu.Unlock()
	client := newOIDCClient(rootDir)
	oc, _, _ := cfg.OIDC.resolved(cfg.path)
	if _, err := client.checkIDToken(oc, idToken("k1", key1, user("alice@example.com", nil))); err != nil {
		t.Fatalf("checkIDToken: %v", err)
	}
	client.keys = map[string]crypto.PublicKey{"k1": &key1.PublicKey}
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err == nil {
		t.Error("checkIDToken with a key of the JWKS not fetched again yet succeeded, want an error")
	}
	client.keysAt = time.Now().Add(-oidcKeysRefetch)
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err != nil {
		t.Errorf("checkIDToken with the new key k2: %v", err)
	}
	mu.Lock()
	if fetches != before+2 {
		t.Errorf("JWKS fetches: %d, want %d", fetches-before, 2)
	}
	mu.Unlock()

	// Keycloak realm and client roles.
	write(configFile, `{"oidc": {"provider": "keycloak", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	status, answer = signIn(idToken("k1", key1, user("frank", map[string]any{"realm_access": map[string]any{"roles": []string{"web-signer"}}})))
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "frank" {
		t.Errorf("sign-in of frank with the realm role web-signer: %d %v, want web-signer", status, answer)
	}
	status, answer = signIn(idToken("k1", key1, user("grace", map[string]any{"resource_access": map[string]any{
		"simple-ca": map[string]any{"roles": []string{"ca-admin"}}, "other": map[string]any{"roles": []string{"web-signer"}}}})))
	if status != http.StatusOK || answer["ca"] != "" {
		t.Errorf("sign-in of grace with the client role ca-admin: %d %v, want ca-admin", status, answer)
	}

	// Invalid settings and profiles.
	for name, c := range map[string]string{
		"an unknown provider": `{"oidc": {"provider": "other", "issuer": "https://idp.example.com", "client_id": "x"}}`,
		"no client ID":        `{"oidc": {"issuer": "https://idp.example.com"}}`,
		"an issuer not a URL": `{"oidc": {"issuer": "idp.example.com", "client_id": "x"}}`,
	} {
		cfg := &config{path: configFile}
		if err := json.Unmarshal([]byte(c), cfg); err != nil {
			t.Fatal(err)
		}
		if err := checkOIDC(rootDir, cfg); err == nil {
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
		write(oidcUsersFile, users)
		if err := checkOIDC(rootDir, cfg); err == nil {
			t.Errorf("checkOIDC with %s in %s succeeded, want an error", name, oidcUsersFile)
		}
	}
}
