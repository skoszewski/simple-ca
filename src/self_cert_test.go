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
	"slices"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/oidc"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
	"software.sslmate.com/src/go-pkcs12"
)

func TestSelfCert(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := cert.MakeCA(rootDir, "Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(rootDir, "Clients CA", 0, "clients", "", "ec"); err != nil {
		t.Fatalf("makeCA clients: %v", err)
	}

	// A test provider.
	b64 := base64.RawURLEncoding.EncodeToString
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/authorize",
				"token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/jwks", "device_authorization_endpoint": idp.URL + "/device"})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
				{"kty": "RSA", "kid": "k1", "use": "sig", "n": b64(key.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	// idToken returns a valid ID token of the client of the pages for the user name, with claims
	// overridden; a nil claim is left out.
	idToken := func(name string, claims map[string]any) string {
		t.Helper()
		now := time.Now().Unix()
		c := map[string]any{"iss": idp.URL, "aud": "simple-ca", "sub": "subject-" + name, "preferred_username": name,
			"email": name + "@example.com", "name": "User " + name, "iat": now, "exp": now + 300, "nonce": simpleca.RandomID(), "jti": simpleca.RandomID()}
		maps.Copy(c, claims)
		maps.DeleteFunc(c, func(_ string, v any) bool { return v == nil })
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
		payload, _ := json.Marshal(c)
		signed := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + b64(sig)
	}
	// cli is the ID token of the client of request-cert from the device authorization grant,
	// without a nonce.
	cli := map[string]any{"aud": "simple-ca-cli", "azp": "simple-ca-cli", "nonce": nil}

	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	request := func(method, target, bearer string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			reader = bytes.NewReader(j)
		}
		req, err := http.NewRequest(method, server.URL+target, reader)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
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
	signIn := func(raw string, more map[string]any) (int, map[string]any) {
		t.Helper()
		body := map[string]any{"id_token": raw}
		maps.Copy(body, more)
		return request("POST", "/api/oidc-token", "", body)
	}
	// tokenOf signs the user in and returns the token of the answer.
	tokenOf := func(raw string) (string, map[string]any) {
		t.Helper()
		status, answer := signIn(raw, nil)
		if status != http.StatusOK || answer["token"] == nil {
			t.Fatalf("sign-in: %d %v, want a token", status, answer)
		}
		return fmt.Sprint(answer["token"]), answer
	}
	selfCert := func(bearer string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return request("POST", "/api/self-cert", bearer, body)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The CSR names another subject and other SANs, which are not used.
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "mallory"},
		DNSNames: []string{"evil.example.org"}, EmailAddresses: []string{"mallory@evil.example.org"}}, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	csr := map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	parse := func(answer map[string]any) *x509.Certificate {
		t.Helper()
		block, _ := pem.Decode([]byte(fmt.Sprint(answer["certificate"])))
		if block == nil {
			t.Fatalf("the answer holds no certificate: %v", answer)
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return crt
	}
	scopesOf := func(answer map[string]any) string { return fmt.Sprint(answer["scopes"]) }

	config := `{"oidc": {"provider": "keycloak", "issuer": "` + idp.URL + `", "client_id": "simple-ca",
  "cli_client_id": "simple-ca-cli"},
  "types": {"person": {"names": "user", "key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "emailProtection"]}}}`
	write(simpleca.ConfigFile, config)
	users := `{
  "profiles": [
    {"name": "staff", "certificate": {"ca": "clients", "types": ["user"], "days": 30, "email_domains": ["example.com"]}},
    {"name": "admin", "token": {"scopes": ["certs"]}},
    {"name": "both", "token": {"scopes": ["certs"]}, "certificate": {"ca": "clients", "types": ["user"]}},
    {"name": "choice", "certificate": {"ca": "", "types": ["person", "user"]}},
    {"name": "nocert", "token": {"scopes": ["certs"]}, "certificate": {"types": ["user"]}},
    {"name": "star", "token": {"scopes": ["*"], "domains": ["example.com"]}, "certificate": {"ca": "", "types": ["user"]}}
  ],
  "rules": [
    {"users": ["bob", "erin", "frank"], "profile": "staff"},
    {"users": ["alice"], "profile": "admin"},
    {"users": ["henry"], "profile": "both"},
    {"users": ["dave"], "profile": "choice"},
    {"users": ["nina"], "profile": "nocert"},
    {"users": ["sam"], "profile": "star"}
  ]
}`
	write(oidc.UsersFile, users)
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := oidc.Check(rootDir, cfg); err != nil {
		t.Fatalf("checkOIDC: %v", err)
	}

	// A profile of a certificate alone gives a token of the scope self-cert alone, which records
	// the profile and the subject of the certificate.
	bob, answer := tokenOf(idToken("bob", nil))
	if scopesOf(answer) != "[self-cert]" || answer["ca"] != "" || answer["name"] != "bob" {
		t.Errorf("sign-in of bob: %v, want the token bob of the scope self-cert", answer)
	}
	db, err := tokens.LoadTokens(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if o := db.Tokens["bob"].OIDC; o == nil || o.Profile != "staff" || o.Email != "bob@example.com" || o.Name != "User bob" {
		t.Errorf("the OIDC entry of bob: %+v, want the profile, the email address and the name", o)
	}

	// The token gives the certificate of the user it was made for, of the CA of certificate.ca.
	status, answer := selfCert(bob, csr)
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "bob" || answer["type"] != "user" {
		t.Fatalf("certificate of bob: %d %v, want one of the CA clients", status, answer)
	}
	crt := parse(answer)
	if cert.NameString(crt.Subject) != "/CN=User bob/emailAddress=bob@example.com" ||
		!slices.Equal(crt.EmailAddresses, []string{"bob@example.com"}) || len(crt.DNSNames) != 0 ||
		!crt.PublicKey.(*ecdsa.PublicKey).Equal(csrKey.Public()) || crt.NotAfter.Sub(crt.NotBefore) != 30*24*time.Hour ||
		crt.Issuer.CommonName != "Clients CA" {
		t.Errorf("certificate of bob: %s %v, want /CN=User bob/emailAddress=bob@example.com of 30 days by Clients CA",
			cert.NameString(crt.Subject), crt.EmailAddresses)
	}
	serial := cert.SerialHex(crt.SerialNumber)
	if !simpleca.FileExists(filepath.Join(rootDir, "clients", "bob-"+serial+"_cert.pem")) {
		t.Errorf("the certificate of bob is not stored as bob-%s_cert.pem", serial)
	}
	if db, _ := tokens.LoadTokens(rootDir); !slices.Contains(db.Tokens["bob"].Certs, serial) {
		t.Errorf("the token bob does not keep the certificate %s", serial)
	}

	// A generated key comes in the PKCS#12 bundle alone, and the same token issues again.
	status, answer = selfCert(bob, map[string]any{"generate": true, "key_type": "rsa"})
	bundle, _ := base64.StdEncoding.DecodeString(fmt.Sprint(answer["pfx"]))
	pfxKey, pfxCert, chain, err := pkcs12.DecodeChain(bundle, fmt.Sprint(answer["password"]))
	if status != http.StatusOK || err != nil || !pfxCert.PublicKey.(*rsa.PublicKey).Equal(pfxKey.(*rsa.PrivateKey).Public()) ||
		len(chain) != 2 {
		t.Errorf("generated certificate of bob: %d %v, %v, want a PKCS#12 bundle with the chain", status, answer["error"], err)
	}

	// The links of the index page name the page for a token of the scope self-cert.
	if status, answer := request("GET", "/api/links", bob, nil); status != http.StatusOK || answer["self_cert"] != true ||
		!bytes.Contains([]byte(fmt.Sprint(answer["links"])), []byte("/self-cert")) {
		t.Errorf("GET /api/links with the token of bob: %d %v, want the page of the certificate", status, answer)
	}

	// A profile with both gives a token of its scopes and self-cert; its certificate is of
	// certificate.ca.
	henry, answer := tokenOf(idToken("henry", nil))
	if scopesOf(answer) != "[certs self-cert]" {
		t.Errorf("sign-in of henry: %v, want the scopes certs and self-cert", answer)
	}
	if status, answer := selfCert(henry, csr); status != http.StatusOK || parse(answer).Issuer.CommonName != "Clients CA" {
		t.Errorf("certificate of henry: %d %v, want one of Clients CA", status, answer)
	}
	// The scope * stands for the other scopes, beside self-cert.
	if _, answer := tokenOf(idToken("sam", nil)); scopesOf(answer) != "[sign tokens certs audit secrets federate self-cert]" {
		t.Errorf("sign-in of sam: %v, want every scope with self-cert", answer)
	}

	// A profile of several types asks for one, and the token then gets the type chosen.
	dave, _ := tokenOf(idToken("dave", nil))
	if status, answer := selfCert(dave, csr); status != http.StatusConflict || fmt.Sprint(answer["types"]) != "[person user]" {
		t.Errorf("certificate of dave without a type: %d %v, want 409 with the types", status, answer)
	}
	body := maps.Clone(csr)
	body["type"] = "person"
	status, answer = selfCert(dave, body)
	if status != http.StatusOK || answer["type"] != "person" ||
		!slices.Equal(parse(answer).ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}) {
		t.Errorf("certificate of dave of the type person: %d %v", status, answer)
	}

	// The client of request-cert gets the token NAME-cli of the scope self-cert alone, for ten
	// minutes, replaced at each sign-in, from an ID token without a nonce used once.
	device := idToken("erin", cli)
	status, answer = signIn(device, nil)
	erinCLI := fmt.Sprint(answer["token"])
	if status != http.StatusOK || answer["name"] != "erin-cli" || scopesOf(answer) != "[self-cert]" {
		t.Errorf("sign-in of request-cert: %d %v, want erin-cli of the scope self-cert", status, answer)
	}
	if db, _ := tokens.LoadTokens(rootDir); db.Tokens["erin-cli"] == nil ||
		db.Tokens["erin-cli"].Expires.Sub(db.Tokens["erin-cli"].Issued) != 10*time.Minute {
		t.Errorf("the token erin-cli: %+v, want one of ten minutes", db.Tokens["erin-cli"])
	}
	if status, _ := signIn(device, nil); status != http.StatusUnauthorized {
		t.Errorf("an ID token of request-cert used again: %d, want 401", status)
	}
	if status, answer := selfCert(erinCLI, csr); status != http.StatusOK || answer["name"] != "erin" {
		t.Errorf("certificate of erin by request-cert: %d %v, want 200", status, answer)
	}
	if status, _ := signIn(idToken("erin", cli), nil); status != http.StatusOK {
		t.Errorf("a second sign-in of request-cert: %d, want 200", status)
	}
	if status, _ := selfCert(erinCLI, csr); status != http.StatusUnauthorized {
		t.Errorf("a token of request-cert replaced: %d, want 401", status)
	}
	for name, c := range map[string]struct {
		raw    string
		more   map[string]any
		status int
	}{
		"request-cert for a profile without a certificate": {idToken("alice", cli), nil, http.StatusForbidden},
		"request-cert with replace":                        {idToken("erin", cli), map[string]any{"replace": true}, http.StatusBadRequest},
		"the pages without a nonce":                        {idToken("bob", map[string]any{"nonce": nil}), nil, http.StatusUnauthorized},
	} {
		if status, answer := signIn(c.raw, c.more); status != c.status {
			t.Errorf("%s: %d %v, want %d", name, status, answer, c.status)
		}
	}

	// Refused requests of a certificate.
	alice, _ := tokenOf(idToken("alice", nil))
	nina, answer := tokenOf(idToken("nina", nil))
	if scopesOf(answer) != "[certs]" {
		t.Errorf("sign-in of nina, whose certificate has no ca: %v, want the scope certs alone", answer)
	}
	plain, err := tokens.MakeToken(rootDir, "plain", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	unverified, _ := tokenOf(idToken("erin", map[string]any{"email_verified": false}))
	elsewhere, _ := tokenOf(idToken("frank", map[string]any{"email": "frank@example.org"}))
	withIDToken := maps.Clone(csr)
	withIDToken["id_token"] = idToken("bob", nil)
	for name, c := range map[string]struct {
		bearer string
		body   map[string]any
		status int
	}{
		"no token":                    {"", csr, http.StatusUnauthorized},
		"a token without self-cert":   {alice, csr, http.StatusForbidden},
		"a certificate without ca":    {nina, csr, http.StatusForbidden},
		"a token of token create":     {plain, csr, http.StatusForbidden},
		"an unverified email address": {unverified, csr, http.StatusForbidden},
		"an email of another domain":  {elsewhere, csr, http.StatusForbidden},
		"an ID token in the body":     {bob, withIDToken, http.StatusBadRequest},
		"a CSR and generate":          {bob, map[string]any{"csr": csr["csr"], "generate": true}, http.StatusBadRequest},
		"neither a CSR nor generate":  {bob, map[string]any{}, http.StatusBadRequest},
		"a key type without generate": {bob, map[string]any{"csr": csr["csr"], "key_type": "ec"}, http.StatusBadRequest},
		"a CSR that does not parse":   {bob, map[string]any{"csr": "x"}, http.StatusBadRequest},
		"a type the profile lacks":    {bob, map[string]any{"csr": csr["csr"], "type": "server"}, http.StatusForbidden},
	} {
		if status, answer := selfCert(c.bearer, c.body); status != c.status {
			t.Errorf("%s: %d %v, want %d", name, status, answer, c.status)
		}
	}
	if _, err := tokens.MakeToken(rootDir, "forged", time.Hour, []string{"self-cert"}, nil, nil, nil, nil); err == nil {
		t.Error("token create with the scope self-cert succeeded, want an error")
	}
	if status, answer := request("GET", "/api/links", alice, nil); answer["self_cert"] != nil ||
		bytes.Contains([]byte(fmt.Sprint(answer["links"])), []byte("/self-cert")) {
		t.Errorf("GET /api/links with a token without self-cert: %d %v, want no page of the certificate", status, answer)
	}

	// A revoked token, and a token whose profile no longer gives a certificate, are refused.
	if err := revokeToken(rootDir, "henry"); err != nil {
		t.Fatal(err)
	}
	if status, _ := selfCert(henry, csr); status != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d, want 401", status)
	}
	write(oidc.UsersFile, `{"profiles": [{"name": "staff", "certificate": {"types": ["user"]}}],
  "rules": [{"users": ["bob"], "profile": "staff"}]}`)
	if status, _ := selfCert(bob, csr); status != http.StatusForbidden {
		t.Errorf("a token whose profile no longer gives a certificate: %d, want 403", status)
	}

	// Without cli_client_id, an ID token of that client is refused.
	write(simpleca.ConfigFile, `{"oidc": {"provider": "keycloak", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	if status, _ := signIn(idToken("bob", cli), nil); status != http.StatusUnauthorized {
		t.Errorf("an ID token of request-cert without cli_client_id: %d, want 401", status)
	}

	// The page of the certificate.
	resp, err := http.Get(server.URL + "/self-cert")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("/assets/webui/self-cert.js")) ||
		bytes.Contains(page, []byte("oidc.js")) {
		t.Errorf("GET /self-cert: %d, want the page without a sign-in of its own", resp.StatusCode)
	}
}
