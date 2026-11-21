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
	"software.sslmate.com/src/go-pkcs12"
)

func TestOIDCCert(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := cert.MakeCA(rootDir, "Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(rootDir, "Clients CA", 0, "clients", "", "ec"); err != nil {
		t.Fatalf("makeCA clients: %v", err)
	}

	// A test provider with a device authorization endpoint.
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
			"email": name + "@example.com", "name": "User " + name, "iat": now, "exp": now + 300, "nonce": simpleca.RandomID()}
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
	post := func(target string, body any) (int, map[string]any) {
		t.Helper()
		j, _ := json.Marshal(body)
		resp, err := http.Post(server.URL+target, "application/json", bytes.NewReader(j))
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
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
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
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

	write(simpleca.ConfigFile, `{"oidc": {"provider": "keycloak", "issuer": "`+idp.URL+`", "client_id": "simple-ca",
  "cli_client_id": "simple-ca-cli"},
  "types": {"person": {"names": "user", "key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "emailProtection"]}}}`)
	write(oidc.UsersFile, `{
  "profiles": [
    {"name": "staff", "certificate": {"ca": "clients", "types": ["user"], "days": 30, "email_domains": ["example.com"]}},
    {"name": "admin", "token": {"scopes": ["certs"]}},
    {"name": "both", "token": {"scopes": ["certs"]}, "certificate": {"ca": "clients", "types": ["user"]}},
    {"name": "choice", "certificate": {"ca": "", "types": ["person", "user"]}},
    {"name": "nocert", "token": {"scopes": ["certs"]}, "certificate": {"types": ["user"]}}
  ],
  "rules": [
    {"users": ["bob", "erin"], "profile": "staff"},
    {"users": ["alice"], "profile": "admin"},
    {"users": ["henry"], "profile": "both"},
    {"users": ["dave"], "profile": "choice"},
    {"users": ["nina"], "profile": "nocert"}
  ]
}`)
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := oidc.Check(rootDir, cfg); err != nil {
		t.Fatalf("checkOIDC: %v", err)
	}

	// The settings name the client of request-cert.
	resp, err := http.Get(server.URL + "/api/oidc")
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	json.NewDecoder(resp.Body).Decode(&settings)
	resp.Body.Close()
	if settings["cli_client_id"] != "simple-ca-cli" || fmt.Sprint(settings["cli_scopes"]) != "[openid profile email]" ||
		fmt.Sprint(settings["email_claim"]) != "[email]" || settings["device_authorization_endpoint"] != idp.URL+"/device" {
		t.Errorf("GET /api/oidc: %v, want the client of request-cert", settings)
	}

	// A CSR gives its public key alone; the subject is that of the claims.
	status, answer := post("/api/oidc-cert", map[string]any{"id_token": idToken("bob", nil), "csr": csr})
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "bob" {
		t.Fatalf("certificate of bob: %d %v, want a certificate of the CA clients", status, answer)
	}
	crt := parse(answer)
	if crt.Subject.CommonName != "User bob" || !slices.Equal(crt.EmailAddresses, []string{"bob@example.com"}) ||
		len(crt.DNSNames) != 0 || !crt.PublicKey.(*ecdsa.PublicKey).Equal(csrKey.Public()) ||
		!slices.Contains(crt.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || crt.NotAfter.Sub(crt.NotBefore) != 30*24*time.Hour {
		t.Errorf("certificate of bob: %s %v %v %v, want CN User bob, bob@example.com, 30 days, the key of the CSR",
			cert.NameString(crt.Subject), crt.EmailAddresses, crt.DNSNames, crt.NotAfter.Sub(crt.NotBefore))
	}
	if cert.NameString(crt.Subject) != "/CN=User bob/emailAddress=bob@example.com" {
		t.Errorf("subject of bob: %s", cert.NameString(crt.Subject))
	}
	serial := cert.SerialHex(crt.SerialNumber)
	if !simpleca.FileExists(filepath.Join(rootDir, "clients", "bob-"+serial+"_cert.pem")) {
		t.Errorf("the certificate of bob is not stored as bob-%s_cert.pem", serial)
	}

	// A generated key is returned in the PKCS#12 bundle alone.
	status, answer = post("/api/oidc-cert", map[string]any{"id_token": idToken("bob", nil), "generate": true, "key_type": "rsa"})
	if status != http.StatusOK || answer["file"] == nil || answer["password"] == nil {
		t.Fatalf("generated certificate of bob: %d %v", status, answer)
	}
	bundle, _ := base64.StdEncoding.DecodeString(fmt.Sprint(answer["pfx"]))
	pfxKey, pfxCert, chain, err := pkcs12.DecodeChain(bundle, fmt.Sprint(answer["password"]))
	if err != nil || !pfxCert.PublicKey.(*rsa.PublicKey).Equal(pfxKey.(*rsa.PrivateKey).Public()) || len(chain) != 2 ||
		cert.SerialHex(pfxCert.SerialNumber) != answer["serial"] {
		t.Errorf("PKCS#12 bundle of bob: %v, chain of %d, want the certificate, its key and the chain", err, len(chain))
	}
	if keys, _ := filepath.Glob(filepath.Join(rootDir, "clients", "bob*_key.pem")); len(keys) != 0 {
		t.Errorf("the generated key is stored: %v", keys)
	}

	// The client of request-cert, without a nonce, gets one certificate for an ID token, and no
	// token.
	device := idToken("erin", cli)
	if status, answer := post("/api/oidc-cert", map[string]any{"id_token": device, "csr": csr}); status != http.StatusOK {
		t.Errorf("certificate of erin with the CLI client: %d %v, want 200", status, answer)
	}
	if status, _ := post("/api/oidc-cert", map[string]any{"id_token": device, "csr": csr}); status != http.StatusUnauthorized {
		t.Errorf("a used ID token without a nonce: %d, want 401", status)
	}
	if status, _ := post("/api/oidc-token", map[string]any{"id_token": idToken("alice", cli)}); status != http.StatusUnauthorized {
		t.Errorf("a token for an ID token of the CLI client: %d, want 401", status)
	}

	// The client a role is given on: the roles of the client of request-cert are its own.
	carol := map[string]any{"resource_access": map[string]any{"simple-ca-cli": map[string]any{"roles": []string{"both"}}}}
	maps.Copy(carol, cli)
	if status, answer := post("/api/oidc-cert", map[string]any{"id_token": idToken("carol", carol), "csr": csr}); status != http.StatusOK {
		t.Errorf("certificate of carol by a role of the CLI client: %d %v, want 200", status, answer)
	}
	if status, _ := post("/api/oidc-cert", map[string]any{"id_token": idToken("carol", map[string]any{
		"resource_access": carol["resource_access"]}), "csr": csr}); status != http.StatusForbidden {
		t.Errorf("certificate of carol by a role of the CLI client in an ID token of the pages: %d, want 403", status)
	}

	// Refused requests.
	for name, c := range map[string]struct {
		body   map[string]any
		status int
	}{
		"a CSR and generate":                {map[string]any{"id_token": idToken("bob", nil), "csr": csr, "generate": true}, http.StatusBadRequest},
		"neither a CSR nor generate":        {map[string]any{"id_token": idToken("bob", nil)}, http.StatusBadRequest},
		"a key type without generate":       {map[string]any{"id_token": idToken("bob", nil), "csr": csr, "key_type": "ec"}, http.StatusBadRequest},
		"an unknown key type":               {map[string]any{"id_token": idToken("bob", nil), "generate": true, "key_type": "dsa"}, http.StatusBadRequest},
		"a CSR that does not parse":         {map[string]any{"id_token": idToken("bob", nil), "csr": "x"}, http.StatusBadRequest},
		"another authorized client":         {map[string]any{"id_token": idToken("bob", map[string]any{"azp": "other"}), "csr": csr}, http.StatusUnauthorized},
		"no email":                          {map[string]any{"id_token": idToken("bob", map[string]any{"email": nil}), "csr": csr}, http.StatusForbidden},
		"an unverified email":               {map[string]any{"id_token": idToken("bob", map[string]any{"email_verified": false}), "csr": csr}, http.StatusForbidden},
		"an email of another domain":        {map[string]any{"id_token": idToken("bob", map[string]any{"email": "bob@example.org"}), "csr": csr}, http.StatusForbidden},
		"a profile without a cert":          {map[string]any{"id_token": idToken("alice", nil), "csr": csr}, http.StatusForbidden},
		"a type the profile does not offer": {map[string]any{"id_token": idToken("dave", nil), "csr": csr, "type": "server"}, http.StatusForbidden},
		"a user without a profile":          {map[string]any{"id_token": idToken("zoe", nil), "csr": csr}, http.StatusForbidden},
		"an unknown key of the body":        {map[string]any{"id_token": idToken("bob", nil), "csr": csr, "days": 1}, http.StatusBadRequest},
	} {
		if status, answer := post("/api/oidc-cert", c.body); status != c.status {
			t.Errorf("%s: %d %v, want %d", name, status, answer, c.status)
		}
	}
	// A refused request leaves the ID token unused.
	bob := idToken("bob", nil)
	post("/api/oidc-cert", map[string]any{"id_token": bob, "csr": "x"})
	if status, _ := post("/api/oidc-cert", map[string]any{"id_token": bob, "csr": csr}); status != http.StatusOK {
		t.Errorf("an ID token after a refused request: %d, want 200", status)
	}

	// A profile with a certificate alone signs in without a token and leaves the ID token unused.
	bobSignIn := idToken("bob", nil)
	status, answer = post("/api/oidc-token", map[string]any{"id_token": bobSignIn})
	if status != http.StatusOK || answer["token"] != nil || answer["certificate"] != true || answer["user"] != "bob" {
		t.Errorf("sign-in of a profile with a certificate alone: %d %v, want 200 with certificate and no token", status, answer)
	}
	if status, answer := post("/api/oidc-cert", map[string]any{"id_token": bobSignIn, "csr": csr}); status != http.StatusOK {
		t.Errorf("a certificate after the sign-in of a profile with a certificate alone: %d %v, want 200", status, answer)
	}

	// A profile with both gives the token of its ca and the certificate of certificate.ca.
	status, answer = post("/api/oidc-token", map[string]any{"id_token": idToken("henry", nil)})
	if status != http.StatusOK || answer["ca"] != "" || answer["token"] == nil || answer["certificate"] != true {
		t.Errorf("a token of a profile with both: %d %v, want a token of the root CA and certificate", status, answer)
	}
	status, answer = post("/api/oidc-cert", map[string]any{"id_token": idToken("henry", nil), "csr": csr})
	if status != http.StatusOK || answer["ca"] != "clients" || parse(answer).Issuer.CommonName != "Clients CA" ||
		parse(answer).NotAfter.Sub(parse(answer).NotBefore) != 365*24*time.Hour {
		t.Errorf("a certificate of a profile with both: %d %v, want one of the CA clients for 365 days", status, answer)
	}

	// A certificate without ca gives no certificate, and the profile a token.
	status, answer = post("/api/oidc-token", map[string]any{"id_token": idToken("nina", nil)})
	if status != http.StatusOK || answer["token"] == nil || answer["certificate"] != false {
		t.Errorf("a token of a profile whose certificate has no ca: %d %v, want a token without certificate", status, answer)
	}
	if status, _ := post("/api/oidc-cert", map[string]any{"id_token": idToken("nina", nil), "csr": csr}); status != http.StatusForbidden {
		t.Errorf("a certificate of a profile whose certificate has no ca: %d, want 403", status)
	}

	// A profile of several types asks for one, and the same ID token then gets the type chosen.
	dave := idToken("dave", nil)
	status, answer = post("/api/oidc-cert", map[string]any{"id_token": dave, "csr": csr})
	if status != http.StatusConflict || fmt.Sprint(answer["types"]) != "[person user]" {
		t.Errorf("certificate of a profile of two types without a type: %d %v, want 409 with the types", status, answer)
	}
	status, answer = post("/api/oidc-cert", map[string]any{"id_token": dave, "csr": csr, "type": "person"})
	if status != http.StatusOK || answer["type"] != "person" ||
		!slices.Equal(parse(answer).ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}) {
		t.Errorf("certificate of the type person: %d %v, want one of clientAuth and emailProtection", status, answer)
	}

	// Without cli_client_id, an ID token of that client is refused.
	write(simpleca.ConfigFile, `{"oidc": {"provider": "keycloak", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	if status, _ := post("/api/oidc-cert", map[string]any{"id_token": idToken("bob", cli), "csr": csr}); status != http.StatusUnauthorized {
		t.Errorf("an ID token of the CLI client without cli_client_id: %d, want 401", status)
	}
	resp, err = http.Get(server.URL + "/api/oidc")
	if err != nil {
		t.Fatal(err)
	}
	settings = nil
	json.NewDecoder(resp.Body).Decode(&settings)
	resp.Body.Close()
	if _, ok := settings["cli_client_id"]; ok {
		t.Errorf("GET /api/oidc without cli_client_id: %v, want no client of request-cert", settings)
	}

	// The links of the index page name no certificate page; the sign-in adds it in the browser.
	resp, err = http.Get(server.URL + "/api/links")
	if err != nil {
		t.Fatal(err)
	}
	links, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(links, []byte("/oidc-certificate")) {
		t.Errorf("GET /api/links: %s, want no link to /oidc-certificate", links)
	}

	// The page of the certificate.
	resp, err = http.Get(server.URL + "/oidc-certificate")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Contains(page, []byte("/assets/webui/oidc-cert.js")) {
		t.Errorf("GET /oidc-certificate: %d, want the page", resp.StatusCode)
	}
}
