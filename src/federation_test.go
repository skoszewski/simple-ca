package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// tokServer serves the root CA in root with newServeMux, without the docs and the web pages, until
// the test ends.
func tokServer(t *testing.T, root string) *httptest.Server {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	srv := httptest.NewServer(newServeMux(root, false, false))
	t.Cleanup(srv.Close)
	return srv
}

// tokDo sends a request of method to url with the bearer token, empty for none, the content type
// and the body, and returns the status and the body of the answer.
func tokDo(t *testing.T, method, url, bearer, contentType, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// tokCreate runs token create with args and returns the JWT it printed.
func tokCreate(t *testing.T, args ...string) string {
	t.Helper()
	out, err := tokCapture(t, append([]string{"token", "create"}, args...)...)
	if err != nil {
		t.Fatalf("token create %q: %v", args, err)
	}
	return strings.TrimSpace(out)
}

func TestAPIFederationToken(t *testing.T) {
	root := tokFederationCA(t)
	servers := filepath.Join(root, "servers")
	srv := tokServer(t, root)
	endpoint := srv.URL + "/servers/api/federation-token"
	fed := tokCreate(t, "--ca-dir", servers, "--scope", "federate", "--federate-type", "azure", "--claim", "env=prod", "build-01")

	for _, body := range []string{"", "{}"} {
		status, answer := tokDo(t, "POST", endpoint, fed, "application/json", body)
		var got map[string]any
		json.Unmarshal([]byte(answer), &got)
		if status != http.StatusOK || got["token_type"] != "azure" || got["audience"] != "api://AzureADTokenExchange" ||
			got["subject"] != "build-01" || got["expires"] == nil {
			t.Fatalf("POST %s with the body %q: %d %s", endpoint, body, status, answer)
		}
		caCert, err := simpleca.LoadCert(filepath.Join(servers, "ca_cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		claims := tokClaims(t, caCert, fmt.Sprint(got["token"]))
		if claims["iss"] != "https://pki.example.com/servers" || claims["sub"] != "build-01" || claims["env"] != "prod" {
			t.Errorf("claims of the JWT of /api/federation-token: %v", claims)
		}
	}

	signOnly := tokCreate(t, "--ca-dir", servers, "--domain", "example.com", "web-deploy")
	noType := tokCreate(t, "--ca-dir", servers, "--scope", "federate", "no-type")
	elsewhere := tokCreate(t, "--ca-dir", servers, "--scope", "federate", "--federate-type", "azure", "--host", "192.0.2.1", "elsewhere")
	for _, c := range []struct {
		what, url, bearer, body string
		status                  int
		want                    string
	}{
		{"no bearer token", endpoint, "", "", http.StatusUnauthorized, "a bearer token is required"},
		{"a body with fields", endpoint, fed, `{"audience":"x"}`, http.StatusBadRequest, "the body is empty or {}"},
		{"a body that is not JSON", endpoint, fed, "x", http.StatusBadRequest, "the body is empty or {}"},
		{"a body too large", endpoint, fed, strings.Repeat(" ", federationMaxBody+1), http.StatusRequestEntityTooLarge,
			tooLargeText(federationMaxBody)},
		{"a token without the scope federate", endpoint, signOnly, "", http.StatusForbidden, "the token does not have the scope federate"},
		{"a token without a token type", endpoint, noType, "", http.StatusForbidden, "the token has no token type of its JWTs"},
		{"a token of another client", endpoint, elsewhere, "", http.StatusForbidden, "the token is not allowed from 127.0.0.1"},
		{"a token that is not one", endpoint, "garbage", "", http.StatusUnauthorized, ""},
		{"the root CA without tokens", srv.URL + "/api/federation-token", fed, "", http.StatusNotFound, ""},
		{"an unknown issuing CA", srv.URL + "/nosuch/api/federation-token", fed, "", http.StatusNotFound, ""},
	} {
		status, answer := tokDo(t, "POST", c.url, c.bearer, "application/json", c.body)
		if status != c.status || !strings.Contains(answer, c.want) {
			t.Errorf("%s: %d %s, want %d %s", c.what, status, answer, c.status, c.want)
		}
	}

	// A token type the settings no longer resolve is refused, and a tokens-db.json that cannot be
	// read is an internal error.
	cfg, err := simpleca.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Federation.Issuer = ""
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if status, answer := tokDo(t, "POST", endpoint, fed, "", ""); status != http.StatusBadRequest || !strings.Contains(answer, "needs an issuer") {
		t.Errorf("a token type without an issuer: %d %s, want 400", status, answer)
	}
	if err := os.WriteFile(filepath.Join(servers, tokens.TokensFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, answer := tokDo(t, "POST", endpoint, fed, "", ""); status != http.StatusInternalServerError {
		t.Errorf("a malformed %s: %d %s, want 500", tokens.TokensFile, status, answer)
	}
	if err := apiErr(http.StatusTeapot, "a %s", "message"); err.Error() != "a message" || err.status != http.StatusTeapot {
		t.Errorf("apiErr: %q, %d", err.Error(), err.status)
	}
}

func TestTokenIssuerRoutes(t *testing.T) {
	root := tokFederationCA(t)
	srv := tokServer(t, root)
	for _, id := range []string{"", "servers"} {
		prefix, issuer := "", "https://pki.example.com"
		if id != "" {
			prefix, issuer = "/"+id, issuer+"/"+id
		}
		caCert, err := simpleca.LoadCert(filepath.Join(root, id, "ca_cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		status, body := tokDo(t, "GET", srv.URL+prefix+"/.well-known/openid-configuration", "", "", "")
		var doc map[string]any
		json.Unmarshal([]byte(body), &doc)
		if status != http.StatusOK || doc["issuer"] != issuer || doc["jwks_uri"] != issuer+"/jwks.json" ||
			fmt.Sprint(doc["id_token_signing_alg_values_supported"]) != "["+jose.JWTAlg(caCert.PublicKey)+"]" {
			t.Errorf("GET %s/.well-known/openid-configuration: %d %s", prefix, status, body)
		}
		want, err := tokens.CAJWKS(filepath.Join(root, id))
		if err != nil {
			t.Fatal(err)
		}
		if status, body := tokDo(t, "GET", srv.URL+prefix+"/jwks.json", "", "", ""); status != http.StatusOK || body != string(want)+"\n" {
			t.Errorf("GET %s/jwks.json: %d %s, want\n%s", prefix, status, body, want)
		}
	}
	if status, _ := tokDo(t, "GET", srv.URL+"/nosuch/jwks.json", "", "", ""); status != http.StatusNotFound {
		t.Errorf("GET /nosuch/jwks.json: %d, want 404", status)
	}

	plain := tokServer(t, newHierarchy(t))
	for _, path := range []string{"/.well-known/openid-configuration", "/servers/jwks.json"} {
		if status, _ := tokDo(t, "GET", plain.URL+path, "", "", ""); status != http.StatusNotFound {
			t.Errorf("GET %s of a CA without an issuer: %d, want 404", path, status)
		}
	}

	broken := newHierarchy(t)
	if err := os.WriteFile(filepath.Join(broken, simpleca.ConfigFile), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status, _ := tokDo(t, "GET", tokServer(t, broken).URL+"/jwks.json", "", "", ""); status != http.StatusInternalServerError {
		t.Errorf("GET /jwks.json with a malformed %s: %d, want 500", simpleca.ConfigFile, status)
	}
}

func TestTokenDescribePage(t *testing.T) {
	root := newHierarchy(t)
	servers := filepath.Join(root, "servers")
	srv := tokServer(t, root)
	page := srv.URL + "/token-describe"
	form := "application/x-www-form-urlencoded"
	jwt := tokCreate(t, "--ca-dir", servers, "--domain", "example.com", "web-deploy")

	if status, body := tokDo(t, "GET", page, "", "", ""); status != http.StatusOK || !strings.Contains(body, `<form method="post" action="/token-describe"`) {
		t.Errorf("GET /token-describe: %d\n%s", status, body)
	}
	describe := func(token string) (int, string) {
		t.Helper()
		return tokDo(t, "POST", page, "", form, url.Values{"token": {token}}.Encode())
	}
	if status, body := describe(jwt); status != http.StatusOK || !strings.Contains(body, "issuing CA servers") ||
		!strings.Contains(body, "web-deploy") || !strings.Contains(body, "example.com") {
		t.Errorf("POST /token-describe of a token of servers: %d\n%s", status, body)
	}
	rootToken := tokCreate(t, "--ca-dir", root, "--domain", "example.com", "root-deploy")
	if status, body := describe(rootToken); status != http.StatusOK || !strings.Contains(body, "root CA") ||
		!strings.Contains(body, "root-deploy") {
		t.Errorf("POST /token-describe of a token of the root CA: %d\n%s", status, body)
	}
	if out, err := tokCapture(t, "token", "renew", "--ca-dir", servers, "web-deploy"); err != nil {
		t.Fatalf("token renew: %q, %v", out, err)
	}
	if status, body := describe(jwt); status != http.StatusOK || !strings.Contains(body, "refused: the token was renewed, revoked or removed") {
		t.Errorf("POST /token-describe of a renewed token: %d\n%s", status, body)
	}
	if out, err := tokCapture(t, "token", "revoke", "--ca-dir", root, "root-deploy"); err != nil {
		t.Fatalf("token revoke: %q, %v", out, err)
	}
	if status, body := describe(rootToken); status != http.StatusOK || !strings.Contains(body, "refused: the token was renewed, revoked or removed") {
		t.Errorf("POST /token-describe of a revoked token: %d\n%s", status, body)
	}
	short, err := tokens.MakeToken(root, "short", time.Second, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if status, body := describe(short); status != http.StatusOK || !strings.Contains(body, "expired at") {
		t.Errorf("POST /token-describe of an expired token: %d\n%s", status, body)
	}
	for _, c := range []struct {
		what, body string
		status     int
		want       string
	}{
		{"no token", "token=", http.StatusUnauthorized, "a token is required"},
		{"a token of no CA", "token=garbage", http.StatusUnauthorized, "the token is not one of a CA of this server"},
		{"a malformed form", "token=%zz", http.StatusBadRequest, "the form is malformed"},
		{"a form too large", "token=" + strings.Repeat("a", formMaxBody), http.StatusRequestEntityTooLarge, tooLargeText(formMaxBody)},
	} {
		if status, body := tokDo(t, "POST", page, "", form, c.body); status != c.status || !strings.Contains(body, c.want) {
			t.Errorf("POST /token-describe with %s: %d\n%s\nwant %d %s", c.what, status, body, c.status, c.want)
		}
	}

	fresh := tokCreate(t, "--ca-dir", servers, "--domain", "example.com", "fresh")
	if err := os.WriteFile(filepath.Join(servers, tokens.TokensFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, body := describe(fresh); status != http.StatusInternalServerError || !strings.Contains(body, "could not read the tokens") {
		t.Errorf("POST /token-describe with a malformed %s: %d\n%s", tokens.TokensFile, status, body)
	}

	if err := os.Rename(filepath.Join(root, "ca_cert.pem"), filepath.Join(root, "ca_cert.pem.moved")); err != nil {
		t.Fatal(err)
	}
	if status, _ := tokDo(t, "GET", page, "", "", ""); status != http.StatusInternalServerError {
		t.Errorf("GET /token-describe without the CA certificate: %d, want 500", status)
	}
}

func TestOIDCCallbackPage(t *testing.T) {
	root := newHierarchy(t)
	srv := tokServer(t, root)
	req, err := http.NewRequest("GET", srv.URL+"/oidc-callback", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(string(body), "Test CA") {
		t.Errorf("GET /oidc-callback: %d %v\n%s", resp.StatusCode, resp.Header, body)
	}
	if err := os.Remove(filepath.Join(root, "ca_cert.pem")); err != nil {
		t.Fatal(err)
	}
	if status, _ := tokDo(t, "GET", srv.URL+"/oidc-callback", "", "", ""); status != http.StatusInternalServerError {
		t.Errorf("GET /oidc-callback without the CA certificate: %d, want 500", status)
	}
}
