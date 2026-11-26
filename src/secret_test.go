package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/secrets"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// secretCA makes a root CA with the issuing CA issuing-ca and returns the root CA directory.
func secretCA(t *testing.T) string {
	t.Helper()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	return caDir
}

func TestSecretWebUI(t *testing.T) {
	caDir := secretCA(t)
	admin, err := tokens.MakeToken(caDir, "admin", time.Hour, []string{"secrets"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	issuingAdmin, err := tokens.MakeToken(filepath.Join(caDir, "issuing-ca"), "issuing-admin", time.Hour, []string{"secrets"},
		nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokensOnly, err := tokens.MakeToken(caDir, "tokens-only", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+"/secrets"+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}

	// The page loads its script; the API takes a token with the scope secrets alone.
	resp, err := http.Get(server.URL + "/secrets/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /secrets/: %v, %v, want the page", resp, err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), `<script src="/assets/webui/secrets.js">`) {
		t.Error("the page does not load secrets.js")
	}
	if status, _ := call("", "GET", "/api/cas", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/cas without a token: %d, want 401", status)
	}
	if status, answer := call(tokensOnly, "GET", "/api/cas", nil); status != http.StatusForbidden ||
		!strings.Contains(fmt.Sprint(answer["error"]), "scope secrets") {
		t.Errorf("GET /api/cas with a token without the scope secrets: %d %v, want 403", status, answer)
	}
	if status, answer := call(admin, "GET", "/api/cas", nil); status != http.StatusOK ||
		fmt.Sprint(answer["defaults"]) != "map[valid:1d]" {
		t.Errorf("GET /api/cas: %d %v, want the default validity 1d", status, answer)
	}

	// A secret is created with its code, listed without its value, and revoked.
	if status, answer := call(admin, "POST", "/api/secrets", map[string]any{"ca": "", "name": "Bad_Name", "value": "v",
		"valid": "1h", "networks": []string{}}); status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), "kebab-case") {
		t.Errorf("create with a bad name: %d %v, want 400", status, answer)
	}
	if status, answer := call(admin, "POST", "/api/secrets", map[string]any{"ca": "", "name": "x", "value": "v",
		"valid": "1h", "secret": "v"}); status != http.StatusBadRequest {
		t.Errorf("create with an unknown field: %d %v, want 400", status, answer)
	}
	status, answer := call(admin, "POST", "/api/secrets", map[string]any{"ca": "issuing-ca", "name": "db-password",
		"value": "hunter2", "valid": "2h", "networks": []string{"192.168.1.0/24"}})
	if ok, _ := regexp.MatchString(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`, fmt.Sprint(answer["code"])); status != http.StatusCreated || !ok {
		t.Fatalf("create: %d %v, want 201 with a code", status, answer)
	}
	status, answer = call(admin, "GET", "/api/secrets?ca=issuing-ca", nil)
	listed, _ := answer["secrets"].([]any)
	if status != http.StatusOK || len(listed) != 1 || listed[0].(map[string]any)["name"] != "db-password" ||
		listed[0].(map[string]any)["creator"] != "admin" || fmt.Sprint(listed[0].(map[string]any)["clients"]) != "[192.168.1.0/24]" ||
		strings.Contains(fmt.Sprint(answer), "hunter2") {
		t.Errorf("list: %d %v, want db-password without its value", status, answer)
	}
	if status, answer := call(issuingAdmin, "GET", "/api/secrets?ca=", nil); status != http.StatusNotFound {
		t.Errorf("a token of the issuing CA listing the root CA: %d %v, want 404", status, answer)
	}
	if status, answer := call(admin, "POST", "/api/secrets/revoke", map[string]any{"ca": "issuing-ca", "name": "db-password"}); status != http.StatusOK {
		t.Errorf("revoke: %d %v, want 200", status, answer)
	}
	if status, _ := call(admin, "POST", "/api/secrets/revoke", map[string]any{"ca": "issuing-ca", "name": "db-password"}); status != http.StatusNotFound {
		t.Errorf("revoking a revoked secret: %d, want 404", status)
	}
	if status, _ := call(admin, "POST", "/api/secrets/revoke", map[string]any{"ca": "../x", "name": "db-password"}); status != http.StatusNotFound {
		t.Errorf("revoking in an unknown CA: %d, want 404", status)
	}
	audit, _ := os.ReadFile(filepath.Join(caDir, simpleca.AuditFile))
	if !strings.Contains(string(audit), "secret.create") || !strings.Contains(string(audit), "secret.revoke") ||
		strings.Contains(string(audit), "hunter2") {
		t.Errorf("the audit log:\n%s\nwant secret.create and secret.revoke without the value", audit)
	}
}

func TestSecretGet(t *testing.T) {
	caDir := secretCA(t)
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()
	get := func(body string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Post(server.URL+"/api/secret-get", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}

	// The API shows the secret once, text as it is and other bytes in base64.
	code, err := secrets.Add(filepath.Join(caDir, "issuing-ca"), "api-key", []byte("key=value\n"), time.Hour, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if status, answer := get(`{"code": "` + strings.ToLower(code) + `"}`); status != http.StatusOK || answer["ca"] != "issuing-ca" ||
		answer["name"] != "api-key" || answer["secret"] != "key=value\n" || answer["encoding"] != nil {
		t.Fatalf("get: %d %v, want the secret api-key of issuing-ca", status, answer)
	}
	if status, _ := get(`{"code": "` + code + `"}`); status != http.StatusUnauthorized {
		t.Errorf("a used code: %d, want 401", status)
	}
	binary, err := secrets.Add(caDir, "binary", []byte{0xff, 0x00, 0x01}, time.Hour, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if status, answer := get(`{"code": "` + binary + `"}`); status != http.StatusOK || answer["secret"] != "/wAB" || answer["encoding"] != "base64" {
		t.Errorf("get of a binary value: %d %v, want it in base64", status, answer)
	}
	for body, want := range map[string]int{`{"code": ""}`: http.StatusBadRequest, `{"code": "x", "other": 1}`: http.StatusBadRequest} {
		if status, _ := get(body); status != want {
			t.Errorf("get %s: %d, want %d", body, status, want)
		}
	}
	far, err := secrets.Add(caDir, "far", []byte("v"), time.Hour, []string{"10.0.0.0/8"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if status, answer := get(`{"code": "` + far + `"}`); status != http.StatusForbidden {
		t.Errorf("a client outside the networks: %d %v, want 403", status, answer)
	}

	// The page shows the secret once, escaped, and refuses the code after that.
	page, err := secrets.Add(caDir, "page", []byte("<b>pass</b>"), time.Hour, nil, "alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		want int
		text string
	}{{http.StatusOK, "&lt;b&gt;pass&lt;/b&gt;"}, {http.StatusUnauthorized, "unknown or used code"}} {
		resp, err := http.PostForm(server.URL+"/secret-get", url.Values{"code": {page}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want || !strings.Contains(string(body), c.text) || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("POST /secret-get: %d, want %d with %q", resp.StatusCode, c.want, c.text)
		}
	}
	resp, err := http.Get(server.URL + "/secret-get")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /secret-get: %v, %v", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `name="code"`) {
		t.Error("GET /secret-get shows no form asking for the code")
	}
	audit, _ := os.ReadFile(filepath.Join(caDir, simpleca.AuditFile))
	if strings.Count(string(audit), "secret.get") != 3 || strings.Contains(string(audit), "pass") {
		t.Errorf("the audit log:\n%s\nwant 3 secret.get records without the values", audit)
	}
}

func TestSecretCommands(t *testing.T) {
	caDir := secretCA(t)
	file := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(file, []byte("from a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, err := tokCapture(t, "secret", "create", "--ca-dir", caDir, "--file", file, "--valid", "2h", "--network", "10.0.0.0/8", "file-secret")
	if ok, _ := regexp.MatchString(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}\n$`, code); err != nil || !ok {
		t.Fatalf("secret create: %q, %v, want a code", code, err)
	}
	if _, err := tokCapture(t, "secret", "create", "--ca-dir", caDir, "--file", file, "file-secret"); err == nil {
		t.Error("a second secret create of the same name succeeded")
	}
	out, err := tokCapture(t, "secret", "list", "--ca-dir", caDir)
	if err != nil || !strings.Contains(out, "file-secret") || !strings.Contains(out, "10.0.0.0/8") || strings.Contains(out, "from a file") {
		t.Errorf("secret list: %q, %v, want file-secret without its value", out, err)
	}
	if out, err := tokCapture(t, "secret", "revoke", "--ca-dir", caDir, "file-secret"); err != nil || out != "Secret \"file-secret\" revoked\n" {
		t.Errorf("secret revoke: %q, %v", out, err)
	}
	if _, err := tokCapture(t, "secret", "revoke", "--ca-dir", caDir, "file-secret"); err == nil {
		t.Error("revoking a revoked secret succeeded")
	}
	if out, err := tokCapture(t, "secret", "list", "--ca-dir", caDir); err != nil || strings.Contains(out, "file-secret") {
		t.Errorf("secret list after the revoke: %q, %v", out, err)
	}
	if _, err := tokCapture(t, "secret", "create", "--ca-dir", caDir, "--file", file, "--valid", "31d", "long"); err == nil {
		t.Error("a validity longer than 30d is taken")
	}
}
