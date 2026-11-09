package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenWebUI(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	key, err := makeToken(caDir, "admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	prefix := "/tokens"
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+prefix+path, reader)
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

	// The page and its scripts are served to anyone; the API takes a token with the scope tokens
	// alone.
	resp, err := http.Get(server.URL + prefix + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %v, %v, want the page", resp, err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, script := range []string{"/assets/webui/webui.js", "/assets/webui/tokens.js"} {
		if !strings.Contains(string(page), `<script src="`+script+`">`) {
			t.Errorf("the page does not load %s", script)
		}
		resp, err := http.Get(server.URL + script)
		if err != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") {
			t.Errorf("GET %s: %v, %v, want the script", script, resp, err)
			continue
		}
		resp.Body.Close()
	}
	for _, path := range []string{"/assets/webui/", "/assets/webui/missing.js"} {
		if resp, err := http.Get(server.URL + path); err != nil || resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %v, %v, want 404", path, resp, err)
		}
	}
	for _, key := range []string{"", "wrong"} {
		if status, answer := call(key, "GET", "/api/cas", nil); status != http.StatusUnauthorized || answer["error"] == nil {
			t.Errorf("GET /api/cas with the token %q: %d %v, want 401 with an error", key, status, answer)
		}
	}
	signOnly, err := makeToken(caDir, "sign-only", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if status, answer := call(signOnly, "GET", "/api/cas", nil); status != http.StatusForbidden ||
		!strings.Contains(fmt.Sprint(answer["error"]), "scope tokens") {
		t.Errorf("GET /api/cas with a token without the scope tokens: %d %v, want 403 naming the scope", status, answer)
	}
	for range 2 {
		status, answer := call(key, "GET", "/api/cas", nil)
		cas, _ := answer["cas"].([]any)
		if status != http.StatusOK || answer["title"] != "Test CA" || len(cas) != 2 ||
			cas[1].(map[string]any)["id"] != "issuing-ca" || fmt.Sprint(cas[1].(map[string]any)["subject"]) != "[[CN Issuing CA]]" ||
			cas[1].(map[string]any)["label"] != nil || cas[1].(map[string]any)["role"] != nil {
			t.Fatalf("GET /api/cas: %d %v, want the root and the issuing CA, with their IDs and subject attributes alone", status, answer)
		}
	}

	// A token is created, listed, renewed with a new JWT ID, revoked, kept, and purged.
	if status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "Bad_Name",
		"valid": "1h", "scopes": []string{"sign"}, "types": []string{"server"}, "domains": []string{"example.com"}}); status != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(answer["error"]), "kebab-case") {
		t.Errorf("create with a bad name: %d %v, want 400 with the error", status, answer)
	}
	status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "web-deploy",
		"valid": "8h", "scopes": []string{"sign"}, "domains": []string{"example.com"}, "clients": []string{"192.168.1.0/24"},
		"types": []string{"server"}})
	if status != http.StatusCreated || !strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Fatalf("create: %d %v, want 201 with the token", status, answer)
	}
	status, answer = call(key, "GET", "/api/tokens?ca=issuing-ca", nil)
	tokens, _ := answer["tokens"].([]any)
	if status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["name"] != "web-deploy" ||
		fmt.Sprint(tokens[0].(map[string]any)["clients"]) != "[192.168.1.0/24]" {
		t.Fatalf("GET /api/tokens: %d %v, want web-deploy from 192.168.1.0/24", status, answer)
	}
	created, _ := loadTokens(filepath.Join(caDir, "issuing-ca"))
	if status, answer := call(key, "POST", "/api/tokens/renew", map[string]any{"ca": "issuing-ca", "name": "web-deploy",
		"valid": "8h"}); status != http.StatusOK ||
		!strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Errorf("renew: %d %v, want the renewed token", status, answer)
	}
	if db, _ := loadTokens(filepath.Join(caDir, "issuing-ca")); db.Tokens["web-deploy"].ID == created.Tokens["web-deploy"].ID {
		t.Error("the renewed token has no new JWT ID")
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "../x", "name": "web-deploy"}); status != http.StatusNotFound {
		t.Errorf("revoke of a CA outside the root: %d, want 404", status)
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "issuing-ca", "name": "web-deploy"}); status != http.StatusOK {
		t.Errorf("revoke: %d, want 200", status)
	}
	status, answer = call(key, "GET", "/api/tokens?ca=issuing-ca", nil)
	if tokens, _ := answer["tokens"].([]any); status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["revoked"] != true {
		t.Errorf("GET /api/tokens after revoking: %d %v, want web-deploy kept, revoked", status, answer)
	}
	if status, answer := call(key, "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca"}); status != http.StatusOK ||
		answer["removed"] != float64(1) {
		t.Errorf("purge: %d %v, want 1 removed", status, answer)
	}
	if status, _ := call(key, "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca", "bogus": true}); status != http.StatusBadRequest {
		t.Errorf("purge with an unknown field: %d, want 400", status)
	}

	// A token grants sign and its own scopes, and manages the tokens whose scopes it grants.
	if status, _ := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "operator",
		"valid": "1h", "scopes": []string{"certs"}}); status != http.StatusForbidden {
		t.Errorf("creating a token with a scope the token lacks: %d, want 403", status)
	}
	if status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "helper",
		"valid": "1h", "scopes": []string{"tokens"}}); status != http.StatusCreated {
		t.Errorf("creating a token with the scope tokens: %d %v, want 201", status, answer)
	}
	if _, err := makeToken(filepath.Join(caDir, "issuing-ca"), "operator", time.Hour, []string{"certs"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "issuing-ca", "name": "operator"}); status != http.StatusForbidden {
		t.Errorf("revoking a token with a scope the token lacks: %d, want 403", status)
	}

	// An issuing CA token opens that CA alone.
	issuingKey, err := makeToken(filepath.Join(caDir, "issuing-ca"), "issuing-admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	status, answer = call(issuingKey, "GET", "/api/cas", nil)
	if cas, _ := answer["cas"].([]any); status != http.StatusOK || len(cas) != 1 || cas[0].(map[string]any)["id"] != "issuing-ca" ||
		answer["user"] != "issuing-admin" || answer["user_ca"] != "issuing-ca" {
		t.Errorf("GET /api/cas with an issuing CA token: %d %v, want the issuing CA alone", status, answer)
	}
	if status, _ := call(issuingKey, "GET", "/api/tokens?ca=", nil); status != http.StatusNotFound {
		t.Errorf("GET /api/tokens of the root CA with an issuing CA token: %d, want 404", status)
	}
}
