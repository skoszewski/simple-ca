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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/pkg/simpleca/tokens"
)

func TestCertWebUI(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	key, err := tokens.MakeToken(caDir, "operator", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	tokensOnly, err := tokens.MakeToken(caDir, "tokens-only", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	prefix := "/certificates"
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

	// The page loads the shared script and its own.
	resp, err := http.Get(server.URL + prefix + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %v, %v, want the page", resp, err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, script := range []string{"/assets/webui/webui.js", "/assets/webui/certs.js"} {
		if !strings.Contains(string(page), `<script src="`+script+`">`) {
			t.Errorf("the page does not load %s", script)
		}
	}

	// The API takes a token with the scope certs alone; the CAs come with the name rules, the
	// reasons and the days.
	if status, _ := call("wrong", "GET", "/api/certs?ca=issuing-ca", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/certs with a wrong token: %d, want 401", status)
	}
	if status, _ := call(tokensOnly, "GET", "/api/cas", nil); status != http.StatusForbidden {
		t.Errorf("GET /api/cas with a token without the scope certs: %d, want 403", status)
	}
	status, answer := call(key, "GET", "/api/cas", nil)
	if names, _ := answer["names"].(map[string]any); status != http.StatusOK || names["user"] != "user" ||
		fmt.Sprint(answer["defaults"]) != "map[crl_days:30 days:365]" {
		t.Fatalf("GET /api/cas: %d %v, want the name rules and the days", status, answer)
	}
	if status, _ := call(key, "POST", "/api/tokens", map[string]any{"ca": ""}); status != http.StatusNotFound {
		t.Errorf("a token request of the certificate page: %d, want 404", status)
	}

	// A certificate is created into the CA directory, once; a second create of the name is refused.
	body := map[string]any{"ca": "issuing-ca", "type": "server", "subject": "web.example.com", "sans": []string{"192.0.2.10"}, "days": 30}
	if status, answer := call(key, "POST", "/api/certs", body); status != http.StatusCreated {
		t.Fatalf("create: %d %v, want 201", status, answer)
	}
	if !simpleca.FileExists(filepath.Join(issuingDir, "web_cert.pem")) || !simpleca.FileExists(filepath.Join(issuingDir, "web_key.pem")) {
		t.Fatal("create wrote no certificate and key to the CA directory")
	}
	if status, _ := call(key, "POST", "/api/certs", body); status != http.StatusConflict {
		t.Errorf("create of an existing name: %d, want 409", status)
	}
	if status, answer := call(key, "POST", "/api/certs", map[string]any{"ca": "issuing-ca", "type": "server",
		"subject": "not a host", "days": 30}); status != http.StatusBadRequest || answer["error"] == nil {
		t.Errorf("create with a bad CN: %d %v, want 400 with the error", status, answer)
	}

	// A request is signed into the CA directory under the name given, cleaned.
	csrPath := filepath.Join(t.TempDir(), "api.csr")
	if out, err := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", os.DevNull, "-subj", "/CN=api.example.com", "-out", csrPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	csr, _ := os.ReadFile(csrPath)
	status, answer = call(key, "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "api server", "csr": string(csr), "days": 30})
	if status != http.StatusCreated || answer["file"] != "api_server_cert.pem" || !simpleca.FileExists(filepath.Join(issuingDir, "api_server_cert.pem")) {
		t.Fatalf("sign: %d %v, want api_server_cert.pem in the CA directory", status, answer)
	}
	if status, _ := call(key, "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "../x", "csr": string(csr), "days": 30}); status != http.StatusBadRequest {
		t.Errorf("sign with a name holding a directory: %d, want 400", status)
	}

	// The certificates are listed; one is revoked for a reason, and the CRL lists it.
	status, answer = call(key, "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ := answer["certs"].([]any)
	if status != http.StatusOK || len(certs) != 2 || certs[0].(map[string]any)["status"] != "valid" {
		t.Fatalf("GET /api/certs: %d %v, want the two certificates, valid", status, answer)
	}
	serial := certs[0].(map[string]any)["serial"]

	// A certificate is shown from its file, as cert show writes it; the root CA shows its issuing CAs.
	status, answer = call(key, "GET", "/api/certs/show?ca=issuing-ca&serial="+serial.(string), nil)
	shown, _ := answer["certificate"].(map[string]any)
	if status != http.StatusOK || answer["file"] != "web_cert.pem" || fmt.Sprint(shown["ip_addresses"]) != "[192.0.2.10]" ||
		fmt.Sprint(shown["key"]) != "map[algorithm:RSA bits:4096]" || shown["validity"] != "valid" ||
		fmt.Sprint(shown["subject"]) != "[[CN web.example.com]]" ||
		!regexp.MustCompile(`^[0-9A-F]{64}$`).MatchString(fmt.Sprint(shown["sha256_fingerprint"])) {
		t.Errorf("GET /api/certs/show: %d %v, want web_cert.pem with its IP address", status, answer)
	}
	if status, answer := call(key, "GET", "/api/certs/show?ca=issuing-ca&serial=00", nil); status != http.StatusNotFound || answer["error"] == nil {
		t.Errorf("GET /api/certs/show of an unknown serial: %d %v, want 404 with an error", status, answer)
	}
	_, answer = call(key, "GET", "/api/certs?ca=", nil)
	rootCerts, _ := answer["certs"].([]any)
	if len(rootCerts) != 1 {
		t.Fatalf("GET /api/certs of the root CA: %v, want the issuing CA", answer)
	}
	if status, answer := call(key, "GET", "/api/certs/show?ca=&serial="+rootCerts[0].(map[string]any)["serial"].(string), nil); status != http.StatusOK || answer["file"] != "issuing-ca/ca_cert.pem" {
		t.Errorf("GET /api/certs/show of the issuing CA: %d %v, want issuing-ca/ca_cert.pem", status, answer)
	}

	if status, _ := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "nonsense"}); status != http.StatusBadRequest {
		t.Errorf("revoke with an unknown reason: %d, want 400", status)
	}
	if status, answer := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "superseded"}); status != http.StatusOK {
		t.Fatalf("revoke: %d %v, want 200", status, answer)
	}
	if status, _ := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial}); status != http.StatusBadRequest {
		t.Errorf("revoke twice: %d, want 400", status)
	}
	if status, answer := call(key, "POST", "/api/crl", map[string]any{"ca": "issuing-ca", "days": 7}); status != http.StatusOK {
		t.Fatalf("crl: %d %v, want 200", status, answer)
	}
	status, answer = call(key, "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ = answer["certs"].([]any)
	crl, _ := answer["crl"].(map[string]any)
	if status != http.StatusOK || certs[0].(map[string]any)["status"] != "revoked" || certs[0].(map[string]any)["reason"] != "superseded" ||
		crl["number"] != "2" {
		t.Errorf("GET /api/certs after revoking: %d %v, want the certificate revoked, superseded, and CRL number 2", status, answer)
	}
}
