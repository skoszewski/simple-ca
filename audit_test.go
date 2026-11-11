package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

func TestAudit(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(rootDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatalf("makeCA servers: %v", err)
	}
	serversDir := filepath.Join(rootDir, "servers")
	field := func(e simpleca.AuditEntry, key string) string {
		for _, p := range e.Fields {
			if p[0] == key {
				return p[1]
			}
		}
		return ""
	}
	last := func() simpleca.AuditEntry {
		t.Helper()
		entries, err := simpleca.ReadAudit(rootDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("readAudit: %d records, %v", len(entries), err)
		}
		return entries[len(entries)-1]
	}

	// The commands record their changes with the OS user; what they print is dropped.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = devNull
	t.Cleanup(func() { os.Stdout = stdout; devNull.Close() })
	for _, c := range []struct {
		args  []string
		event string
	}{
		{[]string{"cert", "create", "--ca-dir", serversDir, "web.example.com"}, "cert.issue"},
		{[]string{"cert", "revoke", "--ca-dir", serversDir, "--reason", "superseded", filepath.Join(serversDir, "web_cert.pem")}, "cert.revoke"},
		{[]string{"crl", "create", "--ca-dir", serversDir}, "crl.write"},
		{[]string{"token", "create", "--ca-dir", serversDir, "--domain", "example.com", "deploy"}, "token.create"},
		{[]string{"token", "revoke", "--ca-dir", serversDir, "deploy"}, "token.revoke"},
		{[]string{"token", "purge", "--ca-dir", serversDir, "deploy"}, "token.purge"},
	} {
		if err := run(c.args); err != nil {
			t.Fatalf("run %q: %v", c.args, err)
		}
		if e := last(); e.Event != c.event || e.CA != "servers" || field(e, "via") != "cli" || field(e, "actor") != simpleca.CLIActor() {
			t.Errorf("run %q: %s, want %s by cli and %s", c.args, e.Line, c.event, simpleca.CLIActor())
		}
	}
	os.Stdout = stdout
	if e := last(); field(e, "name") != "deploy" {
		t.Errorf("token.purge: %s, want the name deploy", e.Line)
	}

	// serve records the token page, the signing API and refused tokens with the client.
	free := authFreeFailures
	authFreeFailures = 1
	shared := guard
	guard = newAuthGuard()
	t.Cleanup(func() { authFreeFailures, guard = free, shared })
	admin, err := simpleca.MakeToken(rootDir, "admin", time.Hour, []string{"*"}, nil, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := simpleca.MakeToken(serversDir, "signer", time.Hour, []string{"sign", "audit"}, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	call := func(token, method, path string, body any) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	if status, _ := call(admin, "POST", "/tokens/api/tokens", map[string]any{"ca": "servers", "name": "web", "valid": "1h",
		"scopes": []string{"sign"}, "types": []string{"server"}, "domains": []string{"example.com"}}); status != http.StatusCreated {
		t.Fatalf("create a token on the token page: %d", status)
	}
	if e := last(); e.Event != "token.create" || field(e, "via") != "webui" || field(e, "actor") != "admin" || field(e, "client") != "127.0.0.1" {
		t.Errorf("token page: %s, want token.create by admin on webui from 127.0.0.1", e.Line)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, answer := call(signer, "POST", "/servers/api/sign", map[string]any{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), "type": "server", "name": "web",
		"days": 30})
	if e := last(); status != http.StatusOK || e.Event != "cert.issue" || field(e, "serial") != answer["serial"] ||
		field(e, "via") != "api" || field(e, "actor") != "signer" {
		t.Errorf("signing API: %d, %s, want cert.issue of serial %v by signer", status, e.Line, answer["serial"])
	}
	call("bad.token.here", "GET", "/tokens/api/cas", nil)
	if e := last(); e.Event != "auth.refused" || field(e, "route") != "/tokens/api/cas" || field(e, "reason") != "invalid token" {
		t.Errorf("a refused token: %s, want auth.refused of /tokens/api/cas", e.Line)
	}
	call("bad.token.here", "GET", "/tokens/api/cas", nil)
	if e := last(); e.Event != "auth.held" || field(e, "wait") != "1s" {
		t.Errorf("a second refused token: %s, want auth.held for 1s", e.Line)
	}
	guard = newAuthGuard()

	// The audit page wants the scope audit, and shows the log of the server, newest first, within
	// limit, to a root CA token, and the records of its own CA to an issuing CA token.
	status, answer = call(signer, "GET", "/audit/api/entries?limit=2", nil)
	if entries, _ := answer["entries"].([]any); status != http.StatusOK || len(entries) != 2 ||
		entries[0].(map[string]any)["event"] != "cert.issue" || answer["total"].(float64) < 8 {
		t.Errorf("the 2 newest records of servers: %d %v, want cert.issue first of at least 8", status, answer)
	}
	cas := func(token string) map[string]bool {
		_, answer := call(token, "GET", "/audit/api/entries", nil)
		seen := map[string]bool{}
		for _, e := range answer["entries"].([]any) {
			seen[e.(map[string]any)["ca"].(string)] = true
		}
		return seen
	}
	if seen := cas(signer); !seen["servers"] || seen[""] {
		t.Errorf("the CAs of the records of an issuing CA token: %v, want servers alone", seen)
	}
	if seen := cas(admin); !seen["servers"] || !seen[""] {
		t.Errorf("the CAs of the records of a root CA token: %v, want the root CA and servers", seen)
	}
	if web, err := simpleca.MakeToken(serversDir, "tokens-only", time.Hour, []string{"tokens"}, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	} else if status, _ := call(web, "GET", "/audit/api/entries", nil); status != http.StatusForbidden {
		t.Errorf("the audit page without the scope audit: %d, want 403", status)
	}

	// audit list filters the records.
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	err = run([]string{"audit", "list", "--ca-dir", rootDir, "--event", "token.", "--ca", "servers", "--actor", simpleca.CLIActor()})
	os.Stdout = stdout
	writer.Close()
	printed, _ := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	out := string(printed)
	if lines := strings.Split(strings.TrimSpace(out), "\n"); len(lines) != 3 || !strings.Contains(lines[0], "event=token.create") {
		t.Errorf("audit list --event token. --ca servers: %q, want the 3 token records of the commands", out)
	}
}
