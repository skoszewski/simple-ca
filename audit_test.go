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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAudit(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(rootDir, "Servers CA", 3650, "servers", ""); err != nil {
		t.Fatalf("makeCA servers: %v", err)
	}
	serversDir := filepath.Join(rootDir, "servers")
	field := func(e auditEntry, key string) string {
		for _, p := range e.Fields {
			if p[0] == key {
				return p[1]
			}
		}
		return ""
	}
	last := func() auditEntry {
		t.Helper()
		entries, err := readAudit(rootDir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("readAudit: %d records, %v", len(entries), err)
		}
		return entries[len(entries)-1]
	}

	// The reader reads back what TextHandler wrote, quoted or not, and the stream gets the same.
	var streamed []string
	logStream = func(line string, pairs [][2]string, level slog.Level) error {
		streamed = append(streamed, line)
		return nil
	}
	t.Cleanup(func() { logStream = nil })
	odd := []string{"two words", `a "quote"`, "k=v", "", `back\slash`, "line\nbreak"}
	audit(serversDir, "test.event", "a", odd[0], "b", odd[1], "c", odd[2], "d", odd[3], "e", odd[4], "f", odd[5], "n", 42)
	e := last()
	if e.Event != "test.event" || e.CA != "servers" || time.Since(e.Time) > time.Minute {
		t.Errorf("record %+v, want test.event of servers, now", e)
	}
	for i, key := range []string{"a", "b", "c", "d", "e", "f"} {
		if got := field(e, key); got != odd[i] {
			t.Errorf("%s = %q, want %q", key, got, odd[i])
		}
	}
	if field(e, "n") != "42" || !strings.HasPrefix(e.Line, "time=") || strings.Contains(e.Line, "level=") {
		t.Errorf("line %q, want time first, n=42 and no level", e.Line)
	}
	if len(streamed) != 1 || strings.TrimSuffix(streamed[0], "\n") != e.Line {
		t.Errorf("stream %q, want the line of the file", streamed)
	}
	if info, err := os.Stat(filepath.Join(rootDir, auditFile)); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("audit.log: %v, want mode 0600", err)
	}
	logStream = nil

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
		if e := last(); e.Event != c.event || e.CA != "servers" || field(e, "via") != "cli" || field(e, "actor") != cliActor() {
			t.Errorf("run %q: %s, want %s by cli and %s", c.args, e.Line, c.event, cliActor())
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
	admin, err := makeToken(rootDir, "admin", time.Hour, []string{"*"}, nil, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := makeToken(serversDir, "signer", time.Hour, []string{"sign", "audit"}, []string{"server"}, []string{"example.com"}, nil, nil)
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
		"scopes": []string{"sign"}, "domains": []string{"example.com"}}); status != http.StatusCreated {
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
	status, answer := call(signer, "POST", "/servers/api/sign", map[string]string{
		"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
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

	// The audit page wants the scope audit, and shows a CA's records, newest first, within limit.
	if status, _ := call(signer, "GET", "/audit/api/entries?ca=servers", nil); status != http.StatusOK {
		t.Errorf("the audit page with the scope audit: %d, want 200", status)
	}
	status, answer = call(signer, "GET", "/audit/api/entries?ca=servers&limit=2", nil)
	if entries, _ := answer["entries"].([]any); status != http.StatusOK || len(entries) != 2 ||
		entries[0].(map[string]any)["event"] != "cert.issue" || answer["total"].(float64) < 8 {
		t.Errorf("the 2 newest records of servers: %d %v, want cert.issue first of at least 8", status, answer)
	}
	if status, _ := call(signer, "GET", "/audit/api/entries?ca=", nil); status != http.StatusNotFound {
		t.Errorf("the root CA records with an issuing CA token: %d, want 404", status)
	}
	if web, err := makeToken(serversDir, "tokens-only", time.Hour, []string{"tokens"}, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	} else if status, _ := call(web, "GET", "/audit/api/entries?ca=servers", nil); status != http.StatusForbidden {
		t.Errorf("the audit page without the scope audit: %d, want 403", status)
	}

	// audit list filters the records, and audit.file moves the log.
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	err = run([]string{"audit", "list", "--ca-dir", rootDir, "--event", "token.", "--ca", "servers", "--actor", cliActor()})
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
	moved := filepath.Join(t.TempDir(), "moved.log")
	if err := os.WriteFile(filepath.Join(rootDir, configFile), []byte(`{"audit": {"file": "`+filepath.ToSlash(moved)+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	audit(rootDir, "test.moved")
	if b, err := os.ReadFile(moved); err != nil || !strings.Contains(string(b), "event=test.moved") {
		t.Errorf("audit.file: %q, %v, want the record in %s", b, err, moved)
	}
}
