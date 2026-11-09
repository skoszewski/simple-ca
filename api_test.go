package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTokens(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	token, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server", "user"}, []string{"Example.COM."}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token %q is not a JWT", token)
	}
	info, err := os.Stat(filepath.Join(caDir, tokensFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v, mode %v, want 0600", tokensFile, err, info.Mode().Perm())
	}
	db, err := loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	tok := db.Tokens["deploy"]
	if tok == nil || !slices.Equal(tok.Domains, []string{"example.com"}) || !slices.Equal(tok.Types, []string{"server", "user"}) ||
		tok.Expires.Sub(tok.Issued) != time.Hour {
		t.Fatalf("token entry %+v, want the domains, types and validity given", tok)
	}

	for _, c := range []struct {
		name    string
		types   []string
		domains []string
	}{
		{"deploy", []string{"server"}, []string{"example.com"}},
		{"bad name", []string{"server"}, []string{"example.com"}},
		{"other", []string{"nosuch"}, []string{"example.com"}},
		{"other", []string{"server"}, nil},
		{"other", []string{"server"}, []string{"192.0.2.1"}},
	} {
		if _, err := makeToken(caDir, c.name, time.Hour, nil, c.types, c.domains, nil, nil); err == nil {
			t.Fatalf("makeToken %q %v %v succeeded, want an error", c.name, c.types, c.domains)
		}
	}

	// --ip takes addresses, kept as prefixes, prefixes, kept masked, and *.
	for _, ips := range [][]string{{"300.1.2.3"}, {"10.0.0.0/33"}, {"fe80::1%en0"}, {"example.com"}} {
		if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, nil, ips, nil); err == nil {
			t.Fatalf("makeToken --ip %v succeeded, want an error", ips)
		}
		if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"}, nil, ips); err == nil {
			t.Fatalf("makeToken --host %v succeeded, want an error", ips)
		}
	}
	if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"}, nil, []string{"*"}); err == nil {
		t.Fatal("makeToken --host * succeeded, want an error")
	}
	if _, err := makeToken(caDir, "scoped", time.Hour, []string{"admin"}, nil, nil, nil, nil); err == nil {
		t.Fatal("makeToken with an unknown scope succeeded, want an error")
	}
	if _, err := makeToken(caDir, "scoped", time.Hour, []string{"tokens"}, nil, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken with --domain without the scope sign succeeded, want an error")
	}
	for _, c := range []struct{ scopes, types []string }{
		{[]string{"*", "tokens"}, nil}, {nil, []string{"*", "server"}}, {[]string{"*"}, nil},
	} {
		if _, err := makeToken(caDir, "all", time.Hour, c.scopes, c.types, nil, nil, nil); err == nil {
			t.Fatalf("makeToken --scope %v --type %v succeeded, want an error", c.scopes, c.types)
		}
	}
	if _, err := makeToken(caDir, "all", time.Hour, []string{"*"}, []string{"*"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("makeToken --scope * --type *: %v", err)
	}
	if db, err := loadTokens(caDir); err != nil || !db.Tokens["all"].hasScope("certs") || !allows(db.Tokens["all"].Types, "user") {
		t.Fatalf("the token all: %+v, %v, want every scope and every type", db.Tokens["all"], err)
	}
	if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"},
		[]string{"192.0.2.10", "10.1.2.3/8", "2001:db8::/32", "*"}, nil); err != nil {
		t.Fatalf("makeToken with * and IP addresses: %v", err)
	}
	db, err = loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if ips := db.Tokens["ips"]; !slices.Equal(ips.IPs, []string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::/32", "*"}) ||
		!slices.Equal(ips.Domains, []string{"*"}) {
		t.Fatalf("token entry %+v, want the IP prefixes masked and the domain *", ips)
	}
	if err := revokeToken(caDir, "ips"); err != nil {
		t.Fatalf("revokeToken ips: %v", err)
	}

	var out bytes.Buffer
	if err := listTokens(&out, caDir); err != nil {
		t.Fatalf("listTokens: %v", err)
	}
	if !strings.Contains(out.String(), "deploy") || strings.Contains(out.String(), "(expired)") ||
		strings.Contains(out.String(), "STATUS") {
		t.Fatalf("token list output:\n%s\nwant the valid token deploy without a status", out.String())
	}
	if shown := showPrefixes([]string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::1/128", "2001:db8::/32", "*"}); !slices.Equal(shown,
		[]string{"192.0.2.10", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32", "*"}) {
		t.Fatalf("showPrefixes = %v, want single addresses without their prefix length", shown)
	}
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	if err := revokeToken(caDir, "deploy"); err == nil {
		t.Fatal("revoking twice succeeded, want an error")
	}
	if err := revokeToken(caDir, "nosuch"); err == nil {
		t.Fatal("revoking an unknown token succeeded, want an error")
	}
	// A revoked token is kept without its JWT ID, expired when it was revoked, holding its name
	// until it is purged.
	out.Reset()
	if err := listTokens(&out, caDir); err != nil || !strings.Contains(out.String(), "deploy  revoked  ") {
		t.Fatalf("token list output:\n%s\n%v, want the revoked token marked revoked, without a time", out.String(), err)
	}
	if db, err := loadTokens(caDir); err != nil || db.Tokens["deploy"] == nil || db.Tokens["deploy"].ID != "" ||
		time.Now().Before(db.Tokens["deploy"].Expires) || time.Since(db.Tokens["deploy"].Expires) > time.Minute {
		t.Fatalf("tokens after revoking: %v, want deploy kept without its JWT ID, expired when revoked", err)
	}
	if _, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken with the name of a revoked token succeeded, want an error")
	}
	if err := purgeToken(caDir, "deploy"); err != nil {
		t.Fatalf("purgeToken of the revoked token: %v", err)
	}
	if _, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("makeToken with the name of a purged token: %v", err)
	}
	if err := purgeToken(caDir, "deploy"); err == nil || !strings.Contains(err.Error(), "revoke it first") {
		t.Fatalf("purgeToken of a token still accepted: %v, want an error", err)
	}

	// A revoked token, without its expiry, is renewed for the default validity of token create.
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	if _, err := renewToken(caDir, "deploy", 0); err != nil {
		t.Fatalf("renewToken of the revoked token: %v", err)
	}
	if db, err := loadTokens(caDir); err != nil || db.Tokens["deploy"].revoked() ||
		db.Tokens["deploy"].Expires.Sub(db.Tokens["deploy"].Issued) != time.Hour {
		t.Fatalf("renewed revoked token %+v, %v, want it valid for an hour, not revoked", db.Tokens["deploy"], err)
	}
	if _, err := makeToken(caDir, "short", time.Millisecond, nil, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken valid for 1ms succeeded, want an error")
	}

	// purgeTokens removes the expired and revoked tokens alone.
	oldJWT, err := makeToken(caDir, "old", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken old: %v", err)
	}
	expire := func() string {
		t.Helper()
		db, err := loadTokens(caDir)
		if err != nil {
			t.Fatalf("loadTokens: %v", err)
		}
		expired := time.Now().Add(-time.Minute)
		db.Tokens["old"].Issued, db.Tokens["old"].Expires = expired.Add(-time.Hour), expired
		if err := db.save(caDir); err != nil {
			t.Fatalf("save: %v", err)
		}
		return db.Tokens["old"].ID
	}
	oldID := expire()
	out.Reset()
	if err := listTokens(&out, caDir); err != nil || !strings.Contains(out.String(), " UTC (expired)") {
		t.Fatalf("token list output:\n%s\n%v, want the expired token marked", out.String(), err)
	}

	// An expired token is kept for as long as it is to be kept, and renewed with a new JWT ID, valid
	// for as long as it was before and allowing what it allowed.
	if n, err := purgeTokens(caDir, time.Hour); err != nil || n != 0 {
		t.Fatalf("purgeTokens keeping an hour: %d, %v, want the token expired a minute ago kept", n, err)
	}
	renewed, err := renewToken(caDir, "old", 0)
	if err != nil {
		t.Fatalf("renewToken: %v", err)
	}
	db, err = loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if tok := db.Tokens["old"]; renewed == oldJWT || tok.ID == oldID || !time.Now().Before(tok.Expires) ||
		tok.Expires.Sub(tok.Issued) != time.Hour || !slices.Equal(tok.Domains, []string{"example.com"}) {
		t.Fatalf("renewed token %+v, want a new JWT and ID, valid for an hour from now, for example.com", tok)
	}
	if _, err := renewToken(caDir, "nowhere", 0); err == nil {
		t.Fatal("renewToken of a token that is not there succeeded")
	}
	expire()
	if n, err := purgeTokens(caDir, 0); err != nil || n != 2 {
		t.Fatalf("purgeTokens: %d, %v, want the expired token and the revoked ips removed", n, err)
	}
	if db, err := loadTokens(caDir); err != nil || !slices.Equal(slices.Sorted(maps.Keys(db.Tokens)), []string{"all", "deploy"}) {
		t.Fatalf("tokens after purging: %v, %v, want all and deploy, the tokens still accepted", slices.Sorted(maps.Keys(db.Tokens)), err)
	}
	if n, err := purgeTokens(t.TempDir(), 0); err != nil || n != 0 {
		t.Fatalf("purgeTokens without tokens-db.json: %d, %v, want 0", n, err)
	}

	// A held lock makes the commands wait and then fail, and its release lets them run.
	lockPath := filepath.Join(caDir, tokensFile+".lock")
	if fileExists(lockPath) {
		t.Fatalf("%s left after the commands", lockPath)
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		t.Fatalf("lockTokens: %v", err)
	}
	wait := tokensLockWait
	tokensLockWait = 200 * time.Millisecond
	t.Cleanup(func() { tokensLockWait = wait })
	if err := revokeToken(caDir, "deploy"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("locked by process %d", os.Getpid())) {
		t.Fatalf("revokeToken while locked: %v, want a lock error naming this process", err)
	}
	unlock()
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken after unlocking: %v", err)
	}
}

func TestAPISign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCA(caDir, "Plain CA", 3650, "plain-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA plain: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	token, err := makeToken(issuingDir, "deploy", time.Hour, nil, []string{"server", "user"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	rootToken, err := makeToken(caDir, "root", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken root: %v", err)
	}
	serverOnly, err := makeToken(issuingDir, "server-only", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken server-only: %v", err)
	}
	expired, err := makeToken(issuingDir, "expired", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken expired: %v", err)
	}
	revoked, err := makeToken(issuingDir, "revoked", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken revoked: %v", err)
	}
	if err := revokeToken(issuingDir, "revoked"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	webuiOnly, err := makeToken(issuingDir, "webui-only", time.Hour, []string{"tokens", "certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken webui-only: %v", err)
	}
	anyType, err := makeToken(issuingDir, "any-type", time.Hour, nil, []string{"*"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken any-type: %v", err)
	}
	if _, err := renewToken(issuingDir, "revoked", 0); err != nil {
		t.Fatalf("renewToken of the revoked token: %v", err)
	}
	db, err := loadTokens(issuingDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	db.Tokens["expired"].Expires = time.Now().Add(-time.Hour)
	if err := db.save(issuingDir); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, claims, _ := strings.Cut(token, ".")
	claims, _, _ = strings.Cut(claims, ".")
	algNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + claims + "."

	csr := func(name string, args ...string) string {
		path := filepath.Join(csrDir, name+".csr")
		out, err := exec.Command("openssl", append([]string{"req", "-new", "-newkey", "ec", "-pkeyopt",
			"ec_paramgen_curve:P-256", "-nodes", "-keyout", filepath.Join(csrDir, name+"_key.pem"), "-out", path}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl req: %v\n%s", err, out)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}
	web := csr("web", "-subj", "/CN=web.example.com", "-addext", "subjectAltName=DNS:web.example.com,DNS:*.web.example.com")
	alice := csr("alice", "-subj", "/CN=Alice Example/emailAddress=alice@example.com")
	outside := csr("outside", "-subj", "/CN=web.example.org")
	withIP := csr("ip", "-subj", "/CN=web.example.com", "-addext", "subjectAltName=IP:192.0.2.1")
	withO := csr("org", "-subj", "/O=Example/CN=web.example.com")

	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()
	post := func(path, token, contentType, body string) (int, map[string]string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]string
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	request := func(csr, certType string) string {
		if certType == "" {
			certType = "server"
		}
		b, _ := json.Marshal(map[string]any{"csr": csr, "type": certType, "name": "web", "days": 30})
		return string(b)
	}

	status, resp := post("/issuing-ca/api/sign", token, "application/json", request(web, ""))
	if status != http.StatusOK {
		t.Fatalf("signing web: %d %v", status, resp)
	}
	certPath := filepath.Join(csrDir, "web_cert.pem")
	if err := os.WriteFile(certPath, []byte(resp["certificate"]), 0o644); err != nil {
		t.Fatal(err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(cert.DNSNames, []string{"web.example.com", "*.web.example.com"}) || resp["serial"] != serialHex(cert.SerialNumber) {
		t.Fatalf("DNS names %v, serial %s, want those of the request and the certificate", cert.DNSNames, resp["serial"])
	}
	if strings.Count(resp["chain"], "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("chain:\n%s\nwant the certificate and the issuing CA", resp["chain"])
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 1 || entries[0].serial != resp["serial"] {
		t.Fatalf("index.txt %+v, %v, want the issued certificate", entries, err)
	}
	if db, err := loadTokens(issuingDir); err != nil || !slices.Equal(db.Tokens["deploy"].Certs, []string{resp["serial"]}) {
		t.Fatalf("certs of the token: %v, want the issued certificate", err)
	}

	status, resp = post("/issuing-ca/api/sign", token, "application/json", request(alice, "user"))
	if status != http.StatusOK {
		t.Fatalf("signing alice: %d %v", status, resp)
	}
	status, resp = post("/api/sign", rootToken, "application/json", request(web, ""))
	if status != http.StatusOK || strings.Count(resp["chain"], "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("signing with the root CA: %d %v, want the certificate alone in the chain", status, resp)
	}

	for _, c := range []struct {
		name, path, token, contentType, body string
		want                                 int
	}{
		{"no token", "/issuing-ca/api/sign", "", "application/json", request(web, ""), http.StatusUnauthorized},
		{"other CA token", "/issuing-ca/api/sign", rootToken, "application/json", request(web, ""), http.StatusUnauthorized},
		{"expired token", "/issuing-ca/api/sign", expired, "application/json", request(web, ""), http.StatusUnauthorized},
		{"revoked token", "/issuing-ca/api/sign", revoked, "application/json", request(web, ""), http.StatusUnauthorized},
		{"alg none", "/issuing-ca/api/sign", algNone, "application/json", request(web, ""), http.StatusUnauthorized},
		{"garbage token", "/issuing-ca/api/sign", "abc", "application/json", request(web, ""), http.StatusUnauthorized},
		{"name outside", "/issuing-ca/api/sign", token, "application/json", request(outside, ""), http.StatusForbidden},
		{"IP SAN", "/issuing-ca/api/sign", token, "application/json", request(withIP, ""), http.StatusForbidden},
		{"O attribute", "/issuing-ca/api/sign", token, "application/json", request(withO, ""), http.StatusForbidden},
		{"email in server", "/issuing-ca/api/sign", token, "application/json", request(alice, "server"), http.StatusForbidden},
		{"DNS in user", "/issuing-ca/api/sign", token, "application/json", request(web, "user"), http.StatusForbidden},
		{"type not allowed", "/issuing-ca/api/sign", serverOnly, "application/json", request(alice, "user"), http.StatusForbidden},
		{"no scope sign", "/issuing-ca/api/sign", webuiOnly, "application/json", request(web, ""), http.StatusForbidden},
		{"type * passes", "/issuing-ca/api/sign", anyType, "application/json", request(web, "nonexistent"), http.StatusBadRequest},
		{"bad csr", "/issuing-ca/api/sign", token, "application/json", request("nonsense", ""), http.StatusBadRequest},
		{"unknown field", "/issuing-ca/api/sign", token, "application/json", `{"csr":"x","days":5}`, http.StatusBadRequest},
		{"content type", "/issuing-ca/api/sign", token, "text/plain", request(web, ""), http.StatusUnsupportedMediaType},
		{"no tokens", "/plain-ca/api/sign", token, "application/json", request(web, ""), http.StatusNotFound},
		{"no CA", "/nosuch/api/sign", token, "application/json", request(web, ""), http.StatusNotFound},
	} {
		if status, resp := post(c.path, c.token, c.contentType, c.body); status != c.want {
			t.Fatalf("%s: status %d %v, want %d", c.name, status, resp, c.want)
		}
	}
	if _, resp := post("/issuing-ca/api/sign", serverOnly, "application/json", request(alice, "user")); resp["error"] !=
		"the token does not allow the type 'user'; choose a type it allows, server, or the default, its first type" {
		t.Errorf("type not allowed: %v, want the types the token allows", resp)
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 2 {
		t.Fatalf("index.txt %+v, %v, want the two certificates issued", entries, err)
	}

	form, err := http.Get(server.URL + "/issuing-ca/sign")
	if err != nil {
		t.Fatal(err)
	}
	formPage, _ := io.ReadAll(form.Body)
	form.Body.Close()
	if form.StatusCode != http.StatusOK || !strings.Contains(string(formPage), `action="/issuing-ca/sign"`) ||
		!strings.Contains(string(formPage), `type="password"`) ||
		!strings.Contains(string(formPage), `<option value="">Default: the token's first type</option>`) ||
		!strings.Contains(string(formPage), `<option value="server">server: TLS server and TLS client</option>`) ||
		!strings.Contains(string(formPage), `<option value="none">none: no key usages</option>`) {
		t.Fatalf("GET /issuing-ca/sign: %d\n%s\nwant the form, its types described", form.StatusCode, formPage)
	}
	signed, err := http.PostForm(server.URL+"/issuing-ca/sign", url.Values{"csr": {web}, "token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	download, _ := io.ReadAll(signed.Body)
	signed.Body.Close()
	if signed.StatusCode != http.StatusOK || signed.Header.Get("Content-Disposition") != "attachment; filename=web_cert.pem" {
		t.Fatalf("POST /issuing-ca/sign: %d %q, want web_cert.pem as a download", signed.StatusCode, signed.Header.Get("Content-Disposition"))
	}
	if err := os.WriteFile(certPath, download, 0o644); err != nil {
		t.Fatal(err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	refused, err := http.PostForm(server.URL+"/issuing-ca/sign", url.Values{"csr": {outside}, "token": {revoked}, "type": {"user"}})
	if err != nil {
		t.Fatal(err)
	}
	refusedPage, _ := io.ReadAll(refused.Body)
	refused.Body.Close()
	if refused.StatusCode != http.StatusUnauthorized || !strings.Contains(string(refusedPage), "unknown token") ||
		!strings.Contains(string(refusedPage), "<option value=\"user\" selected>") {
		t.Fatalf("POST with a revoked token: %d\n%s\nwant the form with the error and the type kept", refused.StatusCode, refusedPage)
	}
	noForm, err := http.Get(server.URL + "/plain-ca/sign")
	if err != nil {
		t.Fatal(err)
	}
	noFormPage, _ := io.ReadAll(noForm.Body)
	noForm.Body.Close()
	if noForm.StatusCode != http.StatusOK || !strings.Contains(string(noFormPage), "has no tokens yet") ||
		strings.Contains(string(noFormPage), "<form") {
		t.Fatalf("GET /plain-ca/sign: %d\n%s\nwant the page saying the CA has no tokens", noForm.StatusCode, noFormPage)
	}
	noTokens, err := http.PostForm(server.URL+"/plain-ca/sign", url.Values{"csr": {web}, "token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	noTokens.Body.Close()
	if noTokens.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /plain-ca/sign: %d, want 403", noTokens.StatusCode)
	}
	if noCA, err := http.Get(server.URL + "/nosuch/sign"); err != nil || noCA.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nosuch/sign: %v %v, want 404", noCA.StatusCode, err)
	}

	resp2, err := http.Get(server.URL + "/api/sign")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/sign: %d, want 405", resp2.StatusCode)
	}
	page, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(body), server.URL+"/issuing-ca/api/sign") || strings.Contains(string(body), "/plain-ca/api/sign") {
		t.Fatalf("index page does not show the signing API of the CAs with tokens alone")
	}

	// A domain * allows any name, and --ip prefixes or * allow IP addresses, of the SANs and the CN.
	anyName, err := makeToken(issuingDir, "any-name", time.Hour, nil, []string{"server"}, []string{"*"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken any-name: %v", err)
	}
	ipRange, err := makeToken(issuingDir, "ip-range", time.Hour, nil, []string{"server"}, nil, []string{"10.0.0.0/8", "2001:db8::/32"}, nil)
	if err != nil {
		t.Fatalf("makeToken ip-range: %v", err)
	}
	lab, err := makeToken(issuingDir, "lab", time.Hour, nil, []string{"server"}, []string{"*"}, []string{"*"}, nil)
	if err != nil {
		t.Fatalf("makeToken lab: %v", err)
	}
	ipOnly := csr("ip-only", "-subj", "/CN=10.1.2.3", "-addext", "subjectAltName=IP:10.1.2.3,IP:2001:db8::5")
	ipOutside := csr("ip-outside", "-subj", "/CN=10.1.2.3", "-addext", "subjectAltName=IP:192.0.2.9")
	for _, c := range []struct {
		name, token, csr string
		want             int
	}{
		{"any name, another domain", anyName, outside, http.StatusOK},
		{"any name, an IP SAN", anyName, withIP, http.StatusForbidden},
		{"IP range, IP CN and SANs", ipRange, ipOnly, http.StatusOK},
		{"IP range, an IP outside", ipRange, ipOutside, http.StatusForbidden},
		{"IP range, a DNS name", ipRange, web, http.StatusForbidden},
		{"lab, DNS and IP", lab, withIP, http.StatusOK},
	} {
		status, resp := post("/issuing-ca/api/sign", c.token, "application/json", request(c.csr, ""))
		if status != c.want {
			t.Fatalf("%s: status %d %v, want %d", c.name, status, resp, c.want)
		}
		if c.csr == ipOnly && status == http.StatusOK {
			block, _ := pem.Decode([]byte(resp["certificate"]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || len(cert.IPAddresses) != 2 || cert.IPAddresses[0].String() != "10.1.2.3" ||
				cert.IPAddresses[1].String() != "2001:db8::5" {
				t.Fatalf("IP SANs of the certificate: %v, %v, want those of the request", cert.IPAddresses, err)
			}
		}
	}

	// token create --localhost allows localhost and 127.0.0.1; --host and --network limit the
	// clients, which are 127.0.0.1 for the test server.
	for _, args := range [][]string{
		{"--localhost", "--host", "127.0.0.1", "localhost-here"},
		{"--localhost", "--network", "192.0.2.0/24, 198.51.100.0/24", "localhost-elsewhere"},
	} {
		if err := run(append([]string{"token", "create", "--ca-dir", issuingDir}, args...)); err != nil {
			t.Fatalf("token create %v: %v", args, err)
		}
	}
	db, err = loadTokens(issuingDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if tok := db.Tokens["localhost-elsewhere"]; !slices.Equal(tok.Domains, []string{"localhost"}) ||
		!slices.Equal(tok.IPs, []string{"127.0.0.1/32"}) ||
		!slices.Equal(tok.Clients, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("token entry %+v, want localhost, 127.0.0.1 and the two client prefixes", tok)
	}
	local := csr("localhost", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	for _, c := range []struct {
		name    string
		clients []string
		want    int
	}{
		{"here", []string{"127.0.0.1"}, http.StatusOK},
		{"elsewhere", []string{"192.0.2.0/24"}, http.StatusForbidden},
	} {
		token, err := makeToken(issuingDir, c.name, time.Hour, nil, []string{"server"}, []string{"localhost"},
			[]string{"127.0.0.1"}, c.clients)
		if err != nil {
			t.Fatalf("makeToken %s: %v", c.name, err)
		}
		status, resp := post("/issuing-ca/api/sign", token, "application/json", request(local, ""))
		if status != c.want || (c.want == http.StatusForbidden && resp["error"] != "the token is not allowed from 127.0.0.1") {
			t.Fatalf("localhost certificate with clients %v: %d %v, want %d", c.clients, status, resp, c.want)
		}
	}

	// Behind a trusted proxy, the client is the one its X-Forwarded-For names; the header of a
	// peer that is not trusted is not read.
	proxied, err := makeToken(issuingDir, "proxied", time.Hour, nil, []string{"server"}, []string{"localhost"},
		[]string{"127.0.0.1"}, []string{"192.0.2.50"})
	if err != nil {
		t.Fatalf("makeToken proxied: %v", err)
	}
	t.Cleanup(func() { trustedProxies = nil })
	for _, c := range []struct {
		trusted   bool
		forwarded string
		want      int
	}{
		{true, "192.0.2.50", http.StatusOK},
		{true, "", http.StatusForbidden},
		{true, "192.0.2.51", http.StatusForbidden},
		{false, "192.0.2.50", http.StatusForbidden},
	} {
		trustedProxies = nil
		if c.trusted {
			trustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/issuing-ca/api/sign", strings.NewReader(request(local, "")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+proxied)
		if c.forwarded != "" {
			req.Header.Set("X-Forwarded-For", c.forwarded)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("X-Forwarded-For %q, proxy trusted %t: %d, want %d", c.forwarded, c.trusted, resp.StatusCode, c.want)
		}
	}
}

func TestTokenDefaults(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	write := func(tokens string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"tokens": `+tokens+`}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(name string) *apiToken {
		t.Helper()
		db, err := loadTokens(caDir)
		if err != nil || db.Tokens[name] == nil {
			t.Fatalf("token %s: %v", name, err)
		}
		return db.Tokens[name]
	}
	write(`{"valid": "8h", "types": ["server"], "domains": ["*"], "ips": ["10.0.0.0/8"], "localhost": true,
		"hosts": ["192.168.1.4"], "networks": ["172.16.0.0/12"]}`)

	// Without options, every setting is the default of simple-ca.json.
	if err := run([]string{"token", "create", "--ca-dir", caDir, "defaults"}); err != nil {
		t.Fatalf("token create with the defaults: %v", err)
	}
	tok := entry("defaults")
	if tok.Expires.Sub(tok.Issued) != 8*time.Hour || !slices.Equal(tok.Domains, []string{"*", "localhost"}) ||
		!slices.Equal(tok.IPs, []string{"10.0.0.0/8", "127.0.0.1/32"}) ||
		!slices.Equal(tok.Clients, []string{"192.168.1.4/32", "172.16.0.0/12"}) {
		t.Fatalf("token from the defaults %+v", tok)
	}

	// An option replaces its default; --network replaces hosts and networks together.
	if err := run([]string{"token", "create", "--ca-dir", caDir, "--valid", "30m", "--domain", "example.com",
		"--network", "10.1.0.0/16", "--localhost=false", "options"}); err != nil {
		t.Fatalf("token create with options: %v", err)
	}
	tok = entry("options")
	if tok.Expires.Sub(tok.Issued) != 30*time.Minute || !slices.Equal(tok.Domains, []string{"example.com"}) ||
		!slices.Equal(tok.IPs, []string{"10.0.0.0/8"}) || !slices.Equal(tok.Clients, []string{"10.1.0.0/16"}) {
		t.Fatalf("token with options %+v", tok)
	}

	write(`{"valid": "8 hours", "domains": ["example.com"]}`)
	if err := run([]string{"token", "create", "--ca-dir", caDir, "bad"}); err == nil || !strings.Contains(err.Error(), "tokens.valid") {
		t.Fatalf("token create with tokens.valid \"8 hours\": %v, want an error naming tokens.valid", err)
	}
	if err := run([]string{"token", "create", "--ca-dir", caDir, "--valid", "1h", "good"}); err != nil {
		t.Fatalf("token create with --valid over a bad tokens.valid: %v", err)
	}
}

func TestSetupCode(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")

	// A token with a setup code is pending: it has no JWT, refuses renewal, and lists its code.
	if _, err := addToken(issuingDir, "bad", nil, time.Hour, nil, nil, []string{"example.com"}, nil, nil, 0, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("addToken with --otc-network without --otc succeeded, want an error")
	}
	code, err := addToken(issuingDir, "remote", nil, 8*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	if ok, _ := regexp.MatchString(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`, code); !ok {
		t.Fatalf("setup code %q, want four groups of four base32 characters", code)
	}
	db, err := loadTokens(issuingDir)
	if err != nil || !db.Tokens["remote"].pending() || db.Tokens["remote"].revoked() || db.Tokens["remote"].ID != "" ||
		db.Tokens["remote"].Setup.Code != setupCodeHash(code) {
		t.Fatalf("the pending token: %+v, %v, want a setup code and no JWT ID", db.Tokens["remote"], err)
	}
	if _, err := renewToken(issuingDir, "remote", 0); err == nil {
		t.Fatal("renewToken of a pending token succeeded, want an error")
	}
	var b strings.Builder
	if err := listTokens(&b, issuingDir); err != nil || !strings.Contains(b.String(), "setup until ") {
		t.Fatalf("listTokens: %v\n%s, want the setup code of remote", err, b.String())
	}

	// The code is exchanged once, in any letter case and without dashes, for a JWT that signs.
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()
	exchange := func(code string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Post(server.URL+"/api/token-setup", "application/json", strings.NewReader(`{"code": "`+code+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	status, answer := exchange(strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if status != http.StatusOK || answer["ca"] != "issuing-ca" || answer["name"] != "remote" ||
		fmt.Sprint(answer["scopes"]) != "[sign]" {
		t.Fatalf("exchange: %d %v, want the token remote of issuing-ca, with the scope sign", status, answer)
	}
	caCert, err := loadCert(filepath.Join(issuingDir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	db, _ = loadTokens(issuingDir)
	if name, tok, err := checkToken(db, caCert, fmt.Sprint(answer["token"])); err != nil || name != "remote" || tok.pending() ||
		tok.Expires.Sub(tok.Issued) != 8*time.Hour {
		t.Fatalf("the exchanged token: %s %+v %v, want remote, valid for 8h from the exchange", name, tok, err)
	}
	if status, _ := exchange(code); status != http.StatusUnauthorized {
		t.Errorf("exchanging a used code: %d, want 401", status)
	}
	if status, _ := exchange("AAAA-BBBB-CCCC-DDDD"); status != http.StatusUnauthorized {
		t.Errorf("exchanging an unknown code: %d, want 401", status)
	}

	// A code is refused from a client outside its networks and once it has expired, and a pending
	// token is no JWT of the signing API.
	far, err := addToken(caDir, "far", nil, time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("addToken --otc-network: %v", err)
	}
	if status, _ := exchange(far); status != http.StatusForbidden {
		t.Errorf("exchanging from outside --otc-network: %d, want 403", status)
	}
	late, err := addToken(caDir, "late", nil, time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Second, nil)
	if err != nil {
		t.Fatalf("addToken --otc-valid 1s: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if status, answer := exchange(late); status != http.StatusUnauthorized || answer["error"] != "the setup code has expired" {
		t.Errorf("exchanging an expired code: %d %v, want 401, expired", status, answer)
	}
	if n, err := purgeTokens(caDir, 0); err != nil || n != 1 {
		t.Errorf("purgeTokens: %d, %v, want the expired setup code removed", n, err)
	}
	db, _ = loadTokens(caDir)
	if _, _, err := lookupToken(db, &jwtClaims{Subject: "far"}); err == nil {
		t.Error("lookupToken of a pending token with an empty JWT ID succeeded, want an error")
	}

	// A token whose code has expired is renewed with a new code, keeping its own validity.
	if _, err := addToken(caDir, "again", nil, 3*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Second, nil); err != nil {
		t.Fatalf("addToken --otc-valid 1s: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	fresh, err := reissueToken(caDir, "again", 0, time.Hour, nil)
	if err != nil {
		t.Fatalf("reissueToken of an expired setup code: %v", err)
	}
	if status, _ := exchange(fresh); status != http.StatusOK {
		t.Errorf("exchanging the new code: %d, want 200", status)
	}
	db, _ = loadTokens(caDir)
	if tok := db.Tokens["again"]; tok.Expires.Sub(tok.Issued) != 3*time.Hour {
		t.Errorf("the token of the new code is valid for %s, want 3h", tok.Expires.Sub(tok.Issued))
	}

	// A token renewed with a setup code waits for it again: its JWT is refused at once, and the
	// code gives it a new one.
	if _, err := reissueToken(issuingDir, "remote", 0, 0, []string{"10.0.0.0/8"}); err == nil {
		t.Error("reissueToken with --otc-network without --otc succeeded, want an error")
	}
	renewed, err := reissueToken(issuingDir, "remote", 0, time.Hour, nil)
	if err != nil {
		t.Fatalf("reissueToken --otc: %v", err)
	}
	db, _ = loadTokens(issuingDir)
	if _, _, err := checkToken(db, caCert, fmt.Sprint(answer["token"])); err == nil || !db.Tokens["remote"].pending() {
		t.Error("the JWT of a token renewed with a setup code is accepted, want it refused")
	}
	if status, again := exchange(renewed); status != http.StatusOK || again["name"] != "remote" || again["token"] == answer["token"] {
		t.Errorf("exchanging the code of a renewed token: %d %v, want a new JWT of remote", status, again)
	}

	// The signing form takes a setup code for one certificate: a refused request leaves the code,
	// a signed one revokes its token; /api/sign takes no code.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrFor := func(name string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	once, err := addToken(issuingDir, "once", nil, time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	client := netip.MustParseAddr("127.0.0.1")
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", "", 0, nil, nil, false); err == nil {
		t.Error("signWithToken of a setup code without setupCodes succeeded, want an error")
	}
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.org"), "", "", 0, nil, nil, true); err == nil {
		t.Error("signWithToken of a setup code for a name the token does not allow succeeded, want an error")
	}
	cert, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", "", 0, nil, nil, true)
	if err != nil {
		t.Fatalf("signWithToken of a setup code: %v", err)
	}
	db, _ = loadTokens(issuingDir)
	if tok := db.Tokens["once"]; !tok.revoked() || !slices.Equal(tok.Certs, []string{serialHex(cert.SerialNumber)}) {
		t.Errorf("the token of the setup code: %+v, want it revoked, with the certificate", tok)
	}
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", "", 0, nil, nil, true); err == nil {
		t.Error("signWithToken of a used setup code succeeded, want an error")
	}

	// The setup code page exchanges a code once.
	page, err := addToken(caDir, "page", nil, time.Hour, []string{"tokens"}, nil, nil, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	for _, c := range []struct {
		want int
		text string
	}{{http.StatusOK, "Your token <strong>page</strong>"}, {http.StatusUnauthorized, "unknown or used setup code"}} {
		resp, err := http.PostForm(server.URL+"/token-setup", url.Values{"code": {page}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want || !strings.Contains(string(body), c.text) {
			t.Errorf("POST /token-setup: %d, want %d with %q", resp.StatusCode, c.want, c.text)
		}
	}

	// A token is described with its limits from tokens-db.json, and a JWT read without its CA
	// with what it holds alone.
	pendingCode, err := addToken(caDir, "pending", nil, 8*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour,
		[]string{"10.0.0.0/8"})
	if err != nil || pendingCode == "" {
		t.Fatalf("addToken --otc: %v", err)
	}
	db, _ = loadTokens(caDir)
	described := fmt.Sprint(describeToken("pending", db.Tokens["pending"], true))
	for _, s := range []string{"[Status waits for its setup code", "[Domains example.com]", "[Code usable from 10.0.0.0/8]",
		"[Valid after the exchange 8h]"} {
		if !strings.Contains(described, s) {
			t.Errorf("describeToken of a pending token: %s, want %q", described, s)
		}
	}
	jwt, err := makeToken(caDir, "held", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	c, err := verifyJWT(nil, jwt)
	if err != nil || c.Subject != "held" || c.Scope != "certs" {
		t.Fatalf("verifyJWT without a CA: %+v, %v, want the claims of held", c, err)
	}
	if described := fmt.Sprint(describeToken(c.Subject, &apiToken{Scopes: strings.Fields(c.Scope)}, false)); strings.Contains(described, "Used from") {
		t.Errorf("describeToken without limits: %s, want no limits", described)
	}
}

func TestTokenAccessAcrossCAs(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	cas := []string{"", "servers", "clients", "devices"}
	for _, id := range cas[1:] {
		if err := makeCA(rootDir, "CA "+id, 3650, id, "", "rsa"); err != nil {
			t.Fatalf("makeCA %s: %v", id, err)
		}
	}
	label := func(id string) string {
		if id == "" {
			return "root"
		}
		return id
	}
	path := func(id string) string {
		if id == "" {
			return ""
		}
		return "/" + id
	}
	caCerts := map[string]*x509.Certificate{}
	for _, id := range cas {
		cert, err := loadCert(filepath.Join(rootDir, id, "ca_cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		caCerts[id] = cert
	}

	// Every CA has tokens of the same four names, so a name of one CA never opens another.
	names := []string{"signer", "keeper", "operator", "master"}
	scopesOf := map[string][]string{"signer": {"sign"}, "keeper": {"tokens"}, "operator": {"certs"}, "master": {"*"}}
	has := func(name, scope string) bool { return allows(scopesOf[name], scope) }
	jwts := map[string]map[string]string{}
	for _, id := range cas {
		jwts[id] = map[string]string{}
		for _, name := range names {
			var types, domains []string
			if has(name, "sign") {
				types, domains = []string{"server"}, []string{"example.com"}
			}
			jwt, err := makeToken(filepath.Join(rootDir, id), name, time.Hour, scopesOf[name], types, domains, nil, nil)
			if err != nil {
				t.Fatalf("makeToken %s of %s: %v", name, label(id), err)
			}
			jwts[id][name] = jwt
		}
	}

	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	do := func(method, target, token, contentType, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
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
	call := func(token, method, target string, body any) (int, map[string]any) {
		t.Helper()
		b := ""
		if body != nil {
			j, _ := json.Marshal(body)
			b = string(j)
		}
		return do(method, target, token, "application/json", b)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	signBody := map[string]any{"csr": csr, "type": "server", "name": "web", "days": 30}
	apiSignStatus := func(token, target string) int {
		t.Helper()
		status, answer := call(token, "POST", path(target)+"/api/sign", signBody)
		if status == http.StatusOK {
			block, _ := pem.Decode(fmt.Append(nil, answer["certificate"]))
			if block == nil {
				t.Errorf("POST %s/api/sign: no certificate in %v", path(target), answer)
				return status
			}
			if cert, err := x509.ParseCertificate(block.Bytes); err != nil || cert.CheckSignatureFrom(caCerts[target]) != nil {
				t.Errorf("POST %s/api/sign: a certificate not signed by the CA %s: %v", path(target), label(target), err)
			}
		}
		return status
	}
	formSignStatus := func(token, target string) int {
		t.Helper()
		resp, err := http.PostForm(server.URL+path(target)+"/sign", url.Values{"token": {token}, "csr": {csr}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") != "application/x-pem-file" {
			t.Errorf("POST %s/sign: %s, want a certificate", path(target), resp.Header.Get("Content-Type"))
		}
		return resp.StatusCode
	}

	// The signing API and the signing form of a CA take a token of that CA with the scope sign
	// alone; a token of another CA is unknown to them, whatever its name.
	for _, owner := range cas {
		for _, name := range names {
			for _, target := range cas {
				want := http.StatusUnauthorized
				if owner == target {
					want = http.StatusForbidden
					if has(name, "sign") {
						want = http.StatusOK
					}
				}
				if status := apiSignStatus(jwts[owner][name], target); status != want {
					t.Errorf("POST %s/api/sign with %s of %s: %d, want %d", path(target), name, label(owner), status, want)
				}
				if status := formSignStatus(jwts[owner][name], target); status != want {
					t.Errorf("POST %s/sign with %s of %s: %d, want %d", path(target), name, label(owner), status, want)
				}
			}
		}
	}

	// The token and certificate pages take a token of any CA with their scope: a root CA token
	// opens every CA, and an issuing CA token its own CA alone.
	for _, page := range []struct{ prefix, scope, list string }{{"/tokens", "tokens", "/api/tokens"}, {"/certificates", "certs", "/api/certs"}} {
		for _, owner := range cas {
			for _, name := range names {
				token, who := jwts[owner][name], name+" of "+label(owner)
				status, answer := call(token, "GET", page.prefix+"/api/cas", nil)
				if !has(name, page.scope) {
					if status != http.StatusForbidden || !strings.Contains(fmt.Sprint(answer["error"]), "scope "+page.scope) {
						t.Errorf("GET %s/api/cas with %s: %d %v, want 403 naming the scope", page.prefix, who, status, answer)
					}
				} else {
					var ids []string
					list, _ := answer["cas"].([]any)
					for _, ca := range list {
						ids = append(ids, fmt.Sprint(ca.(map[string]any)["id"]))
					}
					want := []string{owner}
					if owner == "" {
						want = []string{"", "clients", "devices", "servers"}
					}
					if status != http.StatusOK || !slices.Equal(ids, want) || answer["user"] != name || answer["user_ca"] != owner {
						t.Errorf("GET %s/api/cas with %s: %d %v, want the CAs %q", page.prefix, who, status, answer, want)
					}
				}
				for _, target := range cas {
					want := http.StatusForbidden
					if has(name, page.scope) {
						want = http.StatusNotFound
						if owner == "" || owner == target {
							want = http.StatusOK
						}
					}
					if status, answer := call(token, "GET", page.prefix+page.list+"?ca="+target, nil); status != want {
						t.Errorf("GET %s%s?ca=%s with %s: %d %v, want %d", page.prefix, page.list, target, who, status, answer, want)
					}

					// A change of a CA is refused alike; a token made on the token page is signed by the
					// key of its CA, whichever CA the token of the request belongs to.
					wantChange := want
					if page.scope == "tokens" {
						made := "made-" + name + "-of-" + label(owner) + "-in-" + label(target)
						if want == http.StatusOK {
							wantChange = http.StatusCreated
						}
						status, answer := call(token, "POST", "/tokens/api/tokens",
							map[string]any{"ca": target, "name": made, "valid": "1h", "scopes": []string{"sign"},
								"types": []string{"server"}, "domains": []string{"example.com"}})
						if status != wantChange {
							t.Errorf("creating %s in %s with %s: %d %v, want %d", made, label(target), who, status, answer, wantChange)
							continue
						}
						if status == http.StatusCreated {
							for _, id := range cas {
								if _, err := verifyJWT(caCerts[id], fmt.Sprint(answer["token"])); (err == nil) != (id == target) {
									t.Errorf("the token %s verifies with the CA %s: %v, want it signed by %s alone", made, label(id), err == nil, label(target))
								}
							}
						}
					} else if status, answer := call(token, "POST", "/certificates/api/crl", map[string]any{"ca": target, "days": 7}); status != wantChange {
						t.Errorf("POST /certificates/api/crl of %s with %s: %d %v, want %d", label(target), who, status, answer, wantChange)
					}
				}
			}
		}
	}

	// A root CA token manages the tokens of an issuing CA; an issuing CA token those of no other
	// CA. A revoked token of one CA leaves the token of the same name of another CA working.
	if status, answer := call(jwts["servers"]["keeper"], "POST", "/tokens/api/tokens/revoke",
		map[string]any{"ca": "clients", "name": "signer"}); status != http.StatusNotFound {
		t.Errorf("revoking signer of clients with keeper of servers: %d %v, want 404", status, answer)
	}
	if status, answer := call(jwts["servers"]["keeper"], "POST", "/tokens/api/tokens/purge", map[string]any{"ca": ""}); status != http.StatusNotFound {
		t.Errorf("purging the tokens of the root CA with keeper of servers: %d %v, want 404", status, answer)
	}
	if status, answer := call(jwts[""]["keeper"], "POST", "/tokens/api/tokens/renew",
		map[string]any{"ca": "servers", "name": "master", "valid": "1h"}); status != http.StatusForbidden {
		t.Errorf("renewing master of servers with keeper of root: %d %v, want 403, a scope keeper lacks", status, answer)
	}
	if status, answer := call(jwts[""]["keeper"], "POST", "/tokens/api/tokens/revoke",
		map[string]any{"ca": "servers", "name": "signer"}); status != http.StatusOK {
		t.Fatalf("revoking signer of servers with keeper of root: %d %v, want 200", status, answer)
	}
	if status := apiSignStatus(jwts["servers"]["signer"], "servers"); status != http.StatusUnauthorized {
		t.Errorf("POST /servers/api/sign with the revoked signer of servers: %d, want 401", status)
	}
	for _, id := range []string{"", "clients", "devices"} {
		if status := apiSignStatus(jwts[id]["signer"], id); status != http.StatusOK {
			t.Errorf("POST %s/api/sign with signer of %s after revoking signer of servers: %d, want 200", path(id), label(id), status)
		}
	}
	if status, answer := call(jwts[""]["master"], "POST", "/tokens/api/tokens/renew",
		map[string]any{"ca": "devices", "name": "keeper", "valid": "1h"}); status != http.StatusOK {
		t.Fatalf("renewing keeper of devices with master of root: %d %v, want 200", status, answer)
	} else {
		if status, _ := call(jwts["devices"]["keeper"], "GET", "/tokens/api/cas", nil); status != http.StatusUnauthorized {
			t.Errorf("GET /tokens/api/cas with the JWT of keeper of devices before its renewal: %d, want 401", status)
		}
		if status, answer := call(fmt.Sprint(answer["token"]), "GET", "/tokens/api/cas", nil); status != http.StatusOK || answer["user_ca"] != "devices" {
			t.Errorf("GET /tokens/api/cas with the renewed keeper of devices: %d %v, want devices", status, answer)
		}
	}

	// A setup code is exchanged for a token of its own CA, and the signing form of a CA takes the
	// codes of that CA alone; the signing API and the pages take no code.
	codes := map[string]string{}
	for _, id := range cas[1:] {
		code, err := addToken(filepath.Join(rootDir, id), "remote", nil, time.Hour, nil, []string{"server"}, []string{"example.com"},
			nil, nil, time.Hour, nil)
		if err != nil {
			t.Fatalf("addToken --otc in %s: %v", id, err)
		}
		codes[id] = code
	}
	status, answer := call("", "POST", "/api/token-setup", map[string]string{"code": codes["servers"]})
	if status != http.StatusOK || answer["ca"] != "servers" || answer["name"] != "remote" {
		t.Fatalf("exchanging the code of servers: %d %v, want remote of servers", status, answer)
	}
	for _, target := range cas {
		want := http.StatusUnauthorized
		if target == "servers" {
			want = http.StatusOK
		}
		if status := apiSignStatus(fmt.Sprint(answer["token"]), target); status != want {
			t.Errorf("POST %s/api/sign with remote of servers from its code: %d, want %d", path(target), status, want)
		}
	}
	for _, target := range []string{"", "servers", "devices"} {
		if status := formSignStatus(codes["clients"], target); status != http.StatusUnauthorized {
			t.Errorf("POST %s/sign with the code of clients: %d, want 401", path(target), status)
		}
	}
	if status := apiSignStatus(codes["clients"], "clients"); status != http.StatusUnauthorized {
		t.Errorf("POST /clients/api/sign with the code of clients: %d, want 401", status)
	}
	for _, prefix := range []string{"/tokens", "/certificates"} {
		if status, _ := call(codes["clients"], "GET", prefix+"/api/cas", nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s/api/cas with the code of clients: %d, want 401", prefix, status)
		}
	}
	if status := formSignStatus(codes["clients"], "clients"); status != http.StatusOK {
		t.Errorf("POST /clients/sign with the code of clients: %d, want 200", status)
	}
	if status, answer := call("", "POST", "/api/token-setup", map[string]string{"code": codes["clients"]}); status != http.StatusUnauthorized {
		t.Errorf("exchanging the code of clients used on its signing form: %d %v, want 401", status, answer)
	}

	// A token used from a client it does not allow is refused by every path.
	far, err := makeToken(filepath.Join(rootDir, "devices"), "far", time.Hour, []string{"*"}, []string{"server"},
		[]string{"example.com"}, nil, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("makeToken --network: %v", err)
	}
	if status := apiSignStatus(far, "devices"); status != http.StatusForbidden {
		t.Errorf("POST /devices/api/sign from outside the networks of the token: %d, want 403", status)
	}
	if status := formSignStatus(far, "devices"); status != http.StatusForbidden {
		t.Errorf("POST /devices/sign from outside the networks of the token: %d, want 403", status)
	}
	for _, prefix := range []string{"/tokens", "/certificates"} {
		if status, _ := call(far, "GET", prefix+"/api/cas", nil); status != http.StatusForbidden {
			t.Errorf("GET %s/api/cas from outside the networks of the token: %d, want 403", prefix, status)
		}
	}

	// A JWT with a changed payload or header, or without a signature, is invalid everywhere.
	parts := strings.Split(jwts["clients"]["signer"], ".")
	var claims map[string]any
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["scope"] = "*"
	widened, _ := json.Marshal(claims)
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	for what, forged := range map[string]string{
		"a widened scope":    parts[0] + "." + base64.RawURLEncoding.EncodeToString(widened) + "." + parts[2],
		"the algorithm none": none + "." + parts[1] + ".",
		"no signature":       parts[0] + "." + parts[1] + ".",
	} {
		if status := apiSignStatus(forged, "clients"); status != http.StatusUnauthorized {
			t.Errorf("POST /clients/api/sign with %s: %d, want 401", what, status)
		}
		for _, prefix := range []string{"/tokens", "/certificates"} {
			if status, _ := call(forged, "GET", prefix+"/api/cas", nil); status != http.StatusUnauthorized {
				t.Errorf("GET %s/api/cas with %s: %d, want 401", prefix, what, status)
			}
		}
	}

	// An entry copied from the tokens of one CA into those of another does not make its JWT a
	// token of the other CA: the JWT is still checked with the key of the CA.
	serversDB, err := loadTokens(filepath.Join(rootDir, "servers"))
	if err != nil {
		t.Fatal(err)
	}
	clientsDB, err := loadTokens(filepath.Join(rootDir, "clients"))
	if err != nil {
		t.Fatal(err)
	}
	clientsDB.Tokens["master"] = serversDB.Tokens["master"]
	if err := clientsDB.save(filepath.Join(rootDir, "clients")); err != nil {
		t.Fatal(err)
	}
	if status := apiSignStatus(jwts["servers"]["master"], "clients"); status != http.StatusUnauthorized {
		t.Errorf("POST /clients/api/sign with master of servers copied into clients: %d, want 401", status)
	}
	if status, answer := call(jwts["servers"]["master"], "GET", "/tokens/api/tokens?ca=clients", nil); status != http.StatusNotFound {
		t.Errorf("GET /tokens/api/tokens?ca=clients with master of servers copied into clients: %d %v, want 404", status, answer)
	}

	// A CA outside the root CA directory, or one that does not exist, is not found.
	for _, target := range []string{"/nowhere/api/sign", "/.servers/api/sign"} {
		if status, _ := call(jwts[""]["master"], "POST", target, signBody); status != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", target, status)
		}
	}
	for _, ca := range []string{"..", "../servers", "servers/../clients", "Servers", "nowhere"} {
		for _, target := range []string{"/tokens/api/tokens", "/certificates/api/certs"} {
			if status, _ := call(jwts[""]["master"], "GET", target+"?ca="+url.QueryEscape(ca), nil); status != http.StatusNotFound {
				t.Errorf("GET %s?ca=%s with master of root: %d, want 404", target, ca, status)
			}
		}
	}
}

func TestAPISignStoresCertificates(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	signer, err := makeToken(issuingDir, "deploy", time.Hour, nil, []string{"server"}, []string{"*"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	viewer, err := makeToken(caDir, "viewer", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken viewer: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	defer server.Close()

	do := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+path, r)
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
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	sign := func(cn, name string) (int, string) {
		t.Helper()
		out, err := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
			"-keyout", filepath.Join(csrDir, cn+"_key.pem"), "-subj", "/CN="+cn).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl req: %v\n%s", err, out)
		}
		csr := string(out[bytes.Index(out, []byte("-----BEGIN CERTIFICATE REQUEST-----")):])
		status, answer := do("POST", "/issuing-ca/api/sign", signer, map[string]any{"csr": csr, "type": "server",
			"name": name, "days": 30})
		serial, _ := answer["serial"].(string)
		return status, serial
	}
	fileSerial := func(name string) string {
		t.Helper()
		cert, err := loadCert(filepath.Join(issuingDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return serialHex(cert.SerialNumber)
	}
	shown := func(serial string) int {
		status, _ := do("GET", "/certificates/api/certs/show?ca=issuing-ca&serial="+serial, viewer, nil)
		return status
	}

	// A certificate the API signs is stored as NAME_cert.pem, and the page shows it.
	status, first := sign("web.example.com", "web")
	if status != http.StatusOK {
		t.Fatalf("signing web.example.com: %d, want 200", status)
	}
	if got := fileSerial("web_cert.pem"); got != first {
		t.Errorf("web_cert.pem holds %s, want the certificate signed, %s", got, first)
	}
	if status := shown(first); status != http.StatusOK {
		t.Errorf("showing the certificate signed: %d, want 200", status)
	}

	// The newest certificate of a name replaces the file of the one before it, which index.txt
	// still lists, and the page shows the newest.
	status, second := sign("web.example.com", "web")
	if status != http.StatusOK {
		t.Fatalf("signing web.example.com again: %d, want 200", status)
	}
	if got := fileSerial("web_cert.pem"); got != second {
		t.Errorf("web_cert.pem holds %s, want the newest certificate, %s", got, second)
	}
	if status := shown(second); status != http.StatusOK {
		t.Errorf("showing the newest certificate: %d, want 200", status)
	}
	if status := shown(first); status != http.StatusNotFound {
		t.Errorf("showing the replaced certificate: %d, want 404", status)
	}

	// The name ca is that of the file of the CA certificate, which stays as it is.
	caCert, err := os.ReadFile(filepath.Join(issuingDir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := sign("ca.example.com", "ca"); status != http.StatusBadRequest {
		t.Errorf("signing the name ca: %d, want 400", status)
	}
	if now, _ := os.ReadFile(filepath.Join(issuingDir, "ca_cert.pem")); !bytes.Equal(now, caCert) {
		t.Error("ca_cert.pem changed after a request for the name ca")
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 2 {
		t.Errorf("index.txt: %d entries, %v, want the 2 certificates signed", len(entries), err)
	}
}
