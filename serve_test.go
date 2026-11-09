package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/skoszewski/serve-markdown/v3/render"
)

func TestServe(t *testing.T) {
	caDir := t.TempDir()
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := makeCA(caDir, "Test CA", 3650, "", server.URL, "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := makeCert("web.example.com", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}

	get := func(method, path string) (int, string, []byte) {
		req, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", path, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp.StatusCode, resp.Header.Get("Content-Type"), body
	}

	leaf, err := loadCert(filepath.Join(caDir, "issuing-ca", "web_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	issuing, err := loadCert(filepath.Join(caDir, "issuing-ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	aia := strings.TrimPrefix(leaf.IssuingCertificateURL[0], server.URL)
	if status, typ, body := get("GET", aia); status != http.StatusOK || typ != "application/pkix-cert" || !bytes.Equal(body, issuing.Raw) {
		t.Fatalf("GET %s: %d %s, the DER of the issuing CA: %v", aia, status, typ, bytes.Equal(body, issuing.Raw))
	}
	cdp := strings.TrimPrefix(leaf.CRLDistributionPoints[0], server.URL)
	if status, _, _ := get("GET", cdp); status != http.StatusOK {
		t.Fatalf("GET %s, the first CRL of ca create: %d, want 200", cdp, status)
	}
	if err := makeCA(caDir, "Short CA", 10, "short-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA short: %v", err)
	}
	status, typ, page := get("GET", "/")
	if status != http.StatusOK || typ != "text/html; charset=utf-8" {
		t.Fatalf("GET /: %d %s", status, typ)
	}
	fingerprint := sha256.Sum256(issuing.Raw)
	for _, s := range []string{"<title>Test CA - simple-ca</title>", `font-semibold">Test CA</h1>`, "served by simple-ca",
		"<dd>/CN=Issuing CA</dd>", `<span data-subject="[[&#34;CN&#34;,&#34;Issuing CA&#34;]]">Issuing CA</span>`,
		`font-semibold">Issuing CA</h2>`, `text-subtle-ink">Root CA</span>`, `text-subtle-ink">Subordinate CA</span>`,
		"<dd>/CN=Test CA</dd>", serialHex(issuing.SerialNumber),
		`<span class="whitespace-nowrap">` + colonHex(fingerprint[:8]) + `:</span><span class="whitespace-nowrap">` +
			colonHex(fingerprint[8:16]) + `:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[16:24]) +
			`:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[24:]) + `</span>`,
		"RSA 4096 bits", issuing.NotBefore.UTC().Format(displayTimeFormat), "3650 days left",
		`bg-warn text-warn-ink">10 days left`, `href="/ca_cert.crt"`, `href="/issuing-ca/ca_cert.pem"`,
		"<dd>number 1, 0 revoked, next update ", `href="/issuing-ca/crl.crl"`, `<script src="` + tailwindPath + `">`,
		`<button type="button" data-info="info-1"`, `<dialog id="info-1"`, `<script src="/assets/webui/index.js">`} {
		if !strings.Contains(string(page), s) {
			t.Fatalf("the index page lacks %q:\n%s", s, page)
		}
	}
	if strings.Contains(string(page), "https://") {
		t.Fatalf("the index page loads a resource from another site:\n%s", page)
	}
	if !strings.Contains(string(page), `<tr id="issuing-ca">`) {
		t.Fatalf("the index page has no row with the ID issuing-ca:\n%s", page)
	}

	// /CA and /CA/ of an issuing CA redirect to its section of the index page.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, c := range []struct {
		method, path, location string
		want                   int
	}{
		{"GET", "/issuing-ca", "/#issuing-ca", http.StatusFound},
		{"GET", "/issuing-ca/", "/#issuing-ca", http.StatusFound},
		{"HEAD", "/issuing-ca", "/#issuing-ca", http.StatusFound},
		{"GET", "/nosuch", "", http.StatusNotFound},
		{"GET", "/nosuch/", "", http.StatusNotFound},
	} {
		req, err := http.NewRequest(c.method, server.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want || resp.Header.Get("Location") != c.location {
			t.Fatalf("%s %s: %d to %q, want %d to %q", c.method, c.path, resp.StatusCode, resp.Header.Get("Location"), c.want, c.location)
		}
	}
	bundleAt := strings.Index(string(page), `href="/ca_bundle.pem"`)
	if bundleAt < 0 || bundleAt > strings.Index(string(page), "<main") {
		t.Fatalf("the index page does not offer the CA bundle above the CAs:\n%s", page)
	}
	status, typ, script := get("GET", tailwindPath)
	if status != http.StatusOK || typ != "text/javascript; charset=utf-8" || !bytes.Equal(script, tailwindJS) ||
		!bytes.Contains(script, []byte(`"4.3.3"`)) {
		t.Fatalf("GET %s: %d %s, %d bytes", tailwindPath, status, typ, len(script))
	}
	if status, _, _ := get("GET", "/assets/"); status != http.StatusNotFound {
		t.Fatalf("GET /assets/: %d, want 404", status)
	}
	if err := makeCRL(filepath.Join(caDir, "issuing-ca"), 30); err != nil {
		t.Fatalf("makeCRL: %v", err)
	}
	if _, _, page := get("GET", "/"); !strings.Contains(string(page), "<dd>number 2, 0 revoked, next update ") {
		t.Fatalf("the index page lacks the second CRL of the issuing CA:\n%s", page)
	}
	status, typ, body := get("GET", cdp)
	if status != http.StatusOK || typ != "application/x-pem-file" {
		t.Fatalf("GET %s: %d %s", cdp, status, typ)
	}
	if block, _ := pem.Decode(body); block == nil || block.Type != "X509 CRL" {
		t.Fatalf("GET %s is not a PEM CRL:\n%s", cdp, body)
	}
	status, typ, body = get("GET", "/issuing-ca/crl.crl")
	if status != http.StatusOK || typ != "application/pkix-crl" {
		t.Fatalf("GET /issuing-ca/crl.crl: %d %s", status, typ)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil || crl.CheckSignatureFrom(issuing) != nil {
		t.Fatalf("the DER CRL does not parse or is not signed by the issuing CA: %v", err)
	}

	bundle, err := os.ReadFile(filepath.Join(caDir, "ca_bundle.pem"))
	if err != nil {
		t.Fatalf("read ca_bundle.pem: %v", err)
	}
	if status, _, body := get("GET", "/ca_bundle.pem"); status != http.StatusOK || !bytes.Equal(body, bundle) {
		t.Fatalf("GET /ca_bundle.pem: %d", status)
	}
	status, typ, body = get("GET", "/ca_bundle.p7b")
	if status != http.StatusOK || typ != "application/x-pkcs7-certificates" {
		t.Fatalf("GET /ca_bundle.p7b: %d %s", status, typ)
	}
	p7bPath := filepath.Join(t.TempDir(), "ca_bundle.p7b")
	if err := os.WriteFile(p7bPath, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", p7bPath, err)
	}
	out, err := exec.Command("openssl", "pkcs7", "-inform", "DER", "-in", p7bPath, "-print_certs").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs7: %v\n%s", err, out)
	}
	var p7bCerts, bundleCerts [][]byte
	for rest := out; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		p7bCerts = append(p7bCerts, block.Bytes)
	}
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		bundleCerts = append(bundleCerts, block.Bytes)
	}
	if len(bundleCerts) < 2 || !slices.EqualFunc(p7bCerts, bundleCerts, bytes.Equal) {
		t.Fatalf("ca_bundle.p7b holds %d certificates, want the %d of ca_bundle.pem", len(p7bCerts), len(bundleCerts))
	}
	if status, _, _ := get("HEAD", "/ca_cert.pem"); status != http.StatusOK {
		t.Fatalf("HEAD /ca_cert.pem: %d", status)
	}

	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/ca_key.pem", http.StatusNotFound},
		{"GET", "/issuing-ca/ca_key.pem", http.StatusNotFound},
		{"GET", "/issuing-ca/web_cert.pem", http.StatusNotFound},
		{"GET", "/missing/ca_cert.crt", http.StatusNotFound},
		{"GET", "/issuing-ca/../ca_key.pem", http.StatusNotFound},
		{"GET", "/crl.pem", http.StatusOK},
		{"POST", "/ca_cert.crt", http.StatusMethodNotAllowed},
		{"GET", "/acme/directory", http.StatusNotFound},
		{"GET", "/issuing-ca/acme/directory", http.StatusNotFound},
	} {
		if status, _, _ := get(c.method, c.path); status != c.status {
			t.Fatalf("%s %s: %d, want %d", c.method, c.path, status, c.status)
		}
	}
}

func TestServeAddress(t *testing.T) {
	if err := run([]string{"serve", "--address", ""}); !errors.Is(err, errUsage) {
		t.Fatalf("serve --address \"\": %v, want a usage error", err)
	}
}

func TestClientAddr(t *testing.T) {
	trustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	t.Cleanup(func() { trustedProxies = nil })
	for _, c := range []struct {
		peer    string
		headers []string
		want    string
	}{
		{"192.0.2.1:5000", []string{"203.0.113.7"}, "192.0.2.1"},
		{"10.0.0.1:5000", nil, "10.0.0.1"},
		{"10.0.0.1:5000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"198.51.100.9, 203.0.113.7, 10.0.0.2"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"198.51.100.9", "203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"10.0.0.5, 10.0.0.2"}, "10.0.0.5"},
		{"10.0.0.1:5000", []string{"nonsense, 203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"203.0.113.7, nonsense"}, "10.0.0.1"},
		{"[::ffff:10.0.0.1]:5000", []string{"2001:db8::7"}, "2001:db8::7"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/sign", nil)
		r.RemoteAddr = c.peer
		for _, h := range c.headers {
			r.Header.Add("X-Forwarded-For", h)
		}
		if got := clientAddr(r).String(); got != c.want {
			t.Fatalf("clientAddr from %s with %q = %s, want %s", c.peer, c.headers, got, c.want)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/sign", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	trustedProxies = nil
	if got := clientAddr(r).String(); got != "10.0.0.1" {
		t.Fatalf("clientAddr without trusted proxies = %s, want the peer 10.0.0.1", got)
	}
}

func TestHelpPage(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"help", "docs", "tokens", "certificates"} {
		if err := makeCA(caDir, "Pages CA", 3650, name, "", "rsa"); err == nil || !strings.Contains(err.Error(), "taken") {
			t.Fatalf("makeCA --issuing-ca %s: %v, want it refused", name, err)
		}
	}

	get := func(server *httptest.Server, path string) (int, string) {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp.StatusCode, string(body)
	}

	// Without the page's browser files there is no help, and nothing links to it.
	saved := helpSite
	t.Cleanup(func() { helpSite = saved })
	helpSite = nil
	without := httptest.NewServer(newServeMux(caDir, false, false))
	defer without.Close()
	if status, _ := get(without, "/help/"); status != http.StatusNotFound {
		t.Errorf("/help/ without the assets: status %d, want 404", status)
	}
	for _, path := range []string{"/", "/sign"} {
		if _, body := get(without, path); strings.Contains(body, helpPath) {
			t.Errorf("%s links to %s without the assets", path, helpPath)
		}
	}

	// The token and certificate pages are served, and linked from the index page, with webui alone.
	for _, path := range []string{tokensPath, certsPath} {
		if status, _ := get(without, path); status != http.StatusNotFound {
			t.Errorf("%s without webui: status %d, want 404", path, status)
		}
		if _, body := get(without, "/"); strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("the index page links to %s without webui", path)
		}
	}
	withWebUI := httptest.NewServer(newServeMux(caDir, false, true))
	defer withWebUI.Close()
	for _, path := range []string{tokensPath, certsPath} {
		if status, body := get(withWebUI, path); status != http.StatusOK || !strings.Contains(body, `href="/">All CAs</a>`) {
			t.Errorf("%s with webui: status %d, want the page linking to the index page", path, status)
		}
		if _, body := get(withWebUI, "/"); !strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("the index page does not link to %s with webui", path)
		}
	}

	// With them, the help is a page at /help/, linked from the index page and the form.
	pages, err := fs.Sub(helpPages, "help")
	if err != nil {
		t.Fatal(err)
	}
	helpSite = render.New(pages, render.Options{Prefix: helpPath, Search: render.IndexSearch{"index.md"},
		Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	with := httptest.NewServer(newServeMux(caDir, false, false))
	defer with.Close()
	if status, page := get(with, "/help/"); status != http.StatusOK || !strings.Contains(page, `src="/help/_/assets/page.js"`) {
		t.Errorf("/help/: status %d, want the page shell:\n%s", status, page)
	}
	if status, body := get(with, "/help/_/content?path=%2Fhelp%2F"); status != http.StatusOK ||
		!strings.Contains(body, `"title":"Requesting a certificate"`) || !strings.Contains(body, "## With request-cert") ||
		!strings.Contains(body, "### Send the request") {
		t.Errorf("/help/ content: status %d, want the help:\n%s", status, body)
	}
	for _, path := range []string{"/", "/sign"} {
		if _, body := get(with, path); !strings.Contains(body, `href="/help/"`) {
			t.Errorf("%s does not link to /help/", path)
		}
	}
	// The routes of the CAs stand beside the help.
	if status, _ := get(with, "/ca_cert.pem"); status != http.StatusOK {
		t.Errorf("/ca_cert.pem beside /help/: status %d, want 200", status)
	}
	// The guides are served, and linked from the index page, with serve --docs alone.
	if status, _ := get(with, "/docs/"); status != http.StatusNotFound {
		t.Errorf("/docs/ without --docs: status %d, want 404", status)
	}
	if _, body := get(with, "/"); strings.Contains(body, `href="/docs/"`) {
		t.Error("the index page links to /docs/ without --docs")
	}
	guides, err := fs.Sub(docsPages, "docs")
	if err != nil {
		t.Fatal(err)
	}
	savedDocs := docsSite
	t.Cleanup(func() { docsSite = savedDocs })
	docsSite = render.New(guides, render.Options{Prefix: docsPath, Search: render.IndexSearch{"usage.md"},
		Menu: docsMenu, List: render.DefaultList, Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	withDocs := httptest.NewServer(newServeMux(caDir, true, false))
	defer withDocs.Close()
	status, page := get(withDocs, "/docs/")
	if status != http.StatusOK || !strings.Contains(page, `<a href="/docs/usage.md" class="current">Usage</a>`) ||
		!strings.Contains(page, `<a href="/docs/signing-api.md">Signing API</a>`) {
		t.Errorf("/docs/: status %d, want the page shell with the menu of the guides:\n%s", status, page)
	}
	for _, name := range []string{"usage.md", "serve.md", "acme.md", "signing-api.md", "development.md"} {
		if status, body := get(withDocs, "/docs/_/content?path=%2Fdocs%2F"+name); status != http.StatusOK ||
			strings.Contains(body, `"error":"`) {
			t.Errorf("/docs/%s: status %d, want the guide:\n%s", name, status, body)
		}
	}
	if _, body := get(withDocs, "/"); !strings.Contains(body, `href="/docs/"`) {
		t.Error("the index page does not link to /docs/ with --docs")
	}
}
