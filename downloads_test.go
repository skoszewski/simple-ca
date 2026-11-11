package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
)

func TestServeDownloads(t *testing.T) {
	caDir, dl, apt, outside := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })
	write := func(dir, name, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := func(data string) string {
		h := sha256.Sum256([]byte(data))
		return hex.EncodeToString(h[:])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(server *httptest.Server, path string) (*http.Response, string) {
		t.Helper()
		resp, err := client.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp, string(body)
	}

	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "http://pki.example.com", "ec"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	write(dl, "good", "good data")
	write(dl, "good.sha256", sum("good data")+"  good\n")
	write(dl, "binary", "binary data")
	write(dl, "binary.sha256", strings.ToUpper(sum("binary data"))+" *binary\n")
	write(dl, "nosum", "no sum")
	write(dl, "wrong", "wrong data")
	write(dl, "wrong.sha256", sum("other data")+"  wrong\n")
	write(dl, "renamed", "renamed data")
	write(dl, "renamed.sha256", sum("renamed data")+"  other\n")
	write(dl, ".hidden", "hidden data")
	write(dl, ".hidden.sha256", sum("hidden data")+"  .hidden\n")
	write(outside, "secret", "secret data")
	write(apt, "dists/x/Release", "Origin: test\n")
	packagesIndex := "Package: simple-ca-lite\nVersion: 1.0.0-1\n\nPackage: simple-ca\nVersion: 1.0.0-1\n\n" +
		"Package: simple-ca\nVersion: 0.9.0-1\n"
	write(apt, "Packages", packagesIndex)
	symlinks := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dl, "escape")) == nil &&
		os.Symlink(filepath.Join(outside, "secret"), filepath.Join(apt, "escape")) == nil
	write(dl, "escape.sha256", sum("secret data")+"  escape\n")

	// Without the directories, neither route is served.
	without := httptest.NewServer(newServeMux(caDir, false, false))
	defer without.Close()
	for _, path := range []string{"/downloads/", "/downloads/good", "/apt/dists/x/Release"} {
		if resp, _ := get(without, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s without the directories: status %d, want 404", path, resp.StatusCode)
		}
	}
	if _, body := get(without, "/"); strings.Contains(body, `href="/downloads/"`) || strings.Contains(body, `href="/apt/"`) {
		t.Error("the index page links to /downloads/ or /apt/ without --downloads and --packages")
	}

	t.Cleanup(func() { downloadsDir, packagesDir = "", "" })
	downloadsDir, packagesDir = dl, apt
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()

	resp, page := get(server, "/downloads/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, sum("good data")) {
		t.Fatalf("/downloads/: status %d, want the page with the SHA-256 of good:\n%s", resp.StatusCode, page)
	}
	for _, name := range []string{"good", "binary"} {
		if !strings.Contains(page, `href="/downloads/`+name+`"`) || !strings.Contains(page, `href="/downloads/`+name+`.sha256"`) {
			t.Errorf("/downloads/ does not list %s with its sum file", name)
		}
	}
	for _, name := range []string{"nosum", "wrong", "renamed", ".hidden", "escape", "good.sha256.sha256"} {
		if strings.Contains(page, `href="/downloads/`+name+`"`) {
			t.Errorf("/downloads/ lists %s", name)
		}
	}
	if resp, _ := get(server, "/downloads"); resp.StatusCode != http.StatusTemporaryRedirect ||
		resp.Header.Get("Location") != "/downloads/" {
		t.Errorf("/downloads: status %d to %q, want 307 to /downloads/", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, body := get(server, "/"); !strings.Contains(body, `text-head-link hover:underline" href="/downloads/">Downloads</a>`) ||
		!strings.Contains(body, `hover:text-ink hover:underline" href="/downloads/">Downloads</a>`) {
		t.Error("the index page does not link to /downloads/ in its header and below the page")
	}
	if _, body := get(server, "/"); !strings.Contains(body, `text-head-link hover:underline" href="/apt/">Apt</a>`) ||
		!strings.Contains(body, `hover:text-ink hover:underline" href="/apt/">Apt</a>`) {
		t.Error("the index page does not link to /apt/ in its header and below the page")
	}

	// The apt page tells how to set up the repository, and has no key.asc to point to.
	resp, page = get(server, "/apt/")
	for _, want := range []string{"BASE_URL=" + server.URL, "/etc/apt/keyrings/simple-ca.asc", "$BASE_URL/apt/key.asc",
		"deb [signed-by=/etc/apt/keyrings/simple-ca.asc] $BASE_URL/apt ./", "sudo apt-get install simple-ca simple-ca-lite\n",
		"<li>simple-ca</li>", "<li>simple-ca-lite</li>", "has no\n            <code class=\"font-mono\">key.asc</code>",
		"served over\n            plain HTTP", `src="/assets/webui/copy.js"`} {
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("/apt/: status %d, want %q in the page:\n%s", resp.StatusCode, want, page)
		}
	}
	write(apt, "key.asc", "public key\n")
	if _, page := get(server, "/apt/"); strings.Contains(page, "<code class=\"font-mono\">key.asc</code>, so") {
		t.Error("/apt/ warns about key.asc while the repository has it")
	}
	if resp, body := get(server, "/apt/Packages"); resp.StatusCode != http.StatusOK || body != packagesIndex {
		t.Errorf("/apt/Packages: status %d, %q, want the file", resp.StatusCode, body)
	}

	resp, body := get(server, "/downloads/good")
	if resp.StatusCode != http.StatusOK || body != "good data" || resp.Header.Get("Content-Type") != "application/octet-stream" ||
		resp.Header.Get("Content-Disposition") != "attachment; filename=good" {
		t.Errorf("/downloads/good: status %d, %q, %s, %s", resp.StatusCode, body, resp.Header.Get("Content-Type"),
			resp.Header.Get("Content-Disposition"))
	}
	resp, body = get(server, "/downloads/good.sha256")
	if resp.StatusCode != http.StatusOK || body != sum("good data")+"  good\n" ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("/downloads/good.sha256: status %d, %q, %s", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	for _, path := range []string{"/downloads/nosum", "/downloads/nosum.sha256", "/downloads/wrong", "/downloads/wrong.sha256",
		"/downloads/renamed", "/downloads/.hidden", "/downloads/escape", "/downloads/..%2F" + filepath.Base(outside) + "%2Fsecret"} {
		if resp, _ := get(server, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, resp.StatusCode)
		}
	}

	// A changed file no longer matches its sum.
	write(dl, "good", "changed good data")
	if resp, _ := get(server, "/downloads/good"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/downloads/good after a change: status %d, want 404", resp.StatusCode)
	}
	if _, page := get(server, "/downloads/"); strings.Contains(page, `href="/downloads/good"`) {
		t.Error("/downloads/ lists good after a change")
	}

	if resp, body := get(server, "/apt/dists/x/Release"); resp.StatusCode != http.StatusOK || body != "Origin: test\n" {
		t.Errorf("/apt/dists/x/Release: status %d, %q", resp.StatusCode, body)
	}
	if !symlinks {
		t.Log("symlinks are not supported here; the escape checks are skipped")
		return
	}
	if resp, body := get(server, "/apt/escape"); resp.StatusCode == http.StatusOK || strings.Contains(body, "secret data") {
		t.Errorf("/apt/escape: status %d, want the symlink out of the directory refused", resp.StatusCode)
	}
}
