package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
)

func TestServeACME(t *testing.T) {
	caDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"acme": {"domains": ["localhost"]}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", simpleca.ConfigFile, err)
	}
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()

	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), server.URL+"/servers/acme/directory") || !strings.Contains(string(page), server.URL+"/acme/directory") {
		t.Fatalf("the index page lacks the ACME directories:\n%s", page)
	}
	for _, prefix := range []string{"/servers/acme", "/acme"} {
		resp, err := http.Get(server.URL + prefix + "/directory")
		if err != nil {
			t.Fatalf("GET %s/directory: %v", prefix, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"newOrder":"`+server.URL+prefix+`/new-order"`) {
			t.Fatalf("GET %s/directory: %d\n%s", prefix, resp.StatusCode, body)
		}
	}
}
