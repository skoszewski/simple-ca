package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/pkg/simpleca/tokens"
)

func TestAPILinks(t *testing.T) {
	caDir := t.TempDir()
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "http://pki.example.com", "ec"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	token, err := tokens.MakeToken(caDir, "alice", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	elsewhere, err := tokens.MakeToken(caDir, "bob", time.Hour, []string{"certs"}, nil, nil, nil, []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}

	type answer struct {
		User   string     `json:"user"`
		UserCA string     `json:"user_ca"`
		Links  []pageLink `json:"links"`
		Error  string     `json:"error"`
	}
	get := func(server *httptest.Server, token string) (int, answer) {
		t.Helper()
		req, err := http.NewRequest("GET", server.URL+"/api/links", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var a answer
		if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.StatusCode, a
	}
	hrefs := func(a answer) []string {
		var h []string
		for _, l := range a.Links {
			h = append(h, l.Href)
		}
		return h
	}
	short := []string{"/token-setup", "/token-describe"}
	full := append(slices.Clone(short), tokensPath, certsPath, auditPagePath)

	withWebUI := httptest.NewServer(newServeMux(caDir, false, true))
	defer withWebUI.Close()
	if status, a := get(withWebUI, ""); status != http.StatusOK || !slices.Equal(hrefs(a), short) || a.User != "" {
		t.Errorf("without a token: %d %v %q, want the short list and no user", status, hrefs(a), a.User)
	}
	if status, a := get(withWebUI, token); status != http.StatusOK || !slices.Equal(hrefs(a), full) || a.User != "alice" {
		t.Errorf("with a valid token: %d %v %q, want the full list and alice", status, hrefs(a), a.User)
	}
	if status, a := get(withWebUI, token+"x"); status != http.StatusUnauthorized || len(a.Links) != 0 {
		t.Errorf("with an invalid token: %d %v, want 401 and no links", status, hrefs(a))
	}
	if status, _ := get(withWebUI, elsewhere); status != http.StatusForbidden {
		t.Errorf("with a token not allowed from this client: %d, want 403", status)
	}

	// Without webui, a valid token gets the public links alone.
	without := httptest.NewServer(newServeMux(caDir, false, false))
	defer without.Close()
	if status, a := get(without, token); status != http.StatusOK || !slices.Equal(hrefs(a), short) || a.User != "alice" {
		t.Errorf("without webui, with a valid token: %d %v %q, want the short list", status, hrefs(a), a.User)
	}

	// The downloads and the apt repository are public links, with their directories.
	t.Cleanup(func() { downloadsDir, packagesDir = "", "" })
	downloadsDir, packagesDir = t.TempDir(), t.TempDir()
	if _, a := get(withWebUI, ""); !slices.Equal(hrefs(a), append(slices.Clone(short), downloadsPath, aptPath)) {
		t.Errorf("with downloads and packages, without a token: %v", hrefs(a))
	}
}
