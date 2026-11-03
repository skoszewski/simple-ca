package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuthGuard(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	free := authFreeFailures
	authFreeFailures = 2
	t.Cleanup(func() { authFreeFailures = free })

	// A client is counted by its address, an IPv6 client by its /64.
	for _, c := range [][2]string{{"192.0.2.10", "192.0.2.10/32"}, {"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"}} {
		if key := guardKey(netip.MustParseAddr(c[0])); key.String() != c[1] {
			t.Errorf("guardKey(%s) = %s, want %s", c[0], key, c[1])
		}
	}

	// The hold doubles with each refusal past the free ones, up to authMaxWait.
	g := newAuthGuard()
	client := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("2001:db8:1:2:bbbb::2")
	refusedErr := apiErr(http.StatusUnauthorized, "invalid token")
	for i, want := range []time.Duration{0, 0, time.Second, 2 * time.Second, 4 * time.Second} {
		g.record(client, refusedErr)
		if hold := time.Until(g.clients[guardKey(client)].until); hold > want || (want > 0 && hold < want-time.Second) {
			t.Errorf("refusal %d: hold %s, want %s", i+1, hold, want)
		}
	}
	for range 40 {
		g.record(client, refusedErr)
	}
	if hold := time.Until(g.clients[guardKey(client)].until); hold > authMaxWait {
		t.Errorf("hold %s after many refusals, want at most %s", hold, authMaxWait)
	}
	w := httptest.NewRecorder()
	if err := g.check(w, client); err == nil || w.Header().Get("Retry-After") == "" {
		t.Errorf("check of a held client: %v, Retry-After %q, want 429 and Retry-After", err, w.Header().Get("Retry-After"))
	}
	if err := g.check(httptest.NewRecorder(), other); err != nil {
		t.Errorf("check of another client: %v, want none", err)
	}
	g.record(client, apiErr(http.StatusForbidden, "the token does not have the scope tokens"))
	if g.clients[guardKey(client)] == nil {
		t.Error("an error other than 401 forgot the refusals, want them kept")
	}
	g.record(client, nil)
	if err := g.check(httptest.NewRecorder(), client); err != nil {
		t.Errorf("check after a success: %v, want none", err)
	}

	// The routes checking credentials share the guard, fresh of the refusals of the other tests.
	shared := guard
	guard = newAuthGuard()
	t.Cleanup(func() { guard = shared })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	admin, err := makeToken(rootDir, "admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	call := func(method, path, token, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	forged := admin[:len(admin)-4] + "AAAA"
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized} {
		if resp := call("GET", "/tokens/api/cas", forged, ""); resp.StatusCode != want {
			t.Errorf("forged token %d: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
	for _, c := range []struct{ name, method, path, token, body string }{
		{"the token page with its token", "GET", "/tokens/api/cas", admin, ""},
		{"the signing API", "POST", "/api/sign", forged, `{"csr": ""}`},
		{"a setup code", "POST", "/api/token-setup", "", `{"code": "AAAA-BBBB-CCCC-DDDD"}`},
	} {
		if resp := call(c.method, c.path, c.token, c.body); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Errorf("%s while held back: %d, Retry-After %q, want 429", c.name, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if resp := call("GET", "/tokens/api/cas", admin, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("the token page after the hold: %d, want 200", resp.StatusCode)
	}
	if resp := call("GET", "/tokens/api/cas", forged, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a forged token after a success: %d, want 401", resp.StatusCode)
	}
	if resp := call("GET", "/tokens/api/cas", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", resp.StatusCode)
	}
}
