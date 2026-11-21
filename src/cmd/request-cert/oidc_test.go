// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOIDC is serve with the client of request-cert and its provider in one server: the last
// authorization request, the grants of the token endpoint, the answers of the device grant still
// to give, and the body of the certificate request.
type fakeOIDC struct {
	*httptest.Server
	mu       sync.Mutex
	settings map[string]any
	auth     url.Values
	nonce    string
	grants   []string
	pending  []string
	request  map[string]any
}

// idToken returns an unsigned JWT of claims, which request-cert reads without verifying it.
func idToken(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	f := &fakeOIDC{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		r.ParseForm()
		oauthError := func(code string) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": code})
		}
		switch r.URL.Path {
		case "/api/oidc":
			json.NewEncoder(w).Encode(f.settings)
		case "/device":
			if r.PostForm.Get("client_id") != "simple-ca-cli" || r.PostForm.Get("scope") != "openid email" {
				oauthError("invalid_client")
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"device_code": "dev-1", "user_code": "WDJB-MJHT",
				"verification_uri": "https://idp.example.com/device", "expires_in": 600, "interval": 1})
		case "/token":
			f.grants = append(f.grants, r.PostForm.Get("grant_type"))
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				challenge := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
				if r.PostForm.Get("code") != "code-1" || r.PostForm.Get("client_id") != "simple-ca-cli" ||
					r.PostForm.Get("redirect_uri") != f.auth.Get("redirect_uri") ||
					base64.RawURLEncoding.EncodeToString(challenge[:]) != f.auth.Get("code_challenge") {
					oauthError("invalid_grant")
					return
				}
				json.NewEncoder(w).Encode(map[string]string{"id_token": idToken(map[string]any{
					"email": "alice.smith@example.com", "nonce": cmp.Or(f.nonce, f.auth.Get("nonce"))})})
			case "urn:ietf:params:oauth:grant-type:device_code":
				if len(f.pending) > 0 {
					code := f.pending[0]
					f.pending = f.pending[1:]
					oauthError(code)
					return
				}
				json.NewEncoder(w).Encode(map[string]string{"id_token": idToken(map[string]any{"email": "erin@example.com"})})
			}
		case "/api/oidc-cert":
			f.request = nil
			json.NewDecoder(r.Body).Decode(&f.request)
			if f.request["type"] == nil {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{"error": "the profile staff offers the types person, user; choose one",
					"types": []string{"person", "user"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"serial": "0A", "certificate": "CERT\n", "chain": "CHAIN\n"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	f.settings = map[string]any{"cli_client_id": "simple-ca-cli", "cli_scopes": []string{"openid", "email"},
		"email_claim": []string{"email"}, "authorization_endpoint": f.URL + "/authorize", "token_endpoint": f.URL + "/token",
		"device_authorization_endpoint": f.URL + "/device"}

	// The browser signs in at once and comes back to the redirect URI with a code.
	savedOpen, savedUnit := openBrowser, pollUnit
	t.Cleanup(func() { openBrowser, pollUnit = savedOpen, savedUnit })
	pollUnit = time.Millisecond
	openBrowser = func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.auth = u.Query()
		f.mu.Unlock()
		resp, err := http.Get(u.Query().Get("redirect_uri") + "/?" + url.Values{"code": {"code-1"}, "state": {u.Query().Get("state")}}.Encode())
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	return f
}

// checkRequest checks that the certificate request holds the ID token and a CSR of a key alone.
func checkRequest(t *testing.T, f *fakeOIDC) {
	t.Helper()
	block, _ := pem.Decode([]byte(f.request["csr"].(string)))
	if block == nil {
		t.Fatalf("certificate request %v, want a CSR", f.request)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || len(csr.Subject.Names) != 0 || len(csr.DNSNames) != 0 || f.request["id_token"] == "" {
		t.Errorf("certificate request: %v, subject %v, DNS names %v", err, csr.Subject, csr.DNSNames)
	}
}

func TestRequestCertOIDC(t *testing.T) {
	f := newFakeOIDC(t)
	dir := t.TempDir()
	if err := runWith(t, "", "--oidc", "--type", "person", "--out-dir", dir, f.URL); err != nil {
		t.Fatal(err)
	}
	if f.request["type"] != "person" {
		t.Errorf("certificate request of the type %v, want person", f.request["type"])
	}
	if f.auth.Get("client_id") != "simple-ca-cli" || f.auth.Get("scope") != "openid email" ||
		f.auth.Get("code_challenge_method") != "S256" || !strings.HasPrefix(f.auth.Get("redirect_uri"), "http://127.0.0.1:") {
		t.Errorf("authorization request %v, want the CLI client, PKCE and a loopback redirect", f.auth)
	}
	checkRequest(t, f)
	for name, want := range map[string]string{"alice_smith_cert.pem": "CERT\n", "alice_smith_chain.pem": "CHAIN\n"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != want {
			t.Errorf("%s: %q, %v, want %q", name, b, err, want)
		}
	}
	if info, err := os.Stat(filepath.Join(dir, "alice_smith_key.pem")); err != nil || info.Size() == 0 {
		t.Errorf("key: %v, %v", info, err)
	}

	// A profile of several types needs --type, and leaves no key without it.
	dir = t.TempDir()
	if err := runWith(t, "", "--oidc", "--out-dir", dir, f.URL); err == nil || !strings.Contains(err.Error(), "choose one with --type") {
		t.Errorf("a profile of several types without --type: %v, want an error asking for --type", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a request without --type left %v", entries)
	}

	// An ID token of another sign-in is refused, and leaves no key.
	f.nonce = "another"
	dir = t.TempDir()
	if err := runWith(t, "", "--oidc", "--type", "user", "--out-dir", dir, f.URL); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("an ID token of another nonce: %v, want an error", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused sign-in left %v", entries)
	}
}

func TestRequestCertOIDCDevice(t *testing.T) {
	f := newFakeOIDC(t)
	f.pending = []string{"authorization_pending", "slow_down"}
	dir := t.TempDir()
	if err := runWith(t, "", "--oidc-device", "--type", "user", "--name", "erin-laptop", "--out-dir", dir, f.URL); err != nil {
		t.Fatal(err)
	}
	if len(f.grants) != 3 {
		t.Errorf("token requests %v, want 3 of the device grant", f.grants)
	}
	checkRequest(t, f)
	if _, err := os.Stat(filepath.Join(dir, "erin-laptop_cert.pem")); err != nil {
		t.Errorf("certificate of --name: %v", err)
	}

	// A denied sign-in ends the polling.
	f.pending = []string{"access_denied"}
	if err := runWith(t, "", "--oidc-device", "--out-dir", t.TempDir(), f.URL); err == nil {
		t.Error("a denied device sign-in succeeded, want an error")
	}
}

func TestRequestCertOIDCRefused(t *testing.T) {
	f := newFakeOIDC(t)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"both flows":              {[]string{"--oidc", "--oidc-device", f.URL}, "not both"},
		"--no-browser alone":      {[]string{"--no-browser", f.URL, "web.example.com"}, "--no-browser goes with --oidc"},
		"--days and --setup-code": {[]string{"--oidc-device", "--days", "3", "--setup-code", "X", f.URL}, "--days and --setup-code"},
		"a CN with --oidc":        {[]string{"--oidc", f.URL, "web.example.com"}, "usage"},
	} {
		if err := runWith(t, "", append([]string{"--out-dir", t.TempDir()}, c.args...)...); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
	delete(f.settings, "cli_client_id")
	if err := runWith(t, "", "--oidc", "--out-dir", t.TempDir(), f.URL); err == nil || !strings.Contains(err.Error(), "cli_client_id") {
		t.Errorf("serve without a CLI client: %v, want an error naming cli_client_id", err)
	}
	f.settings["cli_client_id"] = "simple-ca-cli"
	delete(f.settings, "device_authorization_endpoint")
	if err := runWith(t, "", "--oidc-device", "--out-dir", t.TempDir(), f.URL); err == nil || !strings.Contains(err.Error(), "device authorization") {
		t.Errorf("a provider without the device grant: %v, want an error", err)
	}
	if err := runWith(t, "", "--oidc", "--out-dir", t.TempDir(), f.URL+"/nowhere/x"); err == nil || errors.Is(err, errUsage) {
		t.Errorf("a SERVE_URL with a path: %v, want an error of the URL", err)
	}
}
