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

package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
)

// acmeClient is an ACME client of one ES256 key: the server, the key, the URL of its account once
// it has one, and the nonce of the next request.
type acmeClient struct {
	t     *testing.T
	srv   *httptest.Server
	key   *ecdsa.PrivateKey
	kid   string
	nonce string
}

// newACMEClient returns a client of a new key for the ACME server srv.
func newACMEClient(t *testing.T, srv *httptest.Server) *acmeClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &acmeClient{t: t, srv: srv, key: key}
}

// post sends to path the flattened JWS of payload, signed with the key and named by kid, or by
// the JWK without one; a nil payload is a POST-as-GET, and a []byte payload is sent as it is. It
// returns the status, the decoded answer and the Location header.
func (c *acmeClient) post(path string, payload any) (int, map[string]any, string) {
	c.t.Helper()
	if c.nonce == "" {
		resp, err := http.Head(c.srv.URL + "/acme/new-nonce")
		if err != nil {
			c.t.Fatal(err)
		}
		resp.Body.Close()
		c.nonce = resp.Header.Get("Replay-Nonce")
	}
	header := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": c.srv.URL + path}
	if c.kid != "" {
		header["kid"] = c.kid
	} else {
		k := jose.PublicJWK(c.key.Public())
		header["jwk"] = map[string]string{"kty": k.Kty, "crv": k.Crv, "x": k.X, "y": k.Y}
	}
	var body []byte
	switch p := payload.(type) {
	case nil:
	case []byte:
		body = p
	default:
		var err error
		if body, err = json.Marshal(p); err != nil {
			c.t.Fatal(err)
		}
	}
	b64 := base64.RawURLEncoding.EncodeToString
	protected, err := json.Marshal(header)
	if err != nil {
		c.t.Fatal(err)
	}
	signed := b64(protected) + "." + b64(body)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, digest[:])
	if err != nil {
		c.t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	jws, err := json.Marshal(map[string]string{"protected": b64(protected), "payload": b64(body), "signature": b64(sig)})
	if err != nil {
		c.t.Fatal(err)
	}
	resp, err := http.Post(c.srv.URL+path, "application/jose+json", bytes.NewReader(jws))
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	c.nonce = resp.Header.Get("Replay-Nonce")
	raw, _ := io.ReadAll(resp.Body)
	var answer map[string]any
	if err := json.Unmarshal(raw, &answer); err != nil {
		c.t.Fatalf("POST %s: %d %q is not a JSON object", path, resp.StatusCode, raw)
	}
	return resp.StatusCode, answer, resp.Header.Get("Location")
}

// register makes the account of c with the contact email, and keeps its URL.
func (c *acmeClient) register(email string) string {
	c.t.Helper()
	status, answer, location := c.post("/acme/new-account", map[string]any{"contact": []string{"mailto:" + email},
		"termsOfServiceAgreed": true})
	if status != http.StatusCreated || answer["status"] != "valid" || !strings.HasPrefix(location, c.srv.URL+"/acme/acct/") {
		c.t.Fatalf("new-account: %d %v %q, want 201, a valid account and its URL", status, answer, location)
	}
	c.kid = location
	return strings.TrimPrefix(location, c.srv.URL)
}

func TestAccountsAndOrders(t *testing.T) {
	caDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"acme": {"domains": ["example.com"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "ec"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(testMux(caDir))
	defer srv.Close()

	a := newACMEClient(t, srv)
	acct := a.register("a@example.com")
	b := newACMEClient(t, srv)
	other := b.register("b@example.com")

	// An account is read with POST-as-GET, its contacts changed, and refused another status.
	if status, answer, _ := a.post(acct, nil); status != http.StatusOK || answer["status"] != "valid" ||
		fmt.Sprint(answer["contact"]) != "[mailto:a@example.com]" || answer["orders"] != srv.URL+acct+"/orders" {
		t.Errorf("POST-as-GET of the account: %d %v", status, answer)
	}
	if status, answer, _ := a.post(acct, map[string]any{"contact": []string{"mailto:new@example.com"}}); status != http.StatusOK ||
		fmt.Sprint(answer["contact"]) != "[mailto:new@example.com]" {
		t.Errorf("contact update: %d %v, want the new contact", status, answer)
	}
	if status, answer, _ := a.post(acct, nil); fmt.Sprint(answer["contact"]) != "[mailto:new@example.com]" {
		t.Errorf("the account after the contact update: %d %v, want the new contact kept", status, answer)
	}
	for _, c := range []struct {
		payload any
		typ     string
	}{
		{map[string]any{"contact": []string{"tel:+1555"}}, "unsupportedContact"},
		{map[string]any{"status": "revoked"}, "malformed"},
		{[]byte("not json"), "malformed"},
	} {
		if status, answer, _ := a.post(acct, c.payload); status != http.StatusBadRequest ||
			answer["type"] != "urn:ietf:params:acme:error:"+c.typ {
			t.Errorf("account update %v: %d %v, want 400 %s", c.payload, status, answer, c.typ)
		}
	}
	for _, path := range []string{other, other + "/orders"} {
		if status, answer, _ := a.post(path, nil); status != http.StatusUnauthorized ||
			answer["detail"] != "the request is not signed by this account" {
			t.Errorf("POST-as-GET of %s by another account: %d %v, want 401", path, status, answer)
		}
	}

	// The orders of an account are listed, and an order is read by its account alone.
	if status, answer, _ := a.post(acct+"/orders", nil); status != http.StatusOK || fmt.Sprint(answer["orders"]) != "[]" {
		t.Errorf("orders of a new account: %d %v, want none", status, answer)
	}
	status, answer, location := a.post("/acme/new-order", map[string]any{"identifiers": []map[string]string{
		{"type": "dns", "value": "www.example.com"}}})
	if status != http.StatusCreated || !strings.HasPrefix(location, srv.URL+"/acme/order/") {
		t.Fatalf("new-order: %d %v %q, want 201 and the order URL", status, answer, location)
	}
	order := strings.TrimPrefix(location, srv.URL)
	if status, answer, _ := a.post(acct+"/orders", nil); status != http.StatusOK || fmt.Sprint(answer["orders"]) != "["+location+"]" {
		t.Errorf("orders after new-order: %d %v, want [%s]", status, answer, location)
	}
	if status, answer, _ := a.post(order, nil); status != http.StatusOK || answer["status"] != "pending" ||
		fmt.Sprint(answer["identifiers"]) != "[map[type:dns value:www.example.com]]" || answer["finalize"] != location+"/finalize" {
		t.Errorf("POST-as-GET of the order: %d %v, want it pending for www.example.com", status, answer)
	}
	if status, answer, _ := b.post(order, nil); status != http.StatusUnauthorized || answer["detail"] != "the order is of another account" {
		t.Errorf("the order read by another account: %d %v, want 401", status, answer)
	}
	if status, answer, _ := a.post("/acme/order/nosuch", nil); status != http.StatusNotFound {
		t.Errorf("an unknown order: %d %v, want 404", status, answer)
	}

	// A deactivated account signs no more requests.
	if status, answer, _ := a.post(acct, map[string]any{"status": "deactivated"}); status != http.StatusOK ||
		answer["status"] != "deactivated" {
		t.Errorf("deactivation: %d %v, want the account deactivated", status, answer)
	}
	if status, answer, _ := a.post(acct, nil); status != http.StatusUnauthorized || answer["detail"] != `the account is "deactivated"` {
		t.Errorf("a request of the deactivated account: %d %v, want 401", status, answer)
	}
}

func TestProblemError(t *testing.T) {
	p := problem(http.StatusBadRequest, "malformed", "no resource %q", "x")
	if p.Error() != `no resource "x"` || p.Type != "urn:ietf:params:acme:error:malformed" || p.Status != http.StatusBadRequest {
		t.Errorf("problem: %+v, Error %q", p, p.Error())
	}
}
