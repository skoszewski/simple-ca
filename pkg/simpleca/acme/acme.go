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

// Package acme is the ACME server of simple-ca, which issues the certificates of its CAs to ACME
// clients.
package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/pkg/simpleca/jose"
)

// ClientAddr returns the address of the client of a request; the program serving ACME sets it.
var ClientAddr func(r *http.Request) netip.Addr

// Origin returns the origin of a request as its client sees it, such as https://pki.example.com;
// the program serving ACME sets it.
var Origin func(r *http.Request) string

// stateFile is the file of the ACME state of a CA, an order lives acmeOrderLifetime, a nonce
// acmeNonceLifetime, and maxBody is the largest body of a request, in bytes.
const (
	stateFile         = "acme.json"
	acmeOrderLifetime = 7 * 24 * time.Hour
	acmeNonceLifetime = time.Hour
	maxBody           = 64 << 10
)

// httpPort is the port the http-01 challenges are validated on.
var httpPort = 80

// acmeProblem is an ACME error, a problem document of RFC 7807 with an ACME error type.
type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status,omitempty"`
}

func (p *acmeProblem) Error() string { return p.Detail }

// problem returns an ACME error of the type urn:ietf:params:acme:error:typ.
func problem(status int, typ, format string, args ...any) *acmeProblem {
	return &acmeProblem{Type: "urn:ietf:params:acme:error:" + typ, Detail: fmt.Sprintf(format, args...), Status: status}
}

// acmeAccount is an ACME account, identified by its key.
type acmeAccount struct {
	Key        json.RawMessage `json:"key"`
	Thumbprint string          `json:"thumbprint"`
	Contact    []string        `json:"contact,omitempty"`
	Status     string          `json:"status"`
}

// acmeChallenge is a challenge of an authorization.
type acmeChallenge struct {
	Type      string       `json:"type"`
	Token     string       `json:"token"`
	Status    string       `json:"status"`
	Validated *time.Time   `json:"validated,omitempty"`
	Error     *acmeProblem `json:"error,omitempty"`
}

// acmeAuthz is the authorization of an account for a DNS name, without the *. of a wildcard.
type acmeAuthz struct {
	Account    string          `json:"account"`
	Name       string          `json:"name"`
	Wildcard   bool            `json:"wildcard,omitempty"`
	Status     string          `json:"status"`
	Expires    time.Time       `json:"expires"`
	Challenges []acmeChallenge `json:"challenges"`
}

// acmeOrder is an order of an account for a certificate of names, the PEM chain of the
// certificate once it is issued.
type acmeOrder struct {
	Account string       `json:"account"`
	Status  string       `json:"status"`
	Expires time.Time    `json:"expires"`
	Names   []string     `json:"names"`
	Authzs  []string     `json:"authzs"`
	Chain   string       `json:"chain,omitempty"`
	Error   *acmeProblem `json:"error,omitempty"`
}

// acmeState is the ACME state of a CA, kept in acme.json of its directory: the accounts, orders
// and authorizations by ID, and the account each certificate was issued to by serial number.
type acmeState struct {
	Accounts map[string]*acmeAccount `json:"accounts"`
	Orders   map[string]*acmeOrder   `json:"orders"`
	Authzs   map[string]*acmeAuthz   `json:"authzs"`
	Certs    map[string]string       `json:"certs"`
}

// Server is the ACME server of the CAs of serve, for the CAs whose root CA's simple-ca.json
// lists acme.domains; cert.IssueMu guards the states, which are loaded on first use, and nonceMu
// the nonces.
type Server struct {
	states  map[string]*acmeState
	nonceMu sync.Mutex
	nonces  map[string]time.Time
	issued  []string
}

// NewServer returns an ACME server with no state loaded and no nonces.
func NewServer() *Server {
	return &Server{nonces: map[string]time.Time{}, states: map[string]*acmeState{}}
}

// state returns the state of the CA in caDir, dropping the orders and authorizations that
// expired; cert.IssueMu must be held.
func (s *Server) state(caDir string) (*acmeState, error) {
	st, ok := s.states[caDir]
	if !ok {
		st = &acmeState{}
		b, err := os.ReadFile(filepath.Join(caDir, stateFile))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			if err := json.Unmarshal(b, st); err != nil {
				return nil, fmt.Errorf("could not read %s: %w", filepath.Join(caDir, stateFile), err)
			}
		}
		if st.Accounts == nil {
			st.Accounts = map[string]*acmeAccount{}
		}
		if st.Orders == nil {
			st.Orders = map[string]*acmeOrder{}
		}
		if st.Authzs == nil {
			st.Authzs = map[string]*acmeAuthz{}
		}
		if st.Certs == nil {
			st.Certs = map[string]string{}
		}
		s.states[caDir] = st
	}
	now := time.Now()
	for id, o := range st.Orders {
		if now.After(o.Expires) {
			delete(st.Orders, id)
		}
	}
	for id, a := range st.Authzs {
		if now.After(a.Expires) {
			delete(st.Authzs, id)
		}
	}
	return st, nil
}

// save writes the state of the CA in caDir to its acme.json; cert.IssueMu must be held.
func (s *Server) save(caDir string) error {
	b, err := json.MarshalIndent(s.states[caDir], "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, stateFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, stateFile))
}

// newNonce returns a new nonce, dropping the oldest nonces that expired, were used, or are beyond
// limit.
func (s *Server) newNonce(limit int) string {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	now := time.Now()
	for len(s.issued) > 0 && (len(s.issued) >= limit || now.Sub(s.nonces[s.issued[0]]) > acmeNonceLifetime) {
		delete(s.nonces, s.issued[0])
		s.issued = s.issued[1:]
	}
	n := simpleca.RandomID()
	s.nonces[n] = now
	s.issued = append(s.issued, n)
	return n
}

// useNonce reports whether nonce was given out and not used yet, and uses it.
func (s *Server) useNonce(nonce string) bool {
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	t, ok := s.nonces[nonce]
	delete(s.nonces, nonce)
	return ok && time.Since(t) <= acmeNonceLifetime
}

// acmeRequest is a verified ACME request: its payload, empty for a POST-as-GET, and its account
// ID, or its JSON Web Key for a request signed with one.
type acmeRequest struct {
	payload    []byte
	account    string
	jwk        json.RawMessage
	key        crypto.PublicKey
	thumbprint string
}

// acmeCA is the ACME server of one CA for one request: the CA directory, the scheme and host of
// the request, the URL the CA's ACME paths start with, the allowed domains, the limits, and the
// client.
type acmeCA struct {
	*Server
	dir, origin, base string
	domains           []string
	limits            simpleca.ACMEConfig
	client            netip.Addr
}

// Handle serves the ACME request r for the CA in caDir at the ACME path path, below prefix, the
// URL path of the CA's ACME paths; it is 404 Not Found when the CA has no ACME.
func (s *Server) Handle(w http.ResponseWriter, r *http.Request, rootDir, caDir, prefix, path string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil || len(cfg.ACME.Domains) == 0 || !simpleca.FileExists(filepath.Join(caDir, "ca_key.pem")) {
		if err != nil {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		}
		http.NotFound(w, r)
		return
	}
	origin := Origin(r)
	ca := &acmeCA{Server: s, dir: caDir, origin: origin, base: origin + prefix, domains: cfg.ACME.Domains,
		limits: Limits(cfg.ACME), client: ClientAddr(r)}
	w.Header().Set("Link", fmt.Sprintf("<%s/directory>;rel=\"index\"", ca.base))

	switch {
	case path == "directory" && r.Method == http.MethodGet:
		ca.json(w, http.StatusOK, map[string]any{
			"newNonce":   ca.base + "/new-nonce",
			"newAccount": ca.base + "/new-account",
			"newOrder":   ca.base + "/new-order",
			"revokeCert": ca.base + "/revoke-cert",
			"meta":       map[string]any{"externalAccountRequired": false},
		})
		return
	case path == "new-nonce" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		w.Header().Set("Replay-Nonce", s.newNonce(ca.limits.MaxNonces))
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	case r.Method != http.MethodPost:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := ca.verify(r, path == "new-account" || path == "revoke-cert")
	if err == nil {
		err = ca.route(w, req, path)
	}
	if err != nil {
		var p *acmeProblem
		if !errors.As(err, &p) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			p = problem(http.StatusInternalServerError, "serverInternal", "internal error")
		}
		w.Header().Set("Replay-Nonce", s.newNonce(ca.limits.MaxNonces))
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(p.Status)
		json.NewEncoder(w).Encode(p)
	}
}

// json writes v as the JSON response with status and a new nonce.
func (ca *acmeCA) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Replay-Nonce", ca.newNonce(ca.limits.MaxNonces))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// verify reads and verifies the JWS of the ACME request r: its URL, its nonce, and its signature
// by the key of an account, or by the key it carries when jwkAllowed.
func (ca *acmeCA) verify(r *http.Request, jwkAllowed bool) (*acmeRequest, error) {
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != "application/jose+json" {
		return nil, problem(http.StatusUnsupportedMediaType, "malformed", "the content type must be application/jose+json")
	}
	body, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, problem(http.StatusRequestEntityTooLarge, "malformed", "the request is larger than %d bytes", maxBody)
	}
	if err != nil {
		return nil, err
	}
	var jws struct{ Protected, Payload, Signature string }
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, problem(http.StatusBadRequest, "malformed", "the request is not a flattened JWS")
	}
	protected, err1 := base64.RawURLEncoding.DecodeString(jws.Protected)
	payload, err2 := base64.RawURLEncoding.DecodeString(jws.Payload)
	sig, err3 := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, problem(http.StatusBadRequest, "malformed", "the JWS is not in base64url")
	}
	var header struct {
		Alg, Nonce, URL, Kid string
		JWK                  json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(protected, &header); err != nil {
		return nil, problem(http.StatusBadRequest, "malformed", "the protected header is not JSON")
	}
	if header.URL != ca.origin+r.URL.Path {
		return nil, problem(http.StatusUnauthorized, "unauthorized", "the url of the protected header is not that of the request")
	}
	if !ca.useNonce(header.Nonce) {
		return nil, problem(http.StatusBadRequest, "badNonce", "invalid or used nonce")
	}

	req := &acmeRequest{payload: payload}
	switch {
	case header.Kid != "" && header.JWK == nil:
		id, ok := strings.CutPrefix(header.Kid, ca.base+"/acct/")
		cert.IssueMu.Lock()
		st, err := ca.state(ca.dir)
		var acct acmeAccount
		if err == nil && st.Accounts[id] != nil {
			acct = *st.Accounts[id]
		}
		cert.IssueMu.Unlock()
		if err != nil {
			return nil, err
		}
		if !ok || acct.Status == "" {
			return nil, problem(http.StatusBadRequest, "accountDoesNotExist", "no account %s", header.Kid)
		}
		if acct.Status != "valid" {
			return nil, problem(http.StatusUnauthorized, "unauthorized", "the account is %s", acct.Status)
		}
		req.account = id
		req.key, req.thumbprint, err = jose.ParseJWK(acct.Key)
		if err != nil {
			return nil, err
		}
	case header.JWK != nil && header.Kid == "" && jwkAllowed:
		req.jwk = header.JWK
		req.key, req.thumbprint, err = jose.ParseJWK(header.JWK)
		if err != nil {
			return nil, problem(http.StatusBadRequest, "badPublicKey", "%v", err)
		}
	default:
		return nil, problem(http.StatusBadRequest, "malformed", "the request must have either kid or, for this resource, jwk")
	}
	if err := jose.VerifyJWS(header.Alg, req.key, []byte(jws.Protected+"."+jws.Payload), sig); err != nil {
		if errors.Is(err, jose.ErrUnsupportedAlg) {
			return nil, problem(http.StatusBadRequest, "badSignatureAlgorithm", "%v", err)
		}
		return nil, problem(http.StatusBadRequest, "malformed", "%v", err)
	}
	return req, nil
}

// route serves the verified ACME request req at path.
func (ca *acmeCA) route(w http.ResponseWriter, req *acmeRequest, path string) error {
	parts := strings.Split(path, "/")
	switch {
	case path == "new-account":
		return ca.newAccount(w, req)
	case len(parts) == 2 && parts[0] == "acct":
		return ca.account(w, req, parts[1])
	case len(parts) == 3 && parts[0] == "acct" && parts[2] == "orders":
		return ca.accountOrders(w, req, parts[1])
	case path == "new-order":
		return ca.newOrder(w, req)
	case len(parts) == 2 && parts[0] == "order":
		return ca.order(w, req, parts[1])
	case len(parts) == 3 && parts[0] == "order" && parts[2] == "finalize":
		return ca.finalize(w, req, parts[1])
	case len(parts) == 2 && parts[0] == "authz":
		return ca.authz(w, req, parts[1])
	case len(parts) == 3 && parts[0] == "chall":
		return ca.challenge(w, req, parts[1], parts[2])
	case len(parts) == 2 && parts[0] == "cert":
		return ca.certificate(w, req, parts[1])
	case path == "revoke-cert":
		return ca.revoke(w, req)
	}
	return problem(http.StatusNotFound, "malformed", "no resource %s", path)
}

// accountObject returns the account object of the account id.
func (ca *acmeCA) accountObject(id string, a *acmeAccount) map[string]any {
	return map[string]any{"status": a.Status, "contact": a.Contact, "orders": ca.base + "/acct/" + id + "/orders"}
}

// checkContacts returns the problem of contacts that are too many, too long or no mailto: URLs.
func (ca *acmeCA) checkContacts(contacts []string) error {
	if len(contacts) > ca.limits.MaxContacts {
		return problem(http.StatusBadRequest, "invalidContact", "an account has at most %d contacts", ca.limits.MaxContacts)
	}
	for _, c := range contacts {
		if !strings.HasPrefix(c, "mailto:") || len(c) > 254 {
			return problem(http.StatusBadRequest, "unsupportedContact", "contact %q is not a mailto: URL of at most 254 characters", c)
		}
	}
	return nil
}

// newAccount registers the key of req as an account, or returns the account of the key.
func (ca *acmeCA) newAccount(w http.ResponseWriter, req *acmeRequest) error {
	var p struct {
		Contact            []string `json:"contact"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return problem(http.StatusBadRequest, "malformed", "the payload is not an account object")
	}
	if err := ca.checkContacts(p.Contact); err != nil {
		return err
	}
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv,omitempty"`
		X   string `json:"x,omitempty"`
		Y   string `json:"y,omitempty"`
		N   string `json:"n,omitempty"`
		E   string `json:"e,omitempty"`
	}
	json.Unmarshal(req.jwk, &jwk)
	key, err := json.Marshal(jwk)
	if err != nil {
		return err
	}
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	for id, a := range st.Accounts {
		if a.Thumbprint == req.thumbprint {
			w.Header().Set("Location", ca.base+"/acct/"+id)
			ca.json(w, http.StatusOK, ca.accountObject(id, a))
			return nil
		}
	}
	if p.OnlyReturnExisting {
		return problem(http.StatusBadRequest, "accountDoesNotExist", "no account of this key")
	}
	if len(st.Accounts) >= ca.limits.MaxAccounts {
		return problem(http.StatusServiceUnavailable, "rateLimited", "this CA has its %d accounts, acme.max_accounts",
			ca.limits.MaxAccounts)
	}
	id := simpleca.RandomID()
	a := &acmeAccount{Key: key, Thumbprint: req.thumbprint, Contact: p.Contact, Status: "valid"}
	st.Accounts[id] = a
	if err := ca.save(ca.dir); err != nil {
		return err
	}
	w.Header().Set("Location", ca.base+"/acct/"+id)
	ca.json(w, http.StatusCreated, ca.accountObject(id, a))
	return nil
}

// account returns, updates the contacts of or deactivates the account id of req.
func (ca *acmeCA) account(w http.ResponseWriter, req *acmeRequest, id string) error {
	if id != req.account {
		return problem(http.StatusUnauthorized, "unauthorized", "the request is not signed by this account")
	}
	var p struct {
		Contact *[]string `json:"contact"`
		Status  string    `json:"status"`
	}
	if len(req.payload) > 0 {
		if err := json.Unmarshal(req.payload, &p); err != nil {
			return problem(http.StatusBadRequest, "malformed", "the payload is not an account object")
		}
	}
	if p.Contact != nil {
		if err := ca.checkContacts(*p.Contact); err != nil {
			return err
		}
	}
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	a := st.Accounts[id]
	if p.Status != "" && p.Status != "deactivated" {
		return problem(http.StatusBadRequest, "malformed", "an account can only be deactivated")
	}
	if p.Contact != nil || p.Status != "" {
		if p.Contact != nil {
			a.Contact = *p.Contact
		}
		if p.Status != "" {
			a.Status = p.Status
		}
		if err := ca.save(ca.dir); err != nil {
			return err
		}
	}
	ca.json(w, http.StatusOK, ca.accountObject(id, a))
	return nil
}

// accountOrders returns the orders of the account id of req.
func (ca *acmeCA) accountOrders(w http.ResponseWriter, req *acmeRequest, id string) error {
	if id != req.account {
		return problem(http.StatusUnauthorized, "unauthorized", "the request is not signed by this account")
	}
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	urls := []string{}
	for oid, o := range st.Orders {
		if o.Account == id {
			urls = append(urls, ca.base+"/order/"+oid)
		}
	}
	slices.Sort(urls)
	ca.json(w, http.StatusOK, map[string]any{"orders": urls})
	return nil
}

// newOrder creates an order of the account of req for DNS names under the allowed domains, with
// a new pending authorization for each name.
func (ca *acmeCA) newOrder(w http.ResponseWriter, req *acmeRequest) error {
	var p struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
		NotBefore   string                         `json:"notBefore"`
		NotAfter    string                         `json:"notAfter"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil || len(p.Identifiers) == 0 {
		return problem(http.StatusBadRequest, "malformed", "the payload is not an order with identifiers")
	}
	if p.NotBefore != "" || p.NotAfter != "" {
		return problem(http.StatusBadRequest, "malformed", "notBefore and notAfter are not supported")
	}
	if len(p.Identifiers) > ca.limits.MaxNames {
		return problem(http.StatusBadRequest, "malformed", "an order has at most %d identifiers", ca.limits.MaxNames)
	}
	var names []string
	for _, id := range p.Identifiers {
		name := strings.ToLower(id.Value)
		base := strings.TrimPrefix(name, "*.")
		switch {
		case id.Type != "dns":
			return problem(http.StatusBadRequest, "unsupportedIdentifier", "identifier type %q is not supported", id.Type)
		case !simpleca.IsHostname(base):
			return problem(http.StatusBadRequest, "rejectedIdentifier", "%q is not a DNS name", id.Value)
		case !cert.InDomains(base, ca.domains):
			return problem(http.StatusBadRequest, "rejectedIdentifier", "%q is not under the domains of this CA", id.Value)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}

	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	open := 0
	for _, o := range st.Orders {
		if o.Account == req.account && o.Status != "valid" && o.Status != "invalid" {
			open++
		}
	}
	if open >= ca.limits.MaxOrders {
		return problem(http.StatusTooManyRequests, "rateLimited", "the account has its %d open orders, acme.max_orders",
			ca.limits.MaxOrders)
	}
	expires := time.Now().UTC().Add(acmeOrderLifetime).Truncate(time.Second)
	o := &acmeOrder{Account: req.account, Status: "pending", Expires: expires, Names: names}
	for _, name := range names {
		base, wildcard := strings.CutPrefix(name, "*.")
		a := &acmeAuthz{Account: req.account, Name: base, Wildcard: wildcard, Status: "pending", Expires: expires}
		if !wildcard {
			a.Challenges = append(a.Challenges, acmeChallenge{Type: "http-01", Token: simpleca.RandomID(), Status: "pending"})
		}
		a.Challenges = append(a.Challenges, acmeChallenge{Type: "dns-01", Token: simpleca.RandomID(), Status: "pending"})
		aid := simpleca.RandomID()
		st.Authzs[aid] = a
		o.Authzs = append(o.Authzs, aid)
	}
	oid := simpleca.RandomID()
	st.Orders[oid] = o
	if err := ca.save(ca.dir); err != nil {
		return err
	}
	w.Header().Set("Location", ca.base+"/order/"+oid)
	ca.json(w, http.StatusCreated, ca.orderObject(st, oid, o))
	return nil
}

// orderObject returns the order object of the order oid, updating its status from its
// authorizations; cert.IssueMu must be held.
func (ca *acmeCA) orderObject(st *acmeState, oid string, o *acmeOrder) map[string]any {
	if o.Status == "pending" {
		ready := true
		for _, aid := range o.Authzs {
			a := st.Authzs[aid]
			switch {
			case a == nil || (a.Status != "valid" && a.Status != "pending"):
				o.Status = "invalid"
				o.Error = problem(http.StatusForbidden, "unauthorized", "an authorization of the order failed")
			case a.Status != "valid":
				ready = false
			}
		}
		if o.Status == "pending" && ready {
			o.Status = "ready"
		}
	}
	identifiers := []map[string]string{}
	for _, name := range o.Names {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": name})
	}
	authzs := []string{}
	for _, aid := range o.Authzs {
		authzs = append(authzs, ca.base+"/authz/"+aid)
	}
	obj := map[string]any{
		"status":         o.Status,
		"expires":        o.Expires.Format(time.RFC3339),
		"identifiers":    identifiers,
		"authorizations": authzs,
		"finalize":       ca.base + "/order/" + oid + "/finalize",
	}
	if o.Status == "valid" {
		obj["certificate"] = ca.base + "/cert/" + oid
	}
	if o.Error != nil {
		obj["error"] = o.Error
	}
	return obj
}

// ownOrder returns the order oid of the account of req; cert.IssueMu must be held.
func (ca *acmeCA) ownOrder(st *acmeState, req *acmeRequest, oid string) (*acmeOrder, error) {
	o := st.Orders[oid]
	if o == nil {
		return nil, problem(http.StatusNotFound, "malformed", "no order %s", oid)
	}
	if o.Account != req.account {
		return nil, problem(http.StatusUnauthorized, "unauthorized", "the order is of another account")
	}
	return o, nil
}

// order returns the order oid.
func (ca *acmeCA) order(w http.ResponseWriter, req *acmeRequest, oid string) error {
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	o, err := ca.ownOrder(st, req, oid)
	if err != nil {
		return err
	}
	ca.json(w, http.StatusOK, ca.orderObject(st, oid, o))
	return nil
}

// authzObject returns the authorization object of the authorization aid.
func (ca *acmeCA) authzObject(aid string, a *acmeAuthz) map[string]any {
	challenges := []map[string]any{}
	for _, c := range a.Challenges {
		challenges = append(challenges, ca.challengeObject(aid, c))
	}
	obj := map[string]any{
		"identifier": map[string]string{"type": "dns", "value": a.Name},
		"status":     a.Status,
		"expires":    a.Expires.Format(time.RFC3339),
		"challenges": challenges,
	}
	if a.Wildcard {
		obj["wildcard"] = true
	}
	return obj
}

// challengeObject returns the challenge object of c of the authorization aid.
func (ca *acmeCA) challengeObject(aid string, c acmeChallenge) map[string]any {
	obj := map[string]any{"type": c.Type, "url": ca.base + "/chall/" + aid + "/" + c.Type, "token": c.Token, "status": c.Status}
	if c.Validated != nil {
		obj["validated"] = c.Validated.Format(time.RFC3339)
	}
	if c.Error != nil {
		obj["error"] = c.Error
	}
	return obj
}

// ownAuthz returns the authorization aid of the account of req; cert.IssueMu must be held.
func (ca *acmeCA) ownAuthz(st *acmeState, req *acmeRequest, aid string) (*acmeAuthz, error) {
	a := st.Authzs[aid]
	if a == nil {
		return nil, problem(http.StatusNotFound, "malformed", "no authorization %s", aid)
	}
	if a.Account != req.account {
		return nil, problem(http.StatusUnauthorized, "unauthorized", "the authorization is of another account")
	}
	return a, nil
}

// authz returns the authorization aid, or deactivates it.
func (ca *acmeCA) authz(w http.ResponseWriter, req *acmeRequest, aid string) error {
	var p struct{ Status string }
	if len(req.payload) > 0 {
		if err := json.Unmarshal(req.payload, &p); err != nil {
			return problem(http.StatusBadRequest, "malformed", "the payload is not an authorization object")
		}
	}
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	a, err := ca.ownAuthz(st, req, aid)
	if err != nil {
		return err
	}
	switch p.Status {
	case "":
	case "deactivated":
		a.Status = "deactivated"
		if err := ca.save(ca.dir); err != nil {
			return err
		}
	default:
		return problem(http.StatusBadRequest, "malformed", "an authorization can only be deactivated")
	}
	ca.json(w, http.StatusOK, ca.authzObject(aid, a))
	return nil
}

// challenge starts the validation of the challenge typ of the authorization aid, when it is
// pending, and returns it.
func (ca *acmeCA) challenge(w http.ResponseWriter, req *acmeRequest, aid, typ string) error {
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	a, err := ca.ownAuthz(st, req, aid)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(a.Challenges, func(c acmeChallenge) bool { return c.Type == typ })
	if i < 0 {
		return problem(http.StatusNotFound, "malformed", "no challenge %s", typ)
	}
	c := &a.Challenges[i]
	if c.Status == "pending" && a.Status == "pending" && len(req.payload) > 0 {
		c.Status = "processing"
		if err := ca.save(ca.dir); err != nil {
			return err
		}
		go ca.validate(aid, typ, a.Name, c.Token+"."+req.thumbprint)
	}
	w.Header().Add("Link", fmt.Sprintf("<%s/authz/%s>;rel=\"up\"", ca.base, aid))
	ca.json(w, http.StatusOK, ca.challengeObject(aid, *c))
	return nil
}

// validate validates the challenge typ of the authorization aid for name with the key
// authorization keyAuth, and records the result.
func (ca *acmeCA) validate(aid, typ, name, keyAuth string) {
	var failure *acmeProblem
	switch typ {
	case "http-01":
		host := name
		if httpPort != 80 {
			host = net.JoinHostPort(name, strconv.Itoa(httpPort))
		}
		token, _, _ := strings.Cut(keyAuth, ".")
		// A redirect is followed to the same name alone, on the ports of HTTP and HTTPS.
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
			ports := []string{"", "80", "443", strconv.Itoa(httpPort)}
			if len(via) >= 10 || !strings.EqualFold(r.URL.Hostname(), name) || !slices.Contains(ports, r.URL.Port()) {
				return errors.New("redirect to another host or port")
			}
			return nil
		}}
		resp, err := client.Get("http://" + host + "/.well-known/acme-challenge/" + token)
		if err != nil {
			slog.Info("acme.challenge", "dir", ca.dir, "type", typ, "name", name, "error", err.Error())
			failure = problem(http.StatusBadRequest, "connection", "could not fetch the http-01 challenge of %s", name)
			break
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != keyAuth {
			failure = problem(http.StatusForbidden, "incorrectResponse", "the http-01 challenge of %s returned %d and not the key authorization", name, resp.StatusCode)
		}
	case "dns-01":
		sum := sha256.Sum256([]byte(keyAuth))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		records, err := net.DefaultResolver.LookupTXT(ctx, "_acme-challenge."+name)
		cancel()
		switch {
		case err != nil:
			slog.Info("acme.challenge", "dir", ca.dir, "type", typ, "name", name, "error", err.Error())
			failure = problem(http.StatusBadRequest, "dns", "could not look up the TXT record of _acme-challenge.%s", name)
		case !slices.Contains(records, want):
			failure = problem(http.StatusForbidden, "incorrectResponse", "no TXT record of _acme-challenge.%s holds the key authorization digest", name)
		}
	}

	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		slog.Error("serve.error", "dir", ca.dir, "error", err.Error())
		return
	}
	a := st.Authzs[aid]
	if a == nil {
		return
	}
	for i := range a.Challenges {
		c := &a.Challenges[i]
		if c.Type != typ {
			continue
		}
		if failure != nil {
			c.Status, c.Error, a.Status = "invalid", failure, "invalid"
			slog.Info("acme.challenge", "dir", ca.dir, "type", typ, "name", name, "status", "invalid", "detail", failure.Detail)
		} else {
			now := time.Now().UTC().Truncate(time.Second)
			c.Status, c.Validated, a.Status = "valid", &now, "valid"
			slog.Info("acme.challenge", "dir", ca.dir, "type", typ, "name", name, "status", "valid")
		}
	}
	if err := ca.save(ca.dir); err != nil {
		slog.Error("serve.error", "dir", ca.dir, "error", err.Error())
	}
}

// finalize issues the certificate of the ready order oid for its CSR, a server certificate whose
// CN is the first name of the order and whose DNS names are all of them, valid for acme.days,
// 90 days without it, and records it in index.txt.
func (ca *acmeCA) finalize(w http.ResponseWriter, req *acmeRequest, oid string) error {
	var p struct{ CSR string }
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return problem(http.StatusBadRequest, "malformed", "the payload has no csr")
	}
	der, err := base64.RawURLEncoding.DecodeString(p.CSR)
	if err != nil {
		return problem(http.StatusBadRequest, "badCSR", "the csr is not in base64url")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return problem(http.StatusBadRequest, "badCSR", "the csr does not parse or its signature is invalid")
	}
	if key, ok := req.key.(interface{ Equal(crypto.PublicKey) bool }); ok && key.Equal(csr.PublicKey) {
		return problem(http.StatusBadRequest, "badCSR", "the key of the csr is the account key")
	}

	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	o, err := ca.ownOrder(st, req, oid)
	if err != nil {
		return err
	}
	ca.orderObject(st, oid, o)
	if o.Status != "ready" {
		return problem(http.StatusForbidden, "orderNotReady", "the order is %s", o.Status)
	}
	var requested []string
	for _, n := range append([]string{csr.Subject.CommonName}, csr.DNSNames...) {
		if n = strings.ToLower(n); n != "" && !slices.Contains(requested, n) {
			requested = append(requested, n)
		}
	}
	ordered := slices.Clone(o.Names)
	slices.Sort(requested)
	slices.Sort(ordered)
	if !slices.Equal(requested, ordered) || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return problem(http.StatusBadRequest, "badCSR", "the names of the csr are not those of the order")
	}

	cfg, err := simpleca.LoadRootConfig(ca.dir)
	if err != nil {
		return err
	}
	days := 90
	if cfg.ACME.Days > 0 {
		days = cfg.ACME.Days
	}
	// The certificate is stored as the commands store it, named after the first name of the order
	// by the server rules, and replaces an earlier certificate of the name that has no key beside it.
	file, err := cert.CertFile(cert.CertFileName(strings.TrimPrefix(o.Names[0], "*."), "", false))
	if err != nil {
		return problem(http.StatusBadRequest, "rejectedIdentifier", "%v", err)
	}
	if simpleca.FileExists(filepath.Join(ca.dir, strings.TrimSuffix(file, "_cert.pem")+"_key.pem")) {
		return problem(http.StatusConflict, "rejectedIdentifier", "the CA holds a certificate %s with its key, which is not replaced", file)
	}
	caCert, err := simpleca.LoadCert(filepath.Join(ca.dir, "ca_cert.pem"))
	if err != nil {
		return err
	}
	if err := cert.CheckValidity(caCert, time.Now(), days); err != nil {
		return problem(http.StatusInternalServerError, "serverInternal", "acme.days: %v", err)
	}
	tmpl := &x509.Certificate{DNSNames: o.Names}
	if len(o.Names[0]) <= 64 {
		tmpl.Subject = pkix.Name{CommonName: o.Names[0]}
	}
	crt, err := cert.IssueLeaf(ca.dir, "server", days, nil, nil, tmpl, csr.PublicKey)
	if err != nil {
		return err
	}
	if err := cert.StoreCert(ca.dir, filepath.Join(ca.dir, file), crt); err != nil {
		return err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	}
	o.Status, o.Chain = "valid", string(chain)
	st.Certs[cert.SerialHex(crt.SerialNumber)] = req.account
	if err := ca.save(ca.dir); err != nil {
		return err
	}
	cert.AuditIssued(ca.dir, crt, "server", "via", "acme", "actor", req.account, "client", ca.client.String())
	w.Header().Set("Location", ca.base+"/order/"+oid)
	ca.json(w, http.StatusOK, ca.orderObject(st, oid, o))
	return nil
}

// certificate returns the certificate chain of the valid order oid.
func (ca *acmeCA) certificate(w http.ResponseWriter, req *acmeRequest, oid string) error {
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	o, err := ca.ownOrder(st, req, oid)
	if err != nil {
		return err
	}
	if o.Status != "valid" {
		return problem(http.StatusNotFound, "malformed", "the order has no certificate")
	}
	w.Header().Set("Replay-Nonce", ca.newNonce(ca.limits.MaxNonces))
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	io.WriteString(w, o.Chain)
	return nil
}

// revoke revokes a certificate of this CA, for the account it was issued to, or signed with the
// key of the certificate, for a reason from 0 to 5.
func (ca *acmeCA) revoke(w http.ResponseWriter, req *acmeRequest) error {
	var p struct {
		Certificate string `json:"certificate"`
		Reason      *int   `json:"reason"`
	}
	if err := json.Unmarshal(req.payload, &p); err != nil {
		return problem(http.StatusBadRequest, "malformed", "the payload has no certificate")
	}
	der, err := base64.RawURLEncoding.DecodeString(p.Certificate)
	if err != nil {
		return problem(http.StatusBadRequest, "malformed", "the certificate is not in base64url")
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return problem(http.StatusBadRequest, "malformed", "the certificate does not parse")
	}
	caCert, err := simpleca.LoadCert(filepath.Join(ca.dir, "ca_cert.pem"))
	if err != nil {
		return err
	}
	if crt.CheckSignatureFrom(caCert) != nil {
		return problem(http.StatusNotFound, "malformed", "the certificate is not of this CA")
	}
	reason := ""
	if p.Reason != nil {
		if *p.Reason < 0 || *p.Reason > 5 {
			return problem(http.StatusBadRequest, "badRevocationReason", "reason %d is not supported", *p.Reason)
		}
		reason = cert.CRLReasons[*p.Reason].Name
	}

	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	st, err := ca.state(ca.dir)
	if err != nil {
		return err
	}
	serial := cert.SerialHex(crt.SerialNumber)
	authorized := req.account != "" && st.Certs[serial] == req.account
	if req.jwk != nil {
		certKey, err1 := x509.MarshalPKIXPublicKey(crt.PublicKey)
		jwsKey, err2 := x509.MarshalPKIXPublicKey(req.key)
		authorized = err1 == nil && err2 == nil && bytes.Equal(certKey, jwsKey)
	}
	if !authorized {
		return problem(http.StatusForbidden, "unauthorized", "neither the account of the certificate nor its key signed the request")
	}
	revoked, err := cert.MarkRevoked(ca.dir, serial, reason)
	if err != nil {
		return problem(http.StatusNotFound, "malformed", "%v", err)
	}
	if !revoked {
		return problem(http.StatusBadRequest, "alreadyRevoked", "the certificate is revoked already")
	}
	simpleca.Audit(ca.dir, "cert.revoke", "serial", serial, "reason", reason, "via", "acme", "actor", req.account,
		"client", ca.client.String())
	w.Header().Set("Replay-Nonce", ca.newNonce(ca.limits.MaxNonces))
	w.WriteHeader(http.StatusOK)
	return nil
}

// Limits returns the settings with the default of each limit that is not set.
func Limits(c simpleca.ACMEConfig) simpleca.ACMEConfig {
	set := func(limit *int, byDefault int) {
		if *limit < 1 {
			*limit = byDefault
		}
	}
	set(&c.MaxAccounts, 1000)
	set(&c.MaxOrders, 50)
	set(&c.MaxNames, 100)
	set(&c.MaxContacts, 10)
	set(&c.MaxNonces, 100000)
	return c
}
