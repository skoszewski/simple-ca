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
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ---- token webui and cert webui ---------------------------------------------

// webuiScripts are the scripts of the pages, served at their paths: picker.js and webui.js, which
// both pages load, then tokens.js or certs.js; the signing form of serve loads picker.js and
// sign.js, and its index page index.js.
//
//go:embed assets/webui/*.js
var webuiScripts embed.FS

// webuiScriptHandler serves the script of webuiScripts named by the path value file.
var webuiScriptHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if !strings.HasSuffix(file, ".js") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, webuiScripts, "assets/webui/"+file)
})

// webuiServer serves token webui, or cert webui with certs, for the root CA in rootDir and its
// issuing CAs: the page at /, and its API below /api/, for the requests carrying key as their
// bearer token.
type webuiServer struct {
	rootDir string
	key     string
	certs   bool
}

// webuiCA is a CA of the API: its ID, empty for the root CA, its role, its subject, its label in
// the selector, and whether its key is here to sign tokens.
type webuiCA struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Subject string `json:"subject"`
	Label   string `json:"label"`
	HasKey  bool   `json:"has_key"`
}

// webuiDefaults are the values the form creating a token starts with, from tokens of
// simple-ca.json.
type webuiDefaults struct {
	Valid     string   `json:"valid"`
	Types     []string `json:"types"`
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Clients   []string `json:"clients"`
	Localhost bool     `json:"localhost"`
}

// webuiToken is a token of the API: its name, its expiry, whether it was revoked or expired, what
// it allows, the clients it is accepted from, and the count of certificates issued with it.
type webuiToken struct {
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked"`
	Expired bool      `json:"expired"`
	Types   []string  `json:"types"`
	Domains []string  `json:"domains"`
	IPs     []string  `json:"ips"`
	Clients []string  `json:"clients"`
	Certs   int       `json:"certs"`
}

// webuiRequest is the body of a request changing the tokens of the CA CA: the token Name, and,
// to create it, its validity, its certificate types, domains, IP addresses and clients, and
// localhost.
type webuiRequest struct {
	CA        string   `json:"ca"`
	Name      string   `json:"name"`
	Valid     string   `json:"valid"`
	Types     []string `json:"types"`
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Clients   []string `json:"clients"`
	Localhost bool     `json:"localhost"`
}

// caDir returns the directory of the CA id, the root CA when id is empty, or false for an id
// that is not an issuing CA of the root CA.
func (s *webuiServer) caDir(id string) (string, bool) {
	if id == "" {
		return s.rootDir, true
	}
	if !kebabCaseRE.MatchString(id) || !fileExists(filepath.Join(s.rootDir, id, "ca_cert.pem")) {
		return "", false
	}
	return filepath.Join(s.rootDir, id), true
}

// mux returns the routes of the webui: the page, which asks for the key and draws the tokens or
// the certificates from the API, its scripts, the browser build of Tailwind CSS, and the API.
func (s *webuiServer) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		page := "tokens.html"
		if s.certs {
			page = "certs.html"
		}
		if err := pageTemplates.ExecuteTemplate(w, page, struct{ Script string }{tailwindPath}); err != nil {
			log.Printf("webui: %v", err)
		}
	})
	mux.Handle("GET "+tailwindPath, tailwindHandler)
	mux.Handle("GET /assets/webui/{file}", webuiScriptHandler)
	mux.HandleFunc("/api/", s.api)
	return mux
}

// webuiReply writes v as the JSON answer of the API with status.
func webuiReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// webuiFail writes the error message of the API with status.
func webuiFail(w http.ResponseWriter, status int, message string) {
	webuiReply(w, status, map[string]string{"error": message})
}

// api answers a request of the API carrying the key as its bearer token: GET /api/cas, the CAs
// with what the forms of the page start with, and the requests of the tokens or the certificates.
func (s *webuiServer) api(w http.ResponseWriter, r *http.Request) {
	given, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(given), []byte(s.key)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="simple-ca webui"`)
		webuiFail(w, http.StatusUnauthorized, "the key printed at the start is required")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/cas":
		s.listCAs(w)
	case s.certs:
		s.certAPI(w, r)
	default:
		s.tokenAPI(w, r)
	}
}

// webuiDecode reads the JSON body of a request into v, refusing an unknown field, and answers with
// the error when it does not read.
func webuiDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, acmeMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object of the request")
		return false
	}
	return true
}

// tokenAPI answers a request of the tokens:
//
//	GET  /api/tokens?ca=ID    the tokens of a CA
//	POST /api/tokens          creates a token and returns it
//	POST /api/tokens/renew    renews a token and returns it
//	POST /api/tokens/revoke   revokes a token
//	POST /api/tokens/purge    removes a token, expired or revoked, or every such token
func (s *webuiServer) tokenAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/tokens":
		dir, ok := s.caDir(r.URL.Query().Get("ca"))
		if !ok {
			webuiFail(w, http.StatusNotFound, "no such CA")
			return
		}
		s.listTokens(w, dir)
		return
	case r.Method != http.MethodPost ||
		!slices.Contains([]string{"/api/tokens", "/api/tokens/renew", "/api/tokens/revoke", "/api/tokens/purge"}, r.URL.Path):
		webuiFail(w, http.StatusNotFound, "no such request")
		return
	}

	var req webuiRequest
	if !webuiDecode(w, r, &req) {
		return
	}
	dir, ok := s.caDir(req.CA)
	if !ok {
		webuiFail(w, http.StatusNotFound, "no such CA")
		return
	}
	switch r.URL.Path {
	case "/api/tokens":
		valid, err := time.ParseDuration(strings.TrimSpace(req.Valid))
		if err != nil {
			webuiFail(w, http.StatusBadRequest, "valid: '"+req.Valid+"' is not a duration such as 8h")
			return
		}
		domains, ips := req.Domains, req.IPs
		if req.Localhost {
			domains, ips = append(domains, "localhost"), append(ips, "127.0.0.1")
		}
		types := req.Types
		if len(types) == 0 {
			types = []string{"server"}
		}
		token, err := makeToken(dir, req.Name, valid, types, domains, ips, req.Clients)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("token %s of %s created", req.Name, dir)
		webuiReply(w, http.StatusCreated, map[string]string{"name": req.Name, "token": token})
	case "/api/tokens/renew":
		token, err := renewToken(dir, req.Name, 0)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("token %s of %s renewed", req.Name, dir)
		webuiReply(w, http.StatusOK, map[string]string{"name": req.Name, "token": token})
	case "/api/tokens/revoke":
		if err := revokeToken(dir, req.Name); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		webuiReply(w, http.StatusOK, map[string]string{"name": req.Name})
	case "/api/tokens/purge":
		if req.Name != "" {
			if err := purgeToken(dir, req.Name); err != nil {
				webuiFail(w, http.StatusBadRequest, err.Error())
				return
			}
			webuiReply(w, http.StatusOK, map[string]int{"removed": 1})
			return
		}
		n, err := purgeTokens(dir, 0)
		if err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		webuiReply(w, http.StatusOK, map[string]int{"removed": n})
	}
}

// listCAs answers with the root CA and its issuing CAs, the certificate types and the defaults of
// a new token.
func (s *webuiServer) listCAs(w http.ResponseWriter) {
	cfg, err := loadConfig(s.rootDir)
	var types map[string]certTypeDef
	if err == nil {
		types, err = cfg.certTypes()
	}
	rootCert, err2 := loadCert(filepath.Join(s.rootDir, "ca_cert.pem"))
	if err := cmp.Or(err, err2); err != nil {
		log.Printf("webui: %v", err)
		webuiFail(w, http.StatusInternalServerError, "could not read the CA")
		return
	}

	ids := []string{""}
	entries, _ := os.ReadDir(s.rootDir)
	for _, e := range entries {
		if e.IsDir() && kebabCaseRE.MatchString(e.Name()) && fileExists(filepath.Join(s.rootDir, e.Name(), "ca_cert.pem")) {
			ids = append(ids, e.Name())
		}
	}
	var cas []webuiCA
	for _, id := range ids {
		dir, _ := s.caDir(id)
		cert, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
		if err != nil {
			log.Printf("webui: %v", err)
			continue
		}
		ca := webuiCA{ID: id, Role: "root CA", Subject: nameString(cert.Subject),
			Label: "root CA: " + cert.Subject.CommonName, HasKey: fileExists(filepath.Join(dir, "ca_key.pem"))}
		if id != "" {
			ca.Role, ca.Label = "issuing CA "+id, "issuing CA "+id+": "+cert.Subject.CommonName
		}
		cas = append(cas, ca)
	}

	answer := map[string]any{"title": rootCert.Subject.CommonName, "types": slices.Sorted(maps.Keys(types)), "cas": cas}
	if s.certs {
		// The certificate page tells the name rules of each type, the revocation reasons, and the
		// validity of a certificate and of a CRL in days.
		names := map[string]string{}
		for name, t := range types {
			names[name] = t.names
		}
		var reasons []string
		for _, r := range crlReasons[:6] {
			reasons = append(reasons, r.name)
		}
		answer["names"], answer["reasons"] = names, reasons
		answer["defaults"] = map[string]int{"days": cmp.Or(cfg.Days.Cert, 365), "crl_days": cmp.Or(cfg.Days.CRL, 30)}
	} else {
		defaults := webuiDefaults{Valid: cmp.Or(cfg.Tokens.Valid, "1h"), Types: cfg.Tokens.Types,
			Domains: cfg.Tokens.Domains, IPs: cfg.Tokens.IPs,
			Clients: append(slices.Clone(cfg.Tokens.Hosts), cfg.Tokens.Networks...), Localhost: cfg.Tokens.Localhost}
		if len(defaults.Types) == 0 {
			defaults.Types = []string{"server"}
		}
		answer["defaults"] = defaults
	}
	webuiReply(w, http.StatusOK, answer)
}

// listTokens answers with the tokens of the CA in dir, sorted by name.
func (s *webuiServer) listTokens(w http.ResponseWriter, dir string) {
	db, err := loadTokens(dir)
	if err != nil {
		log.Printf("webui: %v", err)
		webuiFail(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	tokens := []webuiToken{}
	for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
		t := db.Tokens[name]
		tokens = append(tokens, webuiToken{Name: name, Expires: t.Expires, Revoked: t.revoked(),
			Expired: !now.Before(t.Expires), Types: t.Types, Domains: t.Domains, IPs: showPrefixes(t.IPs),
			Clients: showPrefixes(t.Clients), Certs: len(t.Certs)})
	}
	webuiReply(w, http.StatusOK, map[string][]webuiToken{"tokens": tokens})
}
