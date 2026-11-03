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
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ---- the token and certificate pages of serve -------------------------------

// tokensPath is the route serve --webui shows the token page under, and certsPath the route of
// the certificate page.
const (
	tokensPath = "/tokens/"
	certsPath  = "/certificates/"
)

// webuiScripts are the scripts of the pages, served at their paths: theme.js, which every page
// loads in its head; picker.js and webui.js, which both pages load, then tokens.js or certs.js;
// the signing form of serve loads picker.js and sign.js, its setup code page picker.js and
// setup.js, and its index page picker.js and index.js.
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

// webuiServer serves the token page, or the certificate page with certs, for the root CA in
// rootDir and its issuing CAs, below tokensPath or certsPath with the prefix stripped: the page at
// /, and its API below /api/, for the requests carrying a token with the scope tokens, or certs,
// as their bearer token, from the clients the token allows, the address of a client behind the
// trusted proxies read from X-Forwarded-For. A copy of it answers each request, with the name, the
// CA ID, the scopes and the entry of the token of the request.
type webuiServer struct {
	rootDir    string
	trusted    []netip.Prefix
	certs      bool
	user       string
	userCA     string
	userScopes []string
	userToken  *apiToken
}

// webuiCA is a CA of the API: its ID, empty for the root CA, its role, its subject, its label in
// the selector, whether its key is here to sign tokens, and the CSS of the colours of its
// theme.json, which the page takes while it shows the CA.
type webuiCA struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	subjectView
	Label  string `json:"label"`
	HasKey bool   `json:"has_key"`
	Theme  string `json:"theme"`
}

// webuiDefaults are the values the form creating a token starts with, from tokens of
// simple-ca.json; the scopes are those of them the token of the request grants, and the validity
// of a setup code is tokenSetupValid.
type webuiDefaults struct {
	Valid     string   `json:"valid"`
	Scopes    []string `json:"scopes"`
	Types     []string `json:"types"`
	Domains   []string `json:"domains"`
	IPs       []string `json:"ips"`
	Clients   []string `json:"clients"`
	Localhost bool     `json:"localhost"`
	OTCValid  string   `json:"otc_valid"`
}

// webuiToken is a token of the API: its name, its expiry, the expiry of its setup code when it is
// pending, whether it was revoked or expired, whether it waits for its setup code, its scopes, what
// it allows, the clients it is accepted from, and the count of certificates issued with it.
type webuiToken struct {
	Name    string    `json:"name"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked"`
	Expired bool      `json:"expired"`
	Pending bool      `json:"pending"`
	Scopes  []string  `json:"scopes"`
	Types   []string  `json:"types"`
	Domains []string  `json:"domains"`
	IPs     []string  `json:"ips"`
	Clients []string  `json:"clients"`
	Certs   int       `json:"certs"`
}

// webuiRequest is the body of a request changing the tokens of the CA CA: the token Name, and,
// to create it, its validity, its scopes, its certificate types, domains, IP addresses and
// clients, and localhost, and, to create or renew it with a setup code in place of its JWT, OTC,
// the validity of the code and the clients it is exchanged from.
type webuiRequest struct {
	CA          string   `json:"ca"`
	Name        string   `json:"name"`
	Valid       string   `json:"valid"`
	Scopes      []string `json:"scopes"`
	Types       []string `json:"types"`
	Domains     []string `json:"domains"`
	IPs         []string `json:"ips"`
	Clients     []string `json:"clients"`
	Localhost   bool     `json:"localhost"`
	OTC         bool     `json:"otc"`
	OTCValid    string   `json:"otc_valid"`
	OTCNetworks []string `json:"otc_networks"`
}

// caDir returns the directory of the CA id, the root CA when id is empty, or false for an id
// that is not an issuing CA of the root CA, or is not the CA of an issuing CA token.
func (s *webuiServer) caDir(id string) (string, bool) {
	if s.userCA != "" && id != s.userCA {
		return "", false
	}
	if id == "" {
		return s.rootDir, true
	}
	if !kebabCaseRE.MatchString(id) || !fileExists(filepath.Join(s.rootDir, id, "ca_cert.pem")) {
		return "", false
	}
	return filepath.Join(s.rootDir, id), true
}

// authenticate takes the bearer token of r, a token of the root CA or of one of its issuing CAs
// with the scope of the webui, used from a client it allows, and keeps its name, its CA and its
// scopes; for any other it answers with the error and returns false.
func (s *webuiServer) authenticate(w http.ResponseWriter, r *http.Request) bool {
	scope := "tokens"
	if s.certs {
		scope = "certs"
	}
	fail := func(status int, message string) bool {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="simple-ca webui"`)
		}
		webuiFail(w, status, message)
		return false
	}
	given, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if given = strings.TrimSpace(given); given == "" {
		return fail(http.StatusUnauthorized, "a token with the scope "+scope+" is required")
	}
	for _, id := range caIDs(s.rootDir) {
		dir := filepath.Join(s.rootDir, id)
		caCert, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
		if err != nil {
			continue
		}
		claims, err := verifyJWT(caCert, given)
		if err != nil {
			continue
		}
		db, err := loadTokens(dir)
		if err != nil {
			log.Printf("webui: %v", err)
			return fail(http.StatusInternalServerError, "could not read the tokens")
		}
		name, tok, err := lookupToken(db, claims)
		var refused *apiError
		if errors.As(err, &refused) {
			return fail(refused.status, refused.msg)
		}
		client := clientAddr(r, s.trusted)
		switch {
		case !tok.hasScope(scope):
			return fail(http.StatusForbidden, "the token does not have the scope "+scope)
		case !tok.clientAllowed(client):
			return fail(http.StatusForbidden, "the token is not allowed from "+client.String())
		}
		s.user, s.userCA, s.userScopes, s.userToken = name, id, tok.scopes(), tok
		return true
	}
	return fail(http.StatusUnauthorized, "invalid token")
}

// grants reports whether the token of the request may grant the scopes: sign, and the scopes it
// has itself, every scope with the scope *.
func (s *webuiServer) grants(scopes []string) bool {
	return !slices.ContainsFunc(scopes, func(scope string) bool {
		return scope != "sign" && !allows(s.userScopes, scope)
	})
}

// mux returns the routes of the page, which asks for the token and draws the tokens or the
// certificates from the API, and of the API; serve serves the scripts and Tailwind CSS it loads.
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

// api answers a request of the API carrying a token of the webui as its bearer token: GET
// /api/cas, the CAs the token opens with what the forms of the page start with, and the requests
// of the tokens or the certificates.
func (s *webuiServer) api(w http.ResponseWriter, r *http.Request) {
	ui := *s
	if !ui.authenticate(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/cas":
		ui.listCAs(w)
	case ui.certs:
		ui.certAPI(w, r)
	default:
		ui.tokenAPI(w, r)
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
	db, err := loadTokens(dir)
	if err != nil {
		log.Printf("webui: %v", err)
		webuiFail(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A token is renewed, revoked or removed only by a token that may grant its scopes.
	if t, ok := db.Tokens[req.Name]; ok && r.URL.Path != "/api/tokens" && !s.grants(t.scopes()) {
		webuiFail(w, http.StatusForbidden, "your token cannot manage '"+req.Name+"': it has a scope your token does not have")
		return
	}
	// A token created or renewed with a setup code gets the code in place of its JWT.
	var setupValid time.Duration
	if req.OTC {
		if setupValid, err = time.ParseDuration(strings.TrimSpace(req.OTCValid)); err != nil {
			webuiFail(w, http.StatusBadRequest, "otc_valid: '"+req.OTCValid+"' is not a duration such as 15m")
			return
		}
	}
	answer := func(status int, name, token string) {
		key := "token"
		if req.OTC {
			key = "code"
		}
		webuiReply(w, status, map[string]string{"name": name, key: token})
	}
	switch r.URL.Path {
	case "/api/tokens":
		valid, err := time.ParseDuration(strings.TrimSpace(req.Valid))
		if err != nil {
			webuiFail(w, http.StatusBadRequest, "valid: '"+req.Valid+"' is not a duration such as 8h")
			return
		}
		scopes := req.Scopes
		if len(scopes) == 0 {
			scopes = []string{"sign"}
		}
		if !s.grants(scopes) {
			webuiFail(w, http.StatusForbidden, "your token can only grant the scopes sign, "+
				strings.Join(s.userScopes, ", "))
			return
		}
		domains, ips, types := req.Domains, req.IPs, req.Types
		if allows(scopes, "sign") {
			if req.Localhost {
				domains, ips = append(domains, "localhost"), append(ips, "127.0.0.1")
			}
			if len(types) == 0 {
				types = []string{"server"}
			}
		}
		token, err := addToken(dir, req.Name, valid, scopes, types, domains, ips, req.Clients, setupValid, req.OTCNetworks)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("token %s of %s created by %s", req.Name, dir, s.user)
		answer(http.StatusCreated, req.Name, token)
	case "/api/tokens/renew":
		token, err := reissueToken(dir, req.Name, 0, setupValid, req.OTCNetworks)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("token %s of %s renewed by %s", req.Name, dir, s.user)
		answer(http.StatusOK, req.Name, token)
	case "/api/tokens/revoke":
		if err := revokeToken(dir, req.Name); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("token %s of %s revoked by %s", req.Name, dir, s.user)
		webuiReply(w, http.StatusOK, map[string]string{"name": req.Name})
	case "/api/tokens/purge":
		if req.Name != "" {
			if err := purgeToken(dir, req.Name); err != nil {
				webuiFail(w, http.StatusBadRequest, err.Error())
				return
			}
			log.Printf("token %s of %s removed by %s", req.Name, dir, s.user)
			webuiReply(w, http.StatusOK, map[string]int{"removed": 1})
			return
		}
		// Every expired or revoked token is removed that the token of the request may grant.
		now, n := time.Now(), 0
		for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
			if t := db.Tokens[name]; !now.Before(t.Expires) && s.grants(t.scopes()) {
				if err := purgeToken(dir, name); err != nil {
					webuiFail(w, http.StatusInternalServerError, err.Error())
					return
				}
				n++
			}
		}
		log.Printf("%d tokens of %s removed by %s", n, dir, s.user)
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

	var cas []webuiCA
	for _, id := range caIDs(s.rootDir) {
		dir, ok := s.caDir(id)
		if !ok {
			continue
		}
		cert, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
		if err != nil {
			log.Printf("webui: %v", err)
			continue
		}
		ca := webuiCA{ID: id, Role: "root CA", subjectView: newSubjectView(nameString(cert.Subject)),
			Label: "root CA: " + cert.Subject.CommonName, HasKey: fileExists(filepath.Join(dir, "ca_key.pem")),
			Theme: string(pageTheme(dir))}
		if id != "" {
			ca.Role, ca.Label = "issuing CA "+id, "issuing CA "+id+": "+cert.Subject.CommonName
		}
		cas = append(cas, ca)
	}

	answer := map[string]any{"title": rootCert.Subject.CommonName, "types": slices.Sorted(maps.Keys(types)), "cas": cas,
		"user": s.user, "user_ca": s.userCA, "user_attributes": describeToken(s.user, s.userToken, true)}
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
			Clients: append(slices.Clone(cfg.Tokens.Hosts), cfg.Tokens.Networks...), Localhost: cfg.Tokens.Localhost,
			OTCValid: durationText(tokenSetupValid)}
		if len(defaults.Types) == 0 {
			defaults.Types = []string{"server"}
		}
		// The scopes the token of the request grants, and the default ones among them.
		grantable := slices.DeleteFunc(append(slices.Clone(tokenScopes), "*"), func(scope string) bool { return !s.grants([]string{scope}) })
		defaults.Scopes = slices.DeleteFunc(slices.Clone(cfg.Tokens.Scopes), func(scope string) bool {
			return !slices.Contains(grantable, scope)
		})
		if len(defaults.Scopes) == 0 {
			defaults.Scopes = []string{"sign"}
		}
		answer["scopes"], answer["defaults"] = grantable, defaults
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
			Expired: !now.Before(t.Expires), Pending: t.pending(), Scopes: t.scopes(), Types: t.Types, Domains: t.Domains, IPs: showPrefixes(t.IPs),
			Clients: showPrefixes(t.Clients), Certs: len(t.Certs)})
	}
	webuiReply(w, http.StatusOK, map[string][]webuiToken{"tokens": tokens})
}
