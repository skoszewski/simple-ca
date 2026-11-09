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
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ---- the token and certificate pages of serve -------------------------------

// tokensPath is the route serve --webui shows the token page under, certsPath the route of the
// certificate page, and auditPagePath that of the audit page.
const (
	tokensPath    = "/tokens/"
	certsPath     = "/certificates/"
	auditPagePath = "/audit/"
)

// webuiScripts are the scripts of the pages, served at their paths: theme.js, which every page
// loads in its head; picker.js, oidc.js and webui.js, which both pages load, then tokens.js or
// certs.js; the signing form of serve loads picker.js, oidc.js and sign.js, its setup code page
// picker.js, oidc.js and setup.js, its OIDC callback page oidc.js, and its index page picker.js
// and index.js.
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

// webuiServer serves the page of its scope, the token page for tokens, the certificate page for
// certs or the audit page for audit, for the root CA in rootDir and its issuing CAs, below its
// path with the prefix stripped: the page at /, and its API below /api/, for the requests carrying
// a token with that scope as their bearer token, from the clients the token allows, the address of a client behind the
// trusted proxies read from X-Forwarded-For. A copy of it answers each request, with the name, the
// CA ID, the scopes and the entry of the token of the request, and its client.
type webuiServer struct {
	rootDir    string
	scope      string
	user       string
	userCA     string
	userScopes []string
	userToken  *apiToken
	client     netip.Addr
}

// auditActor returns the audit pairs naming the token of the request, its OIDC user, and the
// client.
func (s *webuiServer) auditActor() []any {
	pairs := []any{"via", "webui", "actor", s.user}
	if s.userToken != nil && s.userToken.OIDC != nil {
		pairs = append(pairs, "oidc_user", s.userToken.OIDC.User)
	}
	return append(pairs, "client", s.client.String())
}

// webuiCA is a CA of the API: its ID, empty for the root CA, the attributes of its subject, each a
// type and a value, whether its key is here to sign tokens, and the colours of its theme.json,
// which the page takes while it shows the CA.
type webuiCA struct {
	ID      string      `json:"id"`
	Subject [][2]string `json:"subject"`
	HasKey  bool        `json:"has_key"`
	Theme   themeConfig `json:"theme"`
}

// webuiDefaults are the values the form creating a token starts with, from tokens of
// simple-ca.json; the scopes are those of them the token of the request grants, and the validity
// of a setup code is tokenSetupValid.
type webuiDefaults struct {
	Valid    string   `json:"valid"`
	Scopes   []string `json:"scopes"`
	Types    []string `json:"types"`
	Domains  []string `json:"domains"`
	IPs      []string `json:"ips"`
	Clients  []string `json:"clients"`
	OTCValid string   `json:"otc_valid"`
}

// webuiToken is a token of the API: its name, its issue time and its expiry, the expiry of its
// setup code when it is pending, whether it was revoked or expired, whether it waits for its setup
// code, its scopes, what it allows, the clients it is accepted from, the serials of the
// certificates issued with it, the OIDC user it was made for, null for another token, and the JWT
// of a token type it gets with the scope federate, null without it.
type webuiToken struct {
	Name     string         `json:"name"`
	Issued   time.Time      `json:"issued"`
	Expires  time.Time      `json:"expires"`
	Valid    string         `json:"valid"`
	Revoked  bool           `json:"revoked"`
	Expired  bool           `json:"expired"`
	Pending  bool           `json:"pending"`
	Scopes   []string       `json:"scopes"`
	Types    []string       `json:"types"`
	Domains  []string       `json:"domains"`
	IPs      []string       `json:"ips"`
	Clients  []string       `json:"clients"`
	Certs    []string       `json:"certs"`
	OIDC     *tokenOIDC     `json:"oidc"`
	Federate *tokenFederate `json:"federate"`
}

// newWebuiToken returns the token name of tokens-db.json, t, as the API answers with it, expired
// or not at the time now.
func newWebuiToken(name string, t *apiToken, now time.Time) webuiToken {
	// The validity token renew keeps: that of the token, or of a pending token once its code is
	// exchanged; none for a revoked token, which takes the default of token create.
	valid := ""
	switch {
	case t.pending():
		if d, err := t.Setup.valid(); err == nil {
			valid = durationText(d)
		}
	case !t.revoked():
		valid = durationText(t.Expires.Sub(t.Issued))
	}
	return webuiToken{Name: name, Issued: t.Issued, Expires: t.Expires, Valid: valid, Revoked: t.revoked(),
		Expired: !now.Before(t.Expires), Pending: t.pending(), Scopes: t.scopes(), Types: t.Types, Domains: t.Domains,
		IPs: t.IPs, Clients: t.Clients, Certs: append([]string{}, t.Certs...), OIDC: t.OIDC, Federate: t.Federate}
}

// webuiRequest is the body of a request changing the tokens of the CA CA: the token Name, and,
// to create it, its validity, its scopes, its certificate types, domains, IP addresses and
// clients, localhost, and the JWT of a token type of the scope federate, and, to create or renew it
// with a setup code in place of its JWT, OTC, the validity of the code and the clients it is
// exchanged from.
type webuiRequest struct {
	CA          string         `json:"ca"`
	Name        string         `json:"name"`
	Federate    *tokenFederate `json:"federate"`
	Valid       string         `json:"valid"`
	Scopes      []string       `json:"scopes"`
	Types       []string       `json:"types"`
	Domains     []string       `json:"domains"`
	IPs         []string       `json:"ips"`
	Clients     []string       `json:"clients"`
	Localhost   bool           `json:"localhost"`
	OTC         bool           `json:"otc"`
	OTCValid    string         `json:"otc_valid"`
	OTCNetworks []string       `json:"otc_networks"`
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

// authenticate takes the bearer token of r, as identify does, the client held back by the guard
// while its tokens are refused; for a token refused it answers with the error and returns false.
func (s *webuiServer) authenticate(w http.ResponseWriter, r *http.Request) bool {
	scope := s.scope
	given, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	client := clientAddr(r)
	given = strings.TrimSpace(given)
	err := guard.attempt(w, r, s.rootDir, func() error {
		if given == "" {
			return apiErr(http.StatusUnauthorized, "a token with the scope %s is required", scope)
		}
		return s.identify(given, scope, client)
	})
	if err == nil {
		return true
	}
	var e *apiError
	if !errors.As(err, &e) {
		slog.Error("serve.error", "error", err.Error())
		e = apiErr(http.StatusInternalServerError, "could not read the tokens")
	}
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="simple-ca webui"`)
	}
	webuiFail(w, e.status, e.msg)
	return false
}

// identify keeps the name, the CA and the scopes of the token given, a token of the root CA or of
// one of its issuing CAs with the scope, used from client, a client it allows.
func (s *webuiServer) identify(given, scope string, client netip.Addr) error {
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
			return err
		}
		name, tok, err := lookupToken(db, claims)
		switch {
		case err != nil:
			return err
		case !tok.hasScope(scope):
			return apiErr(http.StatusForbidden, "the token does not have the scope %s", scope)
		case !tok.clientAllowed(client):
			return apiErr(http.StatusForbidden, "the token is not allowed from %s", client)
		}
		s.user, s.userCA, s.userScopes, s.userToken, s.client = name, id, tok.scopes(), tok, client
		return nil
	}
	return apiErr(http.StatusUnauthorized, "invalid token")
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
		page := map[string]string{"tokens": "tokens.html", "certs": "certs.html", "audit": "audit.html"}[s.scope]
		if err := pageTemplates.ExecuteTemplate(w, page, struct{ Script string }{tailwindPath}); err != nil {
			slog.Error("serve.error", "error", err.Error())
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
	case ui.scope == "certs":
		ui.certAPI(w, r)
	case ui.scope == "audit":
		ui.auditAPI(w, r)
	default:
		ui.tokenAPI(w, r)
	}
}

// webuiDecode reads the JSON body of a request into v, refusing a field that is not one of
// fields, those the request uses, and answers with the error when it does not read.
func webuiDecode(w http.ResponseWriter, r *http.Request, v any, fields ...string) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, acmeMaxBody))
	var given map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(b, &given)
	}
	if err == nil {
		err = json.Unmarshal(b, v)
	}
	if err != nil || given == nil {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object of the request")
		return false
	}
	for _, field := range slices.Sorted(maps.Keys(given)) {
		if !slices.Contains(fields, field) {
			webuiFail(w, http.StatusBadRequest, "'"+field+"' is not a field of this request")
			return false
		}
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

	// The fields each request uses; the API takes no defaults, so those it needs are required.
	fields := map[string][]string{
		"/api/tokens": {"ca", "name", "valid", "scopes", "types", "domains", "ips", "clients", "localhost", "federate",
			"otc", "otc_valid", "otc_networks"},
		"/api/tokens/renew":  {"ca", "name", "valid", "otc", "otc_valid", "otc_networks"},
		"/api/tokens/revoke": {"ca", "name"},
		"/api/tokens/purge":  {"ca", "name"},
	}[r.URL.Path]
	var req webuiRequest
	if !webuiDecode(w, r, &req, fields...) {
		return
	}
	dir, ok := s.caDir(req.CA)
	if !ok {
		webuiFail(w, http.StatusNotFound, "no such CA")
		return
	}
	db, err := loadTokens(dir)
	if err != nil {
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not read the tokens")
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
		if setupValid, err = parseDuration(req.OTCValid); err != nil {
			webuiFail(w, http.StatusBadRequest, "otc_valid: "+err.Error())
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
	// A validity is given for a token created or renewed, as token create and token renew take it.
	var valid time.Duration
	if r.URL.Path == "/api/tokens" || r.URL.Path == "/api/tokens/renew" {
		if valid, err = parseDuration(req.Valid); err != nil {
			webuiFail(w, http.StatusBadRequest, "valid: "+err.Error())
			return
		}
	}
	switch r.URL.Path {
	case "/api/tokens":
		scopes, domains, ips, types := req.Scopes, req.Domains, req.IPs, req.Types
		switch {
		case len(scopes) == 0:
			webuiFail(w, http.StatusBadRequest, "scopes: a token needs at least one scope")
			return
		case allows(scopes, "sign") && len(types) == 0:
			webuiFail(w, http.StatusBadRequest, "types: a token with the scope sign needs at least one certificate type")
			return
		case !s.grants(scopes):
			webuiFail(w, http.StatusForbidden, "your token can only grant the scopes sign, "+
				strings.Join(s.userScopes, ", "))
			return
		}
		if req.Localhost {
			domains, ips = append(domains, "localhost"), append(ips, "127.0.0.1")
		}
		if req.Federate != nil {
			req.Federate.Audience = strings.TrimSpace(req.Federate.Audience)
		}
		token, err := addToken(dir, req.Name, req.Federate, valid, scopes, types, domains, ips, req.Clients, setupValid,
			req.OTCNetworks)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		record := append([]any{"name", req.Name, "scopes", strings.Join(scopes, ","), "setup_code", req.OTC},
			federateAudit(req.Federate)...)
		audit(dir, "token.create", append(record, s.auditActor()...)...)
		answer(http.StatusCreated, req.Name, token)
	case "/api/tokens/renew":
		token, err := reissueToken(dir, req.Name, valid, setupValid, req.OTCNetworks)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		audit(dir, "token.renew", append([]any{"name", req.Name, "setup_code", req.OTC}, s.auditActor()...)...)
		answer(http.StatusOK, req.Name, token)
	case "/api/tokens/revoke":
		if err := revokeToken(dir, req.Name); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		audit(dir, "token.revoke", append([]any{"name", req.Name}, s.auditActor()...)...)
		webuiReply(w, http.StatusOK, map[string]string{"name": req.Name})
	case "/api/tokens/purge":
		if req.Name != "" {
			if err := purgeToken(dir, req.Name); err != nil {
				webuiFail(w, http.StatusBadRequest, err.Error())
				return
			}
			audit(dir, "token.purge", append([]any{"name", req.Name}, s.auditActor()...)...)
			webuiReply(w, http.StatusOK, map[string]int{"removed": 1})
			return
		}
		// Every expired or revoked token is removed that the token of the request may grant.
		now, n := time.Now(), 0
		for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
			if t := db.Tokens[name]; !now.Before(t.Expires) && s.grants(t.scopes()) {
				if err := purgeToken(dir, name); err != nil {
					slog.Error("serve.error", "error", err.Error())
					webuiFail(w, http.StatusInternalServerError, "could not remove the tokens")
					return
				}
				n++
			}
		}
		if n > 0 {
			audit(dir, "token.purge", append([]any{"count", n}, s.auditActor()...)...)
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
		slog.Error("serve.error", "error", err.Error())
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
			slog.Error("serve.error", "error", err.Error())
			continue
		}
		theme, err := loadTheme(dir)
		if err != nil {
			slog.Error("serve.error", "dir", dir, "error", err.Error())
		}
		cas = append(cas, webuiCA{ID: id, Subject: subjectAttributes(nameString(cert.Subject)),
			HasKey: fileExists(filepath.Join(dir, "ca_key.pem")), Theme: theme})
	}

	answer := map[string]any{"title": rootCert.Subject.CommonName, "types": slices.Sorted(maps.Keys(types)), "cas": cas,
		"user": s.user, "user_ca": s.userCA, "user_token": newWebuiToken(s.user, s.userToken, time.Now())}
	switch s.scope {
	case "certs":
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
	case "tokens":
		defaults := webuiDefaults{Valid: cmp.Or(cfg.Tokens.Valid, "1h"), Types: cfg.Tokens.Types,
			Domains: cfg.Tokens.Domains, IPs: cfg.Tokens.IPs,
			Clients: append(slices.Clone(cfg.Tokens.Hosts), cfg.Tokens.Networks...), OTCValid: durationText(tokenSetupValid)}
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
		// The token types of the scope federate, each with its audience, whether a token needs one
		// given, and the validity of its JWTs.
		tokenTypes, err := cfg.tokenTypes()
		if err != nil {
			slog.Error("serve.error", "error", err.Error())
			webuiFail(w, http.StatusInternalServerError, "could not read the token types")
			return
		}
		typeList := []map[string]any{}
		for _, name := range slices.Sorted(maps.Keys(tokenTypes)) {
			t, maxValid := tokenTypes[name], ""
			if t.maxValid > 0 {
				maxValid = durationText(t.maxValid)
			}
			typeList = append(typeList, map[string]any{"name": name, "base": t.base, "audience": t.audience,
				"needs_audience": t.needsAudience && t.audience == "", "valid": durationText(t.valid), "max_valid": maxValid})
		}
		answer["scopes"], answer["defaults"], answer["token_types"] = grantable, defaults, typeList
	}
	webuiReply(w, http.StatusOK, answer)
}

// listTokens answers with the tokens of the CA in dir, sorted by name.
func (s *webuiServer) listTokens(w http.ResponseWriter, dir string) {
	db, err := loadTokens(dir)
	if err != nil {
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not read the tokens")
		return
	}
	now := time.Now()
	tokens := []webuiToken{}
	for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
		tokens = append(tokens, newWebuiToken(name, db.Tokens[name], now))
	}
	webuiReply(w, http.StatusOK, map[string][]webuiToken{"tokens": tokens})
}
