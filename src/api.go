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
	"bytes"
	"cmp"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// ---- signing API tokens -----------------------------------------------------

const (
	tokensPurgeInterval = 5 * time.Minute
)

// tokenSetupValid is the default validity of a setup code.
const tokenSetupValid = 15 * time.Minute

// purgeTokens removes from tokens-db.json of caDir, when it exists, the tokens that expired, or
// were revoked, at least kept ago, every expired token for a kept of zero, and returns their count.
func purgeTokens(caDir string, kept time.Duration) (int, error) {
	if !simpleca.FileExists(filepath.Join(caDir, tokens.TokensFile)) {
		return 0, nil
	}
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := len(db.Tokens)
	maps.DeleteFunc(db.Tokens, func(_ string, t *tokens.APIToken) bool { return !now.Add(-kept).Before(t.Expires) })
	if n == len(db.Tokens) {
		return 0, nil
	}
	return n - len(db.Tokens), db.Save(caDir)
}

// purgeToken removes the token name, expired or revoked, from tokens-db.json of caDir; a token
// still accepted is revoked first.
func purgeToken(caDir, name string) error {
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return err
	}
	t, ok := db.Tokens[name]
	if !ok {
		return fmt.Errorf("token %q not found in %q", name, filepath.Join(caDir, tokens.TokensFile))
	}
	if time.Now().Before(t.Expires) {
		return fmt.Errorf("token %q is still accepted; revoke it first", name)
	}
	delete(db.Tokens, name)
	return db.Save(caDir)
}

// renewToken renews the token name of the CA in caDir and returns its JWT, as reissueToken does
// without a setup code.
func renewToken(caDir, name string, valid time.Duration) (string, error) {
	return reissueToken(caDir, name, valid, 0, nil)
}

// reissueToken gives the token name of the CA in caDir, revoked, expired or not, a new JWT ID and
// new times, valid for valid from now or, for zero, for as long as it was before, or for the
// default validity of token create when it was revoked, keeping what it allows and where it is
// used from, and returns its JWT. The JWT it had is refused from then on. With a setupValid, the
// token becomes pending instead, as tokens.AddToken makes it, and reissueToken returns its new
// setup code. A token waiting for a setup code that has not expired is refused.
func reissueToken(caDir, name string, valid, setupValid time.Duration, setupClients []string) (string, error) {
	if valid != 0 && valid < time.Second {
		return "", errors.New("the validity of a token must be at least 1s")
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !simpleca.FileExists(filepath.Join(caDir, "ca_cert.pem")) || !simpleca.FileExists(caKeyPath) {
		return "", fmt.Errorf("CA certificate and key not found in %q, which is not a CA directory", caDir)
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return "", err
	}
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return "", err
	}
	old, ok := db.Tokens[name]
	if !ok {
		return "", fmt.Errorf("token %q not found in %q", name, filepath.Join(caDir, tokens.TokensFile))
	}
	if old.Pending() && time.Now().Before(old.Expires) {
		return "", fmt.Errorf("token %q waits for its setup code; revoke it first to renew it", name)
	}
	switch {
	case valid != 0:
	case old.Pending():
		// The expiry of a pending token is that of its code; the validity of the token is kept apart.
		if valid, err = old.Setup.Validity(); err != nil {
			return "", fmt.Errorf("token %q: %w", name, err)
		}
	case !old.Revoked():
		valid = old.Expires.Sub(old.Issued)
	default:
		// A revoked token, whose expiry is when it was revoked, takes the validity token create
		// gives by default.
		cfg, err := simpleca.LoadRootConfig(caDir)
		if err != nil {
			return "", err
		}
		valid = time.Hour
		if cfg.Tokens.Valid != "" {
			if valid, err = simpleca.ParseDuration(cfg.Tokens.Valid); err != nil {
				return "", fmt.Errorf("tokens.valid of %q: %w", cfg.Path, err)
			}
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	tok := &tokens.APIToken{ID: simpleca.RandomID(), Scopes: old.Scopes, Types: old.Types, Domains: old.Domains, IPs: old.IPs,
		Clients: old.Clients, Issued: now, Expires: now.Add(valid), OIDC: old.OIDC, Federate: old.Federate}
	setup, result, err := tokens.NewTokenSetup(valid, setupValid, setupClients)
	if err != nil {
		return "", err
	}
	if setup != nil {
		tok.ID, tok.Expires, tok.Setup = "", now.Add(setupValid), setup
	} else if result, err = tokens.SignToken(caKey, name, tok); err != nil {
		return "", err
	}
	db.Tokens[name] = tok
	if err := db.Save(caDir); err != nil {
		return "", err
	}
	return result, nil
}

// listTokens writes the tokens of the CA in caDir to w, one per line, sorted by name.
func listTokens(w io.Writer, caDir string) error {
	if !simpleca.FileExists(filepath.Join(caDir, "ca_cert.pem")) {
		return fmt.Errorf("CA certificate not found in %q, which is not a CA directory", caDir)
	}
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return err
	}
	now := time.Now()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tEXPIRES\tSCOPES\tCERT TYPES\tDOMAINS\tIPS\tCLIENTS\tFEDERATES\tCERTS\tOIDC USER")
	for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
		t := db.Tokens[name]
		expires := t.Expires.UTC().Format(cert.DisplayTimeFormat)
		switch {
		case t.Revoked():
			expires = "revoked"
		case t.Pending() && !now.Before(t.Expires):
			expires = "setup expired"
		case t.Pending():
			expires = "setup until " + expires
		case !now.Before(t.Expires):
			expires += " (expired)"
		}
		user := "-"
		if t.OIDC != nil {
			user = t.OIDC.User
		}
		federates, certs := "-", "-"
		if t.Federate != nil {
			federates = t.Federate.Type
		}
		if t.HasScope("sign") {
			certs = fmt.Sprint(len(t.Certs))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", simpleca.Printable(name), expires,
			simpleca.Printable(strings.Join(t.EffectiveScopes(), ",")),
			simpleca.Printable(cmp.Or(strings.Join(t.Types, ","), "-")), simpleca.Printable(cmp.Or(strings.Join(t.Domains, ","), "-")),
			cmp.Or(strings.Join(showPrefixes(t.IPs), ","), "-"), cmp.Or(strings.Join(showPrefixes(t.Clients), ","), "any"),
			simpleca.Printable(federates), certs, simpleca.Printable(user))
	}
	return tw.Flush()
}

// describeToken returns the attributes of the token name, each a label and a value, as
// token describe and the setup code page show them; with limits, also what it allows and where it
// is used from, which only tokens-db.json holds, and not its JWT.
func describeToken(name string, t *tokens.APIToken, limits bool) [][2]string {
	now := time.Now()
	at := func(when time.Time) string { return when.UTC().Format(cert.DisplayTimeFormat) }
	list := func(values []string, none string) string { return cmp.Or(strings.Join(values, ", "), none) }
	status := "valid until " + at(t.Expires)
	switch {
	case t.Revoked():
		status = "revoked at " + at(t.Expires)
	case t.Pending() && !now.Before(t.Expires):
		status = "setup code expired at " + at(t.Expires)
	case t.Pending():
		status = "waits for its setup code, until " + at(t.Expires)
	case !now.Before(t.Expires):
		status = "expired at " + at(t.Expires)
	}
	attributes := [][2]string{{"Name", name}, {"Status", status}, {"Issued", at(t.Issued)},
		{"Scopes", list(t.EffectiveScopes(), "-")}}
	if t.OIDC != nil {
		attributes = append(attributes, [2]string{"OIDC user", t.OIDC.User}, [2]string{"OIDC issuer", t.OIDC.Issuer})
	}
	if !limits {
		return attributes
	}
	if t.HasScope("sign") {
		attributes = append(attributes, [2]string{"Cert types", list(t.Types, "-")},
			[2]string{"Domains", list(t.Domains, "-")}, [2]string{"IP addresses", list(showPrefixes(t.IPs), "-")})
	}
	if f := t.Federate; f != nil {
		attributes = append(attributes, [2]string{"Federates", f.Type},
			[2]string{"Audience", cmp.Or(f.Audience, "that of the token type")})
		for _, claim := range slices.Sorted(maps.Keys(f.Claims)) {
			attributes = append(attributes, [2]string{"Claim " + claim, f.Claims[claim]})
		}
	}
	attributes = append(attributes, [2]string{"Used from", list(showPrefixes(t.Clients), "any client")})
	if t.Pending() {
		valid := t.Setup.Valid
		if d, err := t.Setup.Validity(); err == nil {
			valid = simpleca.DurationText(d)
		}
		attributes = append(attributes, [2]string{"Code usable from", list(showPrefixes(t.Setup.Clients), "any client")},
			[2]string{"Valid after the exchange", valid})
	}
	// Only a token with the scope sign issues certificates.
	if t.HasScope("sign") {
		certs := fmt.Sprint(len(t.Certs))
		if len(t.Certs) > 0 {
			certs += ": " + strings.Join(t.Certs, ", ")
		}
		attributes = append(attributes, [2]string{"Certificates", certs})
	}
	return attributes
}

// revokeToken revokes the token name of the CA in caDir by taking its JWT ID, or its setup code,
// from tokens-db.json and making it expire now; its JWT, or its code, is refused from then on, and
// the token is kept, to be renewed, until it is purged.
func revokeToken(caDir, name string) error {
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return err
	}
	t, ok := db.Tokens[name]
	if !ok {
		return fmt.Errorf("token %q not found in %q", name, filepath.Join(caDir, tokens.TokensFile))
	}
	if t.Revoked() {
		return fmt.Errorf("token %q is revoked already", name)
	}
	t.ID, t.Setup, t.Expires = "", nil, time.Now().UTC().Truncate(time.Second)
	return db.Save(caDir)
}

// exchangeSetupCode exchanges the setup code of a pending token of the root CA in rootDir or of
// one of its issuing CAs, used from the address client, for its JWT, and returns the ID of its
// CA, its name and the JWT. The token is valid from now, and the code works once. The error has
// the status 401 for an unknown, used or expired code, and 403 for a client the code is not
// exchanged from.
func exchangeSetupCode(rootDir, code string, client netip.Addr) (caID, name, jwt string, err error) {
	hash := tokens.SetupCodeHash(code)
	for _, id := range simpleca.CAIDs(rootDir) {
		dir := filepath.Join(rootDir, id)
		if id, name, jwt, err := func() (string, string, string, error) {
			unlock, err := tokens.LockTokens(dir)
			if err != nil {
				return "", "", "", err
			}
			defer unlock()
			db, err := tokens.LoadTokens(dir)
			if err != nil {
				return "", "", "", err
			}
			for name, t := range db.Tokens {
				if !t.Pending() || t.Setup.Code != hash {
					continue
				}
				now := time.Now().UTC().Truncate(time.Second)
				if !now.Before(t.Expires) {
					return "", "", "", apiErr(http.StatusUnauthorized, "the setup code has expired")
				}
				if !(&tokens.APIToken{Clients: t.Setup.Clients}).ClientAllowed(client) {
					return "", "", "", apiErr(http.StatusForbidden, "the setup code is not usable from %s", client)
				}
				valid, err := t.Setup.Validity()
				if err != nil {
					return "", "", "", fmt.Errorf("token %q: %w", name, err)
				}
				caKey, err := simpleca.LoadKey(filepath.Join(dir, "ca_key.pem"))
				if err != nil {
					return "", "", "", err
				}
				t.ID, t.Setup, t.Issued, t.Expires = simpleca.RandomID(), nil, now, now.Add(valid)
				jwt, err := tokens.SignToken(caKey, name, t)
				if err != nil {
					return "", "", "", err
				}
				return id, name, jwt, db.Save(dir)
			}
			return "", "", "", nil
		}(); err != nil || name != "" {
			return id, name, jwt, err
		}
	}
	return "", "", "", apiErr(http.StatusUnauthorized, "unknown or used setup code")
}

// The largest request bodies of the signing API and its pages, in bytes: the setup code
// exchange, the forms of the pages, POST /api/sign with its CSR, and /api/federation-token.
const (
	setupCodeMaxBody  = 1 << 10
	formMaxBody       = 64 << 10
	signMaxBody       = 64 << 10
	federationMaxBody = 1 << 10
)

// apiTokenSetup answers POST /api/token-setup, a JSON body {"code": "..."} of at most
// setupCodeMaxBody bytes from a client behind the trusted proxies, with the CA ID, the name, the
// JWT and the scopes of the token the setup code is exchanged for.
func apiTokenSetup(w http.ResponseWriter, r *http.Request, rootDir string) {
	var req struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, setupCodeMaxBody))
	dec.DisallowUnknownFields()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		webuiFail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	err := dec.Decode(&req)
	if bodyTooLarge(err) {
		webuiFail(w, http.StatusRequestEntityTooLarge, tooLargeText(setupCodeMaxBody))
		return
	}
	if err != nil || strings.TrimSpace(req.Code) == "" {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object with the setup code")
		return
	}
	client := clientAddr(r)
	var id, name, jwt string
	err = guard.attempt(w, r, rootDir, func() (err error) {
		id, name, jwt, err = exchangeSetupCode(rootDir, req.Code, client)
		return err
	})
	var refused *apiError
	switch {
	case errors.As(err, &refused):
		webuiFail(w, refused.status, refused.msg)
		return
	case err != nil:
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not set up the token")
		return
	}
	simpleca.Audit(filepath.Join(rootDir, id), "token.setup", "name", name, "via", "setup", "actor", name, "client", client.String())
	scopes := []string{}
	if db, err := tokens.LoadTokens(filepath.Join(rootDir, id)); err == nil && db.Tokens[name] != nil {
		scopes = db.Tokens[name].EffectiveScopes()
	}
	webuiReply(w, http.StatusOK, map[string]any{"ca": id, "name": name, "token": jwt, "scopes": scopes})
}

// tokenDescribePage serves /token-describe for the root CA in rootDir and its issuing CAs: GET
// shows the form asking for a token, and POST shows the attributes of the token, as token
// describe --ca-dir shows them with the CA that signed it, or the form again with the error. A
// token refused is counted as on the other pages.
func tokenDescribePage(w http.ResponseWriter, r *http.Request, rootDir string) {
	caCert, err := simpleca.LoadCert(filepath.Join(rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, Error, CA string
		Theme                            template.CSS
		Attributes                       [][2]string
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: r.URL.Path, Theme: pageTheme(rootDir)}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, formMaxBody)
		if err := r.ParseForm(); bodyTooLarge(err) {
			http.Error(w, tooLargeText(formMaxBody), http.StatusRequestEntityTooLarge)
			return
		} else if err != nil {
			http.Error(w, "the form is malformed", http.StatusBadRequest)
			return
		}
		token := strings.TrimSpace(r.PostForm.Get("token"))
		// The token is checked against each CA of the server, as token describe --ca-dir checks it
		// against one, and its entry read from the tokens-db.json of the CA that signed it.
		err = guard.attempt(w, r, rootDir, func() error {
			if token == "" {
				return apiErr(http.StatusUnauthorized, "a token is required")
			}
			for _, id := range simpleca.CAIDs(rootDir) {
				dir := filepath.Join(rootDir, id)
				crt, err := simpleca.LoadCert(filepath.Join(dir, "ca_cert.pem"))
				if err != nil {
					continue
				}
				c, err := verifyJWT(crt, token)
				if err != nil {
					continue
				}
				db, err := tokens.LoadTokens(dir)
				if err != nil {
					return err
				}
				page.CA = "root CA"
				if id != "" {
					page.CA = "issuing CA " + id
				}
				entry := db.Tokens[c.Subject]
				if entry == nil || entry.ID == "" || entry.ID != c.ID {
					page.Attributes = describeToken(c.Subject, c.Token(), false)
					page.Attributes[1][1] = "refused: the token was renewed, revoked or removed"
					return errUncounted
				}
				page.Attributes = describeToken(c.Subject, entry, true)
				if !entry.Active(time.Now()) {
					return errUncounted
				}
				return nil
			}
			return apiErr(http.StatusUnauthorized, "the token is not one of a CA of this server")
		})
		var e *apiError
		switch {
		case errors.As(err, &e):
			status, page.Error = e.status, e.msg
		case err != nil:
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			status, page.Error = http.StatusInternalServerError, "could not read the tokens"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "token-describe.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// tokenSetupPage serves /token-setup for the root CA in rootDir and its issuing CAs: GET shows the
// form asking for a setup code, and POST exchanges the code, as exchangeSetupCode, and shows the
// token once, with its attributes, or the form again with the error. The client is the one
// clientAddr finds with the trusted proxies.
func tokenSetupPage(w http.ResponseWriter, r *http.Request, rootDir string) {
	caCert, err := simpleca.LoadCert(filepath.Join(rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, Error, CA, Name, Token string
		Theme                                         template.CSS
		Attributes                                    [][2]string
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: r.URL.Path, Theme: pageTheme(rootDir)}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, formMaxBody)
		if err := r.ParseForm(); bodyTooLarge(err) {
			http.Error(w, tooLargeText(formMaxBody), http.StatusRequestEntityTooLarge)
			return
		} else if err != nil {
			http.Error(w, "the form is malformed", http.StatusBadRequest)
			return
		}
		client := clientAddr(r)
		code := strings.TrimSpace(r.PostForm.Get("code"))
		err = guard.attempt(w, r, rootDir, func() (err error) {
			if code == "" {
				return apiErr(http.StatusUnauthorized, "a setup code is required")
			}
			page.CA, page.Name, page.Token, err = exchangeSetupCode(rootDir, code, client)
			return err
		})
		var e *apiError
		switch {
		case errors.As(err, &e):
			status, page.Error = e.status, e.msg
		case err != nil:
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			status, page.Error = http.StatusInternalServerError, "could not set up the token"
		default:
			simpleca.Audit(filepath.Join(rootDir, page.CA), "token.setup", "name", page.Name, "via", "setup", "actor", page.Name,
				"client", client.String())
			if db, err := tokens.LoadTokens(filepath.Join(rootDir, page.CA)); err == nil && db.Tokens[page.Name] != nil {
				page.Attributes = describeToken(page.Name, db.Tokens[page.Name], true)
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "token-setup.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// ---- /api/sign --------------------------------------------------------------

// apiError is an error of the signing API, sent with its HTTP status.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func apiErr(status int, format string, args ...any) *apiError {
	return &apiError{status, fmt.Sprintf(format, args...)}
}

// checkToken returns the name and the entry in db of the JWT token, signed with the key of
// caCert, and an error of status 401 when the token is malformed, signed by another key,
// unknown, which a revoked token is, or expired.
func checkToken(db *tokens.TokensDB, caCert *x509.Certificate, token string) (string, *tokens.APIToken, error) {
	c, err := verifyJWT(caCert, token)
	if err != nil {
		return "", nil, err
	}
	return lookupToken(db, c)
}

// otherCAToken returns err, the refusal of token by the CA in caDir, or, for a token another CA of
// the same root CA signed, the error of status 401 naming both CAs, as token describe names the CA.
func otherCAToken(caDir, token string, err error) error {
	rootDir, id, rerr := simpleca.LocateCA(caDir)
	if rerr != nil {
		return err
	}
	role := func(id string) string {
		if id == "" {
			return "the root CA"
		}
		return "the issuing CA " + id
	}
	for _, other := range simpleca.CAIDs(rootDir) {
		if other == id {
			continue
		}
		caCert, cerr := simpleca.LoadCert(filepath.Join(rootDir, other, "ca_cert.pem"))
		if cerr != nil {
			continue
		}
		if _, verr := verifyJWT(caCert, token); verr == nil {
			return apiErr(http.StatusUnauthorized, "the token is one of %s, not of %s", role(other), role(id))
		}
	}
	return err
}

// verifyJWT returns the claims of the JWT token signed with the key of caCert, and an error of
// status 401 when the token is malformed, signed by another key, or a JWT of a token type, which
// has an issuer; with no caCert, the signature is not checked.
func verifyJWT(caCert *x509.Certificate, token string) (*tokens.JWTClaims, error) {
	invalid := apiErr(http.StatusUnauthorized, "invalid token")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid
	}
	header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, invalid
	}
	// The algorithm is that of the CA key, RS256 or ES256 when the CA is not known.
	var h struct{ Alg string }
	switch {
	case json.Unmarshal(header, &h) != nil:
		return nil, invalid
	case caCert == nil && h.Alg != "RS256" && h.Alg != "ES256":
		return nil, invalid
	case caCert != nil && (h.Alg != jose.JWTAlg(caCert.PublicKey) ||
		jose.VerifyJWS(h.Alg, caCert.PublicKey, []byte(parts[0]+"."+parts[1]), sig) != nil):
		return nil, invalid
	}
	var c tokens.JWTClaims
	if json.Unmarshal(payload, &c) != nil || c.Issuer != "" || len(c.Audience) > 0 {
		return nil, invalid
	}
	return &c, nil
}

// lookupToken returns the name and the entry in db of the token with the verified claims c, and
// an error of status 401 when it is unknown, which a revoked token is, or expired.
func lookupToken(db *tokens.TokensDB, c *tokens.JWTClaims) (string, *tokens.APIToken, error) {
	now := time.Now()
	t, ok := db.Tokens[c.Subject]
	switch {
	case ok && t.Revoked():
		return "", nil, apiErr(http.StatusUnauthorized, "the token has been revoked")
	case !ok || t.Pending() || t.ID != c.ID || c.Scope != strings.Join(t.Scopes, " "):
		return "", nil, apiErr(http.StatusUnauthorized, "unknown token")
	case now.Unix() >= c.ExpiresAt || !now.Before(t.Expires):
		return "", nil, apiErr(http.StatusUnauthorized, "the token has expired")
	}
	return c.Subject, t, nil
}

// checkCSRNames checks the names of csr against the name rules names, "server" or "user", and the
// domains and IP prefixes of the token tok: the subject holds only a CN and email addresses, and
// the SANs only DNS names, email addresses and IP addresses; with the server rules, the CN, a
// hostname or an IP address, the DNS names and the IP addresses are allowed by the token and there
// are no email addresses; with the user rules, the domains of the email addresses are allowed and
// there are neither DNS names nor IP addresses.
func checkCSRNames(csr *x509.CertificateRequest, names string, tok *tokens.APIToken) error {
	domainAllowed := func(name string) bool {
		return slices.Contains(tok.Domains, "*") || cert.InDomains(strings.ToLower(name), tok.Domains)
	}
	ipAllowed := func(addr netip.Addr) bool {
		return slices.ContainsFunc(tok.IPs, func(s string) bool {
			prefix, err := netip.ParsePrefix(s)
			return s == "*" || (err == nil && prefix.Contains(addr.Unmap()))
		})
	}
	var emails []string
	cns := 0
	for _, attr := range csr.Subject.Names {
		switch {
		case attr.Type.Equal(cert.OIDEmailAddress):
			s, _ := attr.Value.(string)
			emails = append(emails, s)
		case attr.Type.String() != "2.5.4.3":
			return apiErr(http.StatusForbidden, "the subject may hold only CN and emailAddress")
		default:
			if _, ok := attr.Value.(string); !ok {
				return apiErr(http.StatusForbidden, "the CN of the subject is not a string")
			}
			cns++
		}
	}
	if cns > 1 {
		return apiErr(http.StatusForbidden, "the subject may hold only one CN")
	}
	if san := cert.CSRSAN(csr); san != nil {
		var gns []asn1.RawValue
		if rest, err := asn1.Unmarshal(san.Value, &gns); err != nil || len(rest) > 0 {
			return apiErr(http.StatusBadRequest, "the subject alternative names do not parse")
		}
		for _, n := range gns {
			if n.Class != asn1.ClassContextSpecific || (n.Tag != 1 && n.Tag != 2 && n.Tag != 7) {
				return apiErr(http.StatusForbidden,
					"the subject alternative names may be only DNS names, email addresses and IP addresses")
			}
		}
	}
	emails = append(emails, csr.EmailAddresses...)

	if names == "user" {
		if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 {
			return apiErr(http.StatusForbidden, "a %s certificate has neither DNS names nor IP addresses", names)
		}
		if len(emails) == 0 {
			return apiErr(http.StatusForbidden, "the request has no email address")
		}
		for _, e := range emails {
			_, domain, _ := strings.Cut(e, "@")
			if !cert.EmailRE.MatchString(e) || !domainAllowed(domain) {
				return apiErr(http.StatusForbidden, "the token does not allow %q", e)
			}
		}
		return nil
	}
	if len(emails) > 0 {
		return apiErr(http.StatusForbidden, "a %s certificate has no email addresses", names)
	}

	// The CN is a hostname, checked with the DNS names, or an IP address, checked with the IP SANs.
	hosts := csr.DNSNames
	var addrs []netip.Addr
	if cn := csr.Subject.CommonName; cn != "" {
		if addr, ok := simpleca.ParseIP(cn); ok {
			addrs = append(addrs, addr)
		} else {
			hosts = append([]string{cn}, hosts...)
		}
	}
	for _, ip := range csr.IPAddresses {
		addr, _ := netip.AddrFromSlice(ip)
		addrs = append(addrs, addr)
	}
	if len(hosts) == 0 && len(addrs) == 0 {
		return apiErr(http.StatusForbidden, "the request has neither a DNS name nor an IP address")
	}
	for _, h := range hosts {
		if !simpleca.IsHostname(strings.TrimPrefix(h, "*.")) || !domainAllowed(h) {
			return apiErr(http.StatusForbidden, "the token does not allow %q", h)
		}
	}
	for _, addr := range addrs {
		if !ipAllowed(addr) {
			return apiErr(http.StatusForbidden, "the token does not allow the IP address %s", addr.Unmap())
		}
	}
	return nil
}

// trustedProxies are the proxies whose X-Forwarded-For header names the client, set once by serve.
var trustedProxies []netip.Prefix

// clientAddr returns the address of the client of r: the address the request comes from, or, when
// that is one of trustedProxies, the last address of its X-Forwarded-For headers that is not a
// trusted proxy, the first one when all of them are.
func clientAddr(r *http.Request) netip.Addr {
	isTrusted := func(addr netip.Addr) bool {
		return slices.ContainsFunc(trustedProxies, func(p netip.Prefix) bool { return p.Contains(addr) })
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	client := peer.Addr().Unmap()
	if !isTrusted(client) {
		return client
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	// The addresses are read from the last, which the trusted proxy added; an address that does
	// not read stops the walk at the last one that does.
	for i := len(hops) - 1; i >= 0; i-- {
		addr, ok := simpleca.ParseIP(strings.TrimSpace(hops[i]))
		if !ok {
			break
		}
		client = addr.Unmap()
		if !isTrusted(client) {
			break
		}
	}
	return client
}

// requestOrigin returns the origin of r as its client sees it, with the host of r: https for a
// request over TLS, or for one from a trusted proxy whose X-Forwarded-Proto ends with https, else
// http.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	if slices.ContainsFunc(trustedProxies, func(p netip.Prefix) bool { return p.Contains(peer.Addr().Unmap()) }) {
		// The value of the last proxy, the one that sent the request, is the last one.
		values := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
		if proto := strings.ToLower(strings.TrimSpace(values[len(values)-1])); proto == "http" || proto == "https" {
			scheme = proto
		}
	}
	return scheme + "://" + r.Host
}

// signWithToken signs the CSR csrData, PEM or DER, with the CA in caDir as a certificate of the
// type certType, valid for days, with the extended key usages ekus and the key usages kus added to
// those of the type, for the JWT token of the CA's tokens-db.json used from the address client,
// which must be in the client prefixes of a token that has them. It writes the certificate to the
// CA directory as the file cert.CertFile gives base, replacing an earlier certificate of the name,
// records it in index.txt and in the token's entry, and returns it with the CA certificate and the
// name of its file. The signing form leaves certType, days and base out: the type is then the
// first type of the token, the days those of days.cert, and the file is named after the CN by the
// rules of cert create, or after the serial number for a request without a name. cert.IssueMu and
// the lock of tokens-db.json are held from the token check to the writes of the certificate file,
// index.txt and tokens-db.json. With setupCodes, token may be the setup code of a pending token of
// the CA instead, used from a client it is exchanged from: the certificate is signed with the
// limits of that token, which is revoked once it is issued, and a refused request leaves the code
// as it was.
func signWithToken(caDir, token string, client netip.Addr, csrData []byte, certType, base string, days int,
	ekus, kus []string, setupCodes bool) (crt, caCert *x509.Certificate, fileName string, err error) {
	cert.IssueMu.Lock()
	defer cert.IssueMu.Unlock()
	unlock, err := tokens.LockTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	defer unlock()
	caCert, err = simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, nil, "", err
	}
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	token = strings.TrimSpace(token)
	var name string
	var tok *tokens.APIToken
	if setupCodes && !strings.Contains(token, ".") {
		hash := tokens.SetupCodeHash(token)
		for n, t := range db.Tokens {
			if t.Pending() && t.Setup.Code == hash {
				name, tok = n, t
			}
		}
		switch {
		case tok == nil:
			return nil, nil, "", apiErr(http.StatusUnauthorized, "unknown or used setup code")
		case !time.Now().Before(tok.Expires):
			return nil, nil, "", apiErr(http.StatusUnauthorized, "the setup code has expired")
		case !(&tokens.APIToken{Clients: tok.Setup.Clients}).ClientAllowed(client):
			return nil, nil, "", apiErr(http.StatusForbidden, "the setup code is not usable from %s", client)
		}
	} else if name, tok, err = checkToken(db, caCert, token); err != nil {
		return nil, nil, "", otherCAToken(caDir, token, err)
	}
	if !tok.ClientAllowed(client) {
		return nil, nil, "", apiErr(http.StatusForbidden, "the token is not allowed from %s", client)
	}
	if !tok.HasScope("sign") {
		return nil, nil, "", apiErr(http.StatusForbidden, "the token does not have the scope sign")
	}
	// The default type is the first type of the token, server for the type *.
	if certType == "" && len(tok.Types) > 0 {
		if certType = tok.Types[0]; certType == "*" {
			certType = "server"
		}
	}
	if !tokens.Allows(tok.Types, certType) {
		return nil, nil, "", apiErr(http.StatusForbidden,
			"the token does not allow the type %q; choose a type it allows, %s, or the default, its first type",
			certType, quoteList(tok.Types))
	}
	cfg, err := simpleca.LoadRootConfig(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	types, err := cert.Types(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	def, ok := types[certType]
	if !ok {
		return nil, nil, "", apiErr(http.StatusBadRequest, "unknown type %q", certType)
	}
	csr, err := cert.ParseCSR(csrData)
	if err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "csr: %v", err)
	}
	if err := checkCSRNames(csr, def.Names, tok); err != nil {
		return nil, nil, "", err
	}

	// The signing form names the file after the CN, else the first DNS name or email address.
	if base == "" {
		cn, email := csr.Subject.CommonName, ""
		if cn == "" && len(csr.DNSNames) > 0 {
			cn = csr.DNSNames[0]
		}
		for _, attr := range csr.Subject.Names {
			if s, ok := attr.Value.(string); ok && attr.Type.Equal(cert.OIDEmailAddress) && email == "" {
				email = s
			}
		}
		if email == "" && len(csr.EmailAddresses) > 0 {
			email = csr.EmailAddresses[0]
		}
		base = cert.CertFileName(strings.TrimPrefix(cn, "*."), email, def.Names == "user")
	}
	if base != "" {
		if fileName, err = cert.CertFile(base); err != nil {
			return nil, nil, "", apiErr(http.StatusBadRequest, "name: %v", err)
		}
	}
	if days == 0 {
		days = cmp.Or(cfg.Days.Cert, 365)
	}
	tmpl := &x509.Certificate{RawSubject: csr.RawSubject}
	if san := cert.CSRSAN(csr); san != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	ku, eku, oids, err := cert.ParseUsages(append(slices.Clone(def.KeyUsage), kus...),
		append(slices.Clone(def.ExtKeyUsage), ekus...))
	if err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "%v", err)
	}
	// A token adds no usages to those of the type.
	if typeKU, typeEKU, typeOIDs, _ := cert.ParseUsages(def.KeyUsage, def.ExtKeyUsage); ku != typeKU ||
		len(eku) != len(typeEKU) || len(oids) != len(typeOIDs) {
		return nil, nil, "", apiErr(http.StatusForbidden,
			"the token does not allow key usages or extended key usages beyond those of the type %q", certType)
	}
	if err := cert.CheckValidity(caCert, time.Now(), days); err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "days: %v", err)
	}
	crt, err = cert.IssueLeaf(caDir, certType, days, ekus, kus, tmpl, csr.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	serial := cert.SerialHex(crt.SerialNumber)
	fileName = cmp.Or(fileName, serial+"_cert.pem")
	if err := cert.StoreCert(caDir, filepath.Join(caDir, fileName), crt); err != nil {
		return nil, nil, "", err
	}
	tok.Certs = append(tok.Certs, serial)
	byCode := tok.Pending()
	if byCode {
		// The token of a setup code signs this certificate alone.
		tok.Setup, tok.Expires = nil, time.Now().UTC().Truncate(time.Second)
	}
	if err := db.Save(caDir); err != nil {
		return nil, nil, "", err
	}
	via := "api"
	if setupCodes {
		via = "form"
	}
	pairs := []any{"setup_code", byCode, "via", via, "actor", name}
	if tok.OIDC != nil {
		pairs = append(pairs, "oidc_user", tok.OIDC.User)
	}
	cert.AuditIssued(caDir, crt, certType, append(pairs, "client", client.String())...)
	return crt, caCert, fileName, nil
}

// apiSign serves a POST of /api/sign for the CA in caDir: it signs the CSR of the JSON request
// with the type it names for the bearer token of the request, as signWithToken, for the client
// clientAddr finds with the trusted proxies, and returns the certificate with its chain.
func apiSign(w http.ResponseWriter, r *http.Request, caDir string) {
	if !simpleca.FileExists(filepath.Join(caDir, "ca_key.pem")) || !simpleca.FileExists(filepath.Join(caDir, tokens.TokensFile)) {
		http.NotFound(w, r)
		return
	}
	var crt, caCert *x509.Certificate
	var req struct {
		CSR  string   `json:"csr"`
		Type string   `json:"type"`
		Name string   `json:"name"`
		Days int      `json:"days"`
		KU   []string `json:"ku"`
		EKU  []string `json:"eku"`
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, signMaxBody))
	dec.DisallowUnknownFields()
	// The body is read only once the content type and the bearer token are there.
	var decodeErr error
	decode := func() bool { decodeErr = dec.Decode(&req); return decodeErr != nil }
	client := clientAddr(r)
	var err error
	switch {
	case strings.TrimSpace(ct) != "application/json":
		err = apiErr(http.StatusUnsupportedMediaType, "the content type must be application/json")
	case !ok:
		err = guard.attempt(w, r, caDir, func() error { return apiErr(http.StatusUnauthorized, "a bearer token is required") })
	case decode() && bodyTooLarge(decodeErr):
		err = apiErr(http.StatusRequestEntityTooLarge, "%s", tooLargeText(signMaxBody))
	case decodeErr != nil:
		err = apiErr(http.StatusBadRequest, "invalid request: the body is not a JSON object of csr, type, name, "+
			"days, ku and eku")
	// The API takes no defaults: the type, the file name and the days are given, as cert sign takes them.
	case strings.TrimSpace(req.Type) == "":
		err = apiErr(http.StatusBadRequest, "type: the certificate type is required")
	case strings.TrimSpace(req.Name) == "" || strings.ContainsAny(req.Name, `/\`):
		err = apiErr(http.StatusBadRequest, "name: the file name of the certificate is required, without a directory")
	case req.Days < 1:
		err = apiErr(http.StatusBadRequest, "days: the validity in days must be a positive integer")
	default:
		err = guard.attempt(w, r, caDir, func() (err error) {
			crt, caCert, _, err = signWithToken(caDir, token, client, []byte(req.CSR), req.Type, req.Name, req.Days,
				req.EKU, req.KU, false)
			return err
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		var e *apiError
		if !errors.As(err, &e) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		if e.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(map[string]string{"error": e.msg})
		return
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}))
	chain := certPEM
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	}
	json.NewEncoder(w).Encode(map[string]string{"serial": cert.SerialHex(crt.SerialNumber), "certificate": certPEM, "chain": chain})
}

// apiFederationToken serves a POST of /api/federation-token for the CA in caDir: for the bearer
// token of the request, a token with the scope federate used from a client it allows, it returns a
// new JWT of the token type of the token, unstored, valid for the validity of the type and never
// after the token expires. The body is empty or {}: the token alone decides what the JWT holds.
func apiFederationToken(w http.ResponseWriter, r *http.Request, caDir string) {
	if !simpleca.FileExists(filepath.Join(caDir, "ca_key.pem")) || !simpleca.FileExists(filepath.Join(caDir, tokens.TokensFile)) {
		http.NotFound(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	client := clientAddr(r)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, federationMaxBody))
	var fields map[string]json.RawMessage
	var answer map[string]any
	switch {
	case bodyTooLarge(err):
		err = apiErr(http.StatusRequestEntityTooLarge, "%s", tooLargeText(federationMaxBody))
	case err != nil || (len(bytes.TrimSpace(body)) > 0 && (json.Unmarshal(body, &fields) != nil || len(fields) > 0)):
		err = apiErr(http.StatusBadRequest, "invalid request: the body is empty or {}; the token decides the JWT")
	case !ok:
		err = guard.attempt(w, r, caDir, func() error { return apiErr(http.StatusUnauthorized, "a bearer token is required") })
	default:
		err = guard.attempt(w, r, caDir, func() error {
			caCert, err := simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
			if err != nil {
				return err
			}
			db, err := tokens.LoadTokens(caDir)
			if err != nil {
				return err
			}
			name, tok, err := checkToken(db, caCert, strings.TrimSpace(token))
			switch {
			case err != nil:
				return otherCAToken(caDir, token, err)
			case !tok.ClientAllowed(client):
				return apiErr(http.StatusForbidden, "the token is not allowed from %s", client)
			case !tok.HasScope("federate"):
				return apiErr(http.StatusForbidden, "the token does not have the scope federate")
			case tok.Federate == nil:
				return apiErr(http.StatusForbidden, "the token has no token type of its JWTs")
			}
			cfg, err := simpleca.LoadRootConfig(caDir)
			if err != nil {
				return err
			}
			_, caID, err := simpleca.LocateCA(caDir)
			if err != nil {
				return err
			}
			fed, err := tok.Federate.Resolve(cfg, caID, name)
			if err != nil {
				return apiErr(http.StatusBadRequest, "%v", err)
			}
			caKey, err := simpleca.LoadKey(filepath.Join(caDir, "ca_key.pem"))
			if err != nil {
				return err
			}
			jwt, id, expires, err := tokens.IssueJWT(caKey, fed, 0, tok.Expires)
			if err != nil {
				return err
			}
			simpleca.Audit(caDir, "token.issue", "name", name, "token_type", fed.TypeName, "audience", fed.Audience,
				"subject", fed.Subject, "jti", id, "via", "api", "actor", name, "client", client.String())
			answer = map[string]any{"token": jwt, "token_type": fed.TypeName, "audience": fed.Audience,
				"subject": fed.Subject, "expires": expires}
			return nil
		})
	}
	if err != nil {
		var e *apiError
		if !errors.As(err, &e) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		if e.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		webuiFail(w, e.status, e.msg)
		return
	}
	webuiReply(w, http.StatusOK, answer)
}

// ---- /sign ------------------------------------------------------------------

// signPage serves /sign for the CA in caDir, whose page is at path: GET shows the form, and POST
// signs its CSR with its type and token, or setup code, as signWithToken, and sends the
// certificate as a download, or shows the form again with the error. For a CA without its key or
// its tokens-db.json, the page says why it signs no requests, and a POST is 403 Forbidden. The
// client is the one clientAddr finds with the trusted proxies.
func signPage(w http.ResponseWriter, r *http.Request, caDir, path string) {
	caCert, err1 := simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
	cfg, err2 := simpleca.LoadRootConfig(caDir)
	var types map[string]cert.CertTypeDef
	if err := cmp.Or(err1, err2); err == nil {
		types, err1 = cert.Types(cfg)
	}
	if err := cmp.Or(err1, err2); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, CSR, Type, Error, Unavailable string
		Theme                                                template.CSS
		Types                                                []struct{ Name, Label string }
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: path, Theme: pageTheme(caDir)}

	// Each type is offered with what its certificates are for: its extended key usages, else its
	// key usages.
	usageWords := map[string]string{"serverAuth": "TLS server", "clientAuth": "TLS client",
		"emailProtection": "e-mail", "codeSigning": "code signing"}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		def := types[name]
		var words []string
		for _, usage := range def.ExtKeyUsage {
			words = append(words, cmp.Or(usageWords[usage], usage))
		}
		description := "no key usages"
		switch {
		case len(words) > 1:
			description = strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
		case len(words) == 1:
			description = words[0]
		case len(def.KeyUsage) > 0:
			description = "key usages " + strings.Join(def.KeyUsage, ", ")
		}
		page.Types = append(page.Types, struct{ Name, Label string }{name, name + ": " + description})
	}

	// A CA without its key or its tokens shows why it signs no requests, in place of the form.
	switch {
	case !simpleca.FileExists(filepath.Join(caDir, "ca_key.pem")):
		page.Unavailable = "No key of this CA on this server"
	case !simpleca.FileExists(filepath.Join(caDir, tokens.TokensFile)):
		page.Unavailable = "This CA has no tokens yet"
	}

	status := http.StatusOK
	switch {
	case page.Unavailable != "" && r.Method == http.MethodPost:
		status = http.StatusForbidden
	case r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, formMaxBody)
		if err := r.ParseForm(); bodyTooLarge(err) {
			http.Error(w, tooLargeText(formMaxBody), http.StatusRequestEntityTooLarge)
			return
		} else if err != nil {
			http.Error(w, "the form is malformed", http.StatusBadRequest)
			return
		}
		page.CSR, page.Type = r.PostForm.Get("csr"), r.PostForm.Get("type")
		client := clientAddr(r)
		var crt *x509.Certificate
		var fileName string
		token := strings.TrimSpace(r.PostForm.Get("token"))
		// The form takes the defaults of the type, the days and the file name.
		err := guard.attempt(w, r, caDir, func() (err error) {
			if token == "" {
				return apiErr(http.StatusUnauthorized, "a token or a setup code is required")
			}
			crt, _, fileName, err = signWithToken(caDir, token, client, []byte(page.CSR), page.Type, "", 0, nil, nil, true)
			return err
		})
		if err == nil {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fileName}))
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw}))
			return
		}
		var e *apiError
		if !errors.As(err, &e) {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		status, page.Error = e.status, e.msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "sign.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}
