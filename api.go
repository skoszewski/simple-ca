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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"log"
	"maps"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// ---- signing API tokens -----------------------------------------------------

const (
	tokensFile          = "tokens-db.json"
	tokensPurgeInterval = 5 * time.Minute
)

// tokensLockWait is how long a command or serve waits for the lock of tokens-db.json.
var tokensLockWait = 10 * time.Second

// jwtHeader is the base64url header of the tokens, RS256 signed.
var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

var tokenNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// apiToken is a token of the signing API of a CA: its JWT ID, the certificate types and the
// domains it allows, its validity, and the serial numbers of the certificates issued with it. A
// revoked token has no entry.
type apiToken struct {
	ID      string    `json:"id"`
	Types   []string  `json:"types"`
	Domains []string  `json:"domains"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
	Certs   []string  `json:"certs,omitempty"`
}

// tokensDB is tokens-db.json of a CA directory, the tokens of its signing API by name.
type tokensDB struct {
	Tokens map[string]*apiToken `json:"tokens"`
}

// jwtClaims are the claims of a token: its ID, its name, and when it was issued and expires, in
// seconds since the epoch.
type jwtClaims struct {
	ID        string `json:"jti"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// loadTokens reads tokens-db.json of caDir, or returns an empty database when it does not exist.
func loadTokens(caDir string) (*tokensDB, error) {
	db := &tokensDB{Tokens: map[string]*apiToken{}}
	b, err := os.ReadFile(filepath.Join(caDir, tokensFile))
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", filepath.Join(caDir, tokensFile), err)
	}
	if db.Tokens == nil {
		db.Tokens = map[string]*apiToken{}
	}
	return db, nil
}

// save writes the database to tokens-db.json of caDir, readable by its owner alone.
func (db *tokensDB) save(caDir string) error {
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, tokensFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, tokensFile))
}

// lockTokens locks tokens-db.json of caDir for the commands and serve by creating
// tokens-db.json.lock, which one of them at a time can create, holding the PID of the locker. It
// waits up to tokensLockWait for the lock, and returns the function that unlocks it.
func lockTokens(caDir string) (func(), error) {
	path := filepath.Join(caDir, tokensFile+".lock")
	deadline := time.Now().Add(tokensLockWait)
	for {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, err = fmt.Fprintf(f, "%d\n", os.Getpid())
			if err := cmp.Or(err, f.Close()); err != nil {
				os.Remove(path)
				return nil, err
			}
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if time.Now().After(deadline) {
			pid, _ := os.ReadFile(path)
			return nil, fmt.Errorf("%s is locked by process %s; remove %s if that process is gone",
				filepath.Join(caDir, tokensFile), strings.TrimSpace(string(pid)), path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// purgeTokens removes the expired tokens from tokens-db.json of caDir, when it exists, and returns
// their count.
func purgeTokens(caDir string) (int, error) {
	if !fileExists(filepath.Join(caDir, tokensFile)) {
		return 0, nil
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	n := len(db.Tokens)
	maps.DeleteFunc(db.Tokens, func(_ string, t *apiToken) bool { return !now.Before(t.Expires) })
	if n == len(db.Tokens) {
		return 0, nil
	}
	return n - len(db.Tokens), db.save(caDir)
}

// makeToken adds the token name, valid for valid, for the certificate types certTypes and the
// domains to tokens-db.json of the CA in caDir, and returns its JWT, signed with the CA key.
func makeToken(caDir, name string, valid time.Duration, certTypes, domains []string) (string, error) {
	if valid < time.Second {
		return "", errors.New("--valid must be at least 1s")
	}
	if !tokenNameRE.MatchString(name) {
		return "", fmt.Errorf("token name '%s': a token name is made of letters, digits, '.', '-' and '_'", name)
	}
	if len(domains) == 0 {
		return "", errors.New("at least one --domain is required")
	}
	var names []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if !isHostname(d) {
			return "", fmt.Errorf("--domain '%s' is not a domain name", d)
		}
		names = append(names, d)
	}
	cfg, err := loadRootConfig(caDir)
	if err != nil {
		return "", err
	}
	types, err := cfg.certTypes()
	if err != nil {
		return "", err
	}
	for _, t := range certTypes {
		if _, ok := types[t]; !ok {
			return "", fmt.Errorf("unknown type '%s': must be one of %s", t, typeNames(types))
		}
	}
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) || !fileExists(caKeyPath) {
		return "", fmt.Errorf(
			"CA certificate and key not found in %s. Please point --ca-dir to a CA directory", caDir)
	}
	caKey, err := loadKey(caKeyPath)
	if err != nil {
		return "", err
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return "", err
	}
	if _, ok := db.Tokens[name]; ok {
		return "", fmt.Errorf("token '%s' exists", name)
	}

	now := time.Now().UTC().Truncate(time.Second)
	tok := &apiToken{ID: randomID(), Types: certTypes, Domains: names, Issued: now, Expires: now.Add(valid)}
	claims, err := json.Marshal(jwtClaims{tok.ID, name, tok.Issued.Unix(), tok.Expires.Unix()})
	if err != nil {
		return "", err
	}
	signed := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, caKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	db.Tokens[name] = tok
	if err := db.save(caDir); err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// listTokens writes the tokens of the CA in caDir to w, one per line, sorted by name.
func listTokens(w io.Writer, caDir string) error {
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) {
		return fmt.Errorf("CA certificate not found in %s. Please point --ca-dir to a CA directory", caDir)
	}
	db, err := loadTokens(caDir)
	if err != nil {
		return err
	}
	now := time.Now()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tEXPIRES\tTYPES\tDOMAINS\tCERTS")
	for _, name := range slices.Sorted(maps.Keys(db.Tokens)) {
		t := db.Tokens[name]
		status := "valid"
		if !now.Before(t.Expires) {
			status = "expired"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\n", name, status, t.Expires.UTC().Format(displayTimeFormat),
			strings.Join(t.Types, ","), strings.Join(t.Domains, ","), len(t.Certs))
	}
	return tw.Flush()
}

// revokeToken revokes the token name of the CA in caDir by removing it from tokens-db.json; its
// JWT is unknown from then on, also when the name is used again, as the new token has a new ID.
func revokeToken(caDir, name string) error {
	unlock, err := lockTokens(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := loadTokens(caDir)
	if err != nil {
		return err
	}
	if _, ok := db.Tokens[name]; !ok {
		return fmt.Errorf("token '%s' not found in %s", name, filepath.Join(caDir, tokensFile))
	}
	delete(db.Tokens, name)
	if err := db.save(caDir); err != nil {
		return err
	}
	fmt.Printf("Token %s revoked\n", name)
	return nil
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
func checkToken(db *tokensDB, caCert *x509.Certificate, token string) (string, *apiToken, error) {
	invalid := apiErr(http.StatusUnauthorized, "invalid token")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", nil, invalid
	}
	header, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", nil, invalid
	}
	var h struct{ Alg string }
	if json.Unmarshal(header, &h) != nil || h.Alg != "RS256" {
		return "", nil, invalid
	}
	if verifyJWS("RS256", caCert.PublicKey, []byte(parts[0]+"."+parts[1]), sig) != nil {
		return "", nil, invalid
	}
	var c jwtClaims
	if json.Unmarshal(payload, &c) != nil {
		return "", nil, invalid
	}
	now := time.Now()
	t, ok := db.Tokens[c.Subject]
	switch {
	case !ok || t.ID != c.ID:
		return "", nil, apiErr(http.StatusUnauthorized, "unknown token")
	case now.Unix() >= c.ExpiresAt || !now.Before(t.Expires):
		return "", nil, apiErr(http.StatusUnauthorized, "the token has expired")
	}
	return c.Subject, t, nil
}

// checkCSRNames checks the names of csr against the name rules names, "server" or "user", and the
// domains of a token: the subject holds only a CN and email addresses, and the SANs only DNS names
// and email addresses; with the server rules, the CN and the DNS names are in the domains and
// there are no email addresses; with the user rules, the domains of the email addresses are in
// the domains and there are no DNS names.
func checkCSRNames(csr *x509.CertificateRequest, names string, domains []string) error {
	var emails []string
	for _, attr := range csr.Subject.Names {
		switch {
		case attr.Type.Equal(oidEmailAddress):
			s, _ := attr.Value.(string)
			emails = append(emails, s)
		case attr.Type.String() != "2.5.4.3":
			return apiErr(http.StatusForbidden, "the subject may hold only CN and emailAddress")
		}
	}
	if san := csrSAN(csr); san != nil {
		var gns []asn1.RawValue
		if rest, err := asn1.Unmarshal(san.Value, &gns); err != nil || len(rest) > 0 {
			return apiErr(http.StatusBadRequest, "the subject alternative names do not parse")
		}
		for _, n := range gns {
			if n.Class != asn1.ClassContextSpecific || (n.Tag != 1 && n.Tag != 2) {
				return apiErr(http.StatusForbidden, "the subject alternative names may be only DNS names and email addresses")
			}
		}
	}
	emails = append(emails, csr.EmailAddresses...)

	if names == "user" {
		if len(csr.DNSNames) > 0 {
			return apiErr(http.StatusForbidden, "a %s certificate has no DNS names", names)
		}
		if len(emails) == 0 {
			return apiErr(http.StatusForbidden, "the request has no email address")
		}
		for _, e := range emails {
			_, domain, _ := strings.Cut(e, "@")
			if !emailRE.MatchString(e) || !inDomains(strings.ToLower(domain), domains) {
				return apiErr(http.StatusForbidden, "the token does not allow '%s'", e)
			}
		}
		return nil
	}
	if len(emails) > 0 {
		return apiErr(http.StatusForbidden, "a %s certificate has no email addresses", names)
	}
	hosts := csr.DNSNames
	if csr.Subject.CommonName != "" {
		hosts = append([]string{csr.Subject.CommonName}, hosts...)
	}
	if len(hosts) == 0 {
		return apiErr(http.StatusForbidden, "the request has no DNS name")
	}
	for _, h := range hosts {
		if !isHostname(strings.TrimPrefix(h, "*.")) || !inDomains(strings.ToLower(h), domains) {
			return apiErr(http.StatusForbidden, "the token does not allow '%s'", h)
		}
	}
	return nil
}

// signWithToken signs the CSR csrData, PEM or DER, with the CA in caDir as a certificate of the
// type certType, the first type of the token by default, for the JWT token of the CA's
// tokens-db.json, records it in index.txt and in the token's entry, and returns it with the CA
// certificate and the name of its file, NAME_cert.pem by the rules of cert create, the serial
// number for a request without a name. mu and the lock of tokens-db.json are held from the token
// check to the writes of index.txt and tokens-db.json.
func signWithToken(caDir, token string, csrData []byte, certType string, mu *sync.Mutex) (cert, caCert *x509.Certificate, fileName string, err error) {
	mu.Lock()
	defer mu.Unlock()
	unlock, err := lockTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	defer unlock()
	caCert, err = loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, nil, "", err
	}
	db, err := loadTokens(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	name, tok, err := checkToken(db, caCert, strings.TrimSpace(token))
	if err != nil {
		return nil, nil, "", err
	}
	if certType == "" && len(tok.Types) > 0 {
		certType = tok.Types[0]
	}
	if !slices.Contains(tok.Types, certType) {
		return nil, nil, "", apiErr(http.StatusForbidden, "the token does not allow the type '%s'", certType)
	}
	cfg, err := loadRootConfig(caDir)
	if err != nil {
		return nil, nil, "", err
	}
	types, err := cfg.certTypes()
	if err != nil {
		return nil, nil, "", err
	}
	def, ok := types[certType]
	if !ok {
		return nil, nil, "", apiErr(http.StatusBadRequest, "unknown type '%s'", certType)
	}
	csr, err := parseCSR(csrData)
	if err != nil {
		return nil, nil, "", apiErr(http.StatusBadRequest, "csr: %v", err)
	}
	if err := checkCSRNames(csr, def.names, tok.Domains); err != nil {
		return nil, nil, "", err
	}

	days := 365
	if cfg.Days.Cert > 0 {
		days = cfg.Days.Cert
	}
	tmpl := &x509.Certificate{RawSubject: csr.RawSubject}
	if san := csrSAN(csr); san != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	cert, err = issueLeaf(caDir, certType, days, nil, nil, tmpl, csr.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	if err := recordIssued(caDir, cert); err != nil {
		return nil, nil, "", err
	}
	serial := serialHex(cert.SerialNumber)
	tok.Certs = append(tok.Certs, serial)
	if err := db.save(caDir); err != nil {
		return nil, nil, "", err
	}
	log.Printf("API certificate %s issued to token %s for %s", serial, name, nameString(cert.Subject))

	// The file is named after the CN, else the first DNS name or email address.
	cn, email := csr.Subject.CommonName, ""
	if cn == "" && len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	}
	for _, attr := range csr.Subject.Names {
		if s, ok := attr.Value.(string); ok && attr.Type.Equal(oidEmailAddress) && email == "" {
			email = s
		}
	}
	if email == "" && len(csr.EmailAddresses) > 0 {
		email = csr.EmailAddresses[0]
	}
	fileName = cmp.Or(certFileName(strings.TrimPrefix(cn, "*."), email, def.names == "user"), serial) + "_cert.pem"
	return cert, caCert, fileName, nil
}

// apiSign serves a POST of /api/sign for the CA in caDir: it signs the CSR of the JSON request
// with the type it names for the bearer token of the request, as signWithToken, and returns the
// certificate with its chain.
func apiSign(w http.ResponseWriter, r *http.Request, caDir string, mu *sync.Mutex) {
	log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	if !fileExists(filepath.Join(caDir, "ca_key.pem")) || !fileExists(filepath.Join(caDir, tokensFile)) {
		http.NotFound(w, r)
		return
	}
	var cert, caCert *x509.Certificate
	var req struct {
		CSR  string `json:"csr"`
		Type string `json:"type"`
	}
	var err error
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	dec := json.NewDecoder(io.LimitReader(r.Body, acmeMaxBody))
	dec.DisallowUnknownFields()
	switch {
	case strings.TrimSpace(ct) != "application/json":
		err = apiErr(http.StatusUnsupportedMediaType, "the content type must be application/json")
	case !ok:
		err = apiErr(http.StatusUnauthorized, "a bearer token is required")
	case dec.Decode(&req) != nil:
		err = apiErr(http.StatusBadRequest, "invalid request: the body is not a JSON object of csr and type")
	default:
		cert, caCert, _, err = signWithToken(caDir, token, []byte(req.CSR), req.Type, mu)
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		var e *apiError
		if !errors.As(err, &e) {
			log.Printf("%s: %v", r.URL.Path, err)
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		if e.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		w.WriteHeader(e.status)
		json.NewEncoder(w).Encode(map[string]string{"error": e.msg})
		return
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	chain := certPEM
	if !bytes.Equal(caCert.RawSubject, caCert.RawIssuer) {
		chain += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	}
	json.NewEncoder(w).Encode(map[string]string{"serial": serialHex(cert.SerialNumber), "certificate": certPEM, "chain": chain})
}

// ---- /sign ------------------------------------------------------------------

// signTemplate is the page of /sign, a form of a CSR, a certificate type and a token, in the style
// of the index page.
var signTemplate = template.Must(template.New("sign").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign a certificate request - {{.Title}} - simple-ca</title>
    <script src="{{.Script}}"></script>
  </head>
  <body class="min-h-screen bg-slate-100 text-slate-900">
    <div class="mx-auto max-w-3xl px-4 py-10 sm:py-16">
      <div class="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-lg">
        <div class="bg-slate-900 px-6 py-4 text-slate-100">
          <h1 class="text-xl font-semibold">Sign a certificate request</h1>
          <p class="mt-1 text-sm text-slate-300">{{.Title}}, served by simple-ca</p>
        </div>
        {{- if .Unavailable}}
        <div class="space-y-4 px-6 py-5">
          <p class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">{{.Unavailable}}</p>
          <a class="text-sm text-sky-700 hover:underline" href="/">All CAs</a>
        </div>
        {{- else}}
        <form method="post" action="{{.Action}}" class="space-y-5 px-6 py-5">
          {{- if .Error}}
          <p class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{{.Error}}</p>
          {{- end}}
          <div class="space-y-1">
            <label for="csr" class="block text-sm font-medium">Certificate signing request (PEM)</label>
            <textarea id="csr" name="csr" rows="14" required spellcheck="false"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----">{{.CSR}}</textarea>
          </div>
          <div class="space-y-1">
            <label for="type" class="block text-sm font-medium">Certificate type</label>
            <select id="type" name="type" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm">
              <option value="">the first type of the token</option>
              {{- range .Types}}
              <option value="{{.}}"{{if eq . $.Type}} selected{{end}}>{{.}}</option>
              {{- end}}
            </select>
          </div>
          <div class="space-y-1">
            <label for="token" class="block text-sm font-medium">Token</label>
            <input id="token" name="token" type="password" required autocomplete="off"
              class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm">
          </div>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <a class="text-sm text-sky-700 hover:underline" href="/">All CAs</a>
            <button type="submit" class="rounded-lg bg-sky-700 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-sky-600">Sign and download</button>
          </div>
        </form>
        {{- end}}
      </div>
    </div>
  </body>
</html>
`))

// signPage serves /sign for the CA in caDir, whose page is at path: GET shows the form, and POST
// signs its CSR with its type and token, as signWithToken, and sends the certificate as a
// download, or shows the form again with the error. For a CA without its key or its
// tokens-db.json, the page says why it signs no requests, and a POST is 403 Forbidden.
func signPage(w http.ResponseWriter, r *http.Request, caDir, path string, mu *sync.Mutex) {
	log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	caCert, err1 := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	cfg, err2 := loadRootConfig(caDir)
	var types map[string]certTypeDef
	if err := cmp.Or(err1, err2); err == nil {
		types, err1 = cfg.certTypes()
	}
	if err := cmp.Or(err1, err2); err != nil {
		log.Printf("%s: %v", r.URL.Path, err)
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, CSR, Type, Error, Unavailable string
		Types                                                []string
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: path, Types: slices.Sorted(maps.Keys(types))}

	// A CA without its key or its tokens shows why it signs no requests, in place of the form.
	switch {
	case !fileExists(filepath.Join(caDir, "ca_key.pem")):
		page.Unavailable = "This CA does not sign requests here: its key is not on this server."
	case !fileExists(filepath.Join(caDir, tokensFile)):
		page.Unavailable = "This CA has no tokens yet. Its administrator creates one with " +
			"simple-ca token create, with --ca-dir set to the directory of this CA."
	}

	status := http.StatusOK
	switch {
	case page.Unavailable != "" && r.Method == http.MethodPost:
		status = http.StatusForbidden
	case r.Method == http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, acmeMaxBody)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "the form is too large or malformed", http.StatusBadRequest)
			return
		}
		page.CSR, page.Type = r.PostForm.Get("csr"), r.PostForm.Get("type")
		cert, _, fileName, err := signWithToken(caDir, r.PostForm.Get("token"), []byte(page.CSR), page.Type, mu)
		if err == nil {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": fileName}))
			w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			return
		}
		var e *apiError
		if !errors.As(err, &e) {
			log.Printf("%s: %v", r.URL.Path, err)
			e = apiErr(http.StatusInternalServerError, "internal error")
		}
		status, page.Error = e.status, e.msg
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := signTemplate.Execute(w, page); err != nil {
		log.Printf("%s: %v", r.URL.Path, err)
	}
}
