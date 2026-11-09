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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ---- token types ------------------------------------------------------------

// tokenTypeDef is a token type, the kind of the JWTs simple-ca issues for a verifier other than
// itself: the built-in type it is, or is based on, empty for none, the audience of its JWTs,
// whether one is needed, the template of their subject, their validity, the longest validity of
// one, the longest subject in bytes, and the claims they carry.
type tokenTypeDef struct {
	base          string
	audience      string
	needsAudience bool
	subject       string
	valid         time.Duration
	maxValid      time.Duration
	maxSubject    int
	claims        map[string]string
}

// newTokenType is the token type a type of simple-ca.json without a base starts from.
var newTokenType = tokenTypeDef{subject: "{name}", valid: time.Hour}

// builtinTokenTypes are the token types simple-ca.json can redefine and base its own types on.
var builtinTokenTypes = map[string]tokenTypeDef{
	"google": {base: "google", needsAudience: true, subject: "{name}", valid: time.Hour, maxValid: 24 * time.Hour, maxSubject: 127},
	"azure":  {base: "azure", audience: "api://AzureADTokenExchange", subject: "{name}", valid: time.Hour, maxSubject: 600},
}

// reservedClaims are the claims simple-ca writes itself, or its own tokens carry, which a token
// type and --claim cannot set.
var reservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope"}

// claimNameRE matches the name of a claim given to a token, snake_case.
var claimNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// placeholderRE matches a placeholder of a subject template.
var placeholderRE = regexp.MustCompile(`\{[^{}]*\}`)

// checkClaims returns an error, naming where the claims are given, for a claim name that is not
// snake_case or is reserved.
func checkClaims(where string, claims map[string]string) error {
	for _, name := range slices.Sorted(maps.Keys(claims)) {
		switch {
		case slices.Contains(reservedClaims, name):
			return fmt.Errorf("%s: the claim '%s' is reserved by simple-ca and cannot be given", where, name)
		case !claimNameRE.MatchString(name):
			return fmt.Errorf("%s: the claim '%s' is not a snake_case name, such as deploy_env", where, name)
		}
	}
	return nil
}

// tokenTypes returns the built-in token types with federation.types of simple-ca.json defined or
// redefined over them. A type of the file redefines only the fields it gives; a new type starts
// from the built-in type its base names, or from newTokenType without one.
func (c *config) tokenTypes() (map[string]tokenTypeDef, error) {
	types := maps.Clone(builtinTokenTypes)
	for _, name := range slices.Sorted(maps.Keys(c.Federation.Types)) {
		t := c.Federation.Types[name]
		where := fmt.Sprintf("token type '%s' in %s", name, c.path)
		if !kebabCaseRE.MatchString(name) {
			return nil, fmt.Errorf("%s: the name is not a kebab-case name, such as gcp-deploy", where)
		}
		def, builtin := builtinTokenTypes[name]
		switch {
		case name == "api":
			return nil, fmt.Errorf("%s: api names the tokens of simple-ca itself, not a token type", where)
		case builtin && t.Base != "":
			return nil, fmt.Errorf("%s: a built-in type takes no base", where)
		case !builtin && t.Base == "":
			def = newTokenType
		case !builtin:
			base, ok := builtinTokenTypes[t.Base]
			if !ok {
				return nil, fmt.Errorf("%s: unknown base '%s': must be one of %s", where, t.Base,
					strings.Join(slices.Sorted(maps.Keys(builtinTokenTypes)), ", "))
			}
			def = base
		}
		def.claims = maps.Clone(def.claims)
		if t.Audience != "" {
			def.audience = t.Audience
		}
		if t.Subject != "" {
			for _, p := range placeholderRE.FindAllString(t.Subject, -1) {
				if p != "{name}" && p != "{ca}" {
					return nil, fmt.Errorf("%s: unknown placeholder %s in the subject: must be {name} or {ca}", where, p)
				}
			}
			def.subject = t.Subject
		}
		if t.MaxValid != "" {
			d, err := time.ParseDuration(t.MaxValid)
			if err != nil || d < time.Second {
				return nil, fmt.Errorf("%s: max_valid '%s' is not a duration of at least 1s, such as 24h", where, t.MaxValid)
			}
			if def.maxValid > 0 && d > def.maxValid {
				return nil, fmt.Errorf("%s: max_valid %s is longer than the %s its base allows", where, t.MaxValid,
					durationText(def.maxValid))
			}
			def.maxValid = d
		}
		if t.Valid != "" {
			d, err := time.ParseDuration(t.Valid)
			if err != nil || d < time.Second {
				return nil, fmt.Errorf("%s: valid '%s' is not a duration of at least 1s, such as 1h", where, t.Valid)
			}
			def.valid = d
		}
		if def.maxValid > 0 && def.valid > def.maxValid {
			return nil, fmt.Errorf("%s: valid %s is longer than max_valid %s", where, durationText(def.valid),
				durationText(def.maxValid))
		}
		if err := checkClaims(where, t.Claims); err != nil {
			return nil, err
		}
		if def.claims == nil && len(t.Claims) > 0 {
			def.claims = map[string]string{}
		}
		maps.Copy(def.claims, t.Claims)
		types[name] = def
	}
	return types, nil
}

// tokenTypeNames returns the names of the token types, sorted, joined by commas.
func tokenTypeNames(types map[string]tokenTypeDef) string {
	return strings.Join(slices.Sorted(maps.Keys(types)), ", ")
}

// tokenIssuer returns the issuer of the JWTs of the CA caID, empty for the root CA:
// federation.issuer, else ca_publish_base_url, followed by /caID for an issuing CA, or empty without
// both.
func (c *config) tokenIssuer(caID string) string {
	base := strings.TrimSuffix(cmp.Or(c.Federation.Issuer, c.CAPublishBaseURL), "/")
	if base == "" || caID == "" {
		return base
	}
	return base + "/" + caID
}

// tokenFederate is the JWT a token with the scope federate gets: its token type, the audience
// given in place of that of the type, and the claims given over those of the type.
type tokenFederate struct {
	Type     string            `json:"type"`
	Audience string            `json:"audience,omitempty"`
	Claims   map[string]string `json:"claims,omitempty"`
}

// federation is what the JWTs of a tokenFederate for one name hold: their token type, issuer,
// audience, subject and claims, with the validity and the longest validity of the type.
type federation struct {
	typeName, issuer, audience, subject string
	claims                              map[string]string
	valid, maxValid                     time.Duration
}

// resolve returns the federation of f for the name of the CA caID, as cfg defines its token type,
// or why a JWT of f cannot be issued.
func (f tokenFederate) resolve(cfg *config, caID, name string) (*federation, error) {
	types, err := cfg.tokenTypes()
	if err != nil {
		return nil, err
	}
	def, ok := types[f.Type]
	if !ok {
		return nil, fmt.Errorf("unknown token type '%s': must be one of %s", f.Type, tokenTypeNames(types))
	}
	audience := cmp.Or(f.Audience, def.audience)
	if def.needsAudience && audience == "" {
		return nil, fmt.Errorf("the token type %s needs an audience", f.Type)
	}
	if err := checkClaims("the claims", f.Claims); err != nil {
		return nil, err
	}
	issuer := cfg.tokenIssuer(caID)
	if issuer == "" {
		return nil, fmt.Errorf("the token type %s needs an issuer: set federation.issuer or ca_publish_base_url of %s",
			f.Type, cfg.path)
	}
	subject := strings.NewReplacer("{name}", name, "{ca}", caID).Replace(def.subject)
	if def.maxSubject > 0 && len(subject) > def.maxSubject {
		return nil, fmt.Errorf("the subject '%s' of the token type %s is longer than %d bytes", subject, f.Type, def.maxSubject)
	}
	claims := maps.Clone(def.claims)
	if claims == nil {
		claims = map[string]string{}
	}
	maps.Copy(claims, f.Claims)
	return &federation{typeName: f.Type, issuer: issuer, audience: audience, subject: subject, claims: claims,
		valid: def.valid, maxValid: def.maxValid}, nil
}

// issueJWT returns a JWT of fed signed with caKey, valid for valid, the validity of its type for
// zero, and never after notAfter unless it is zero, with its JWT ID and expiry; it is not stored.
func issueJWT(caKey crypto.Signer, fed *federation, valid time.Duration, notAfter time.Time) (string, string, time.Time, error) {
	if valid == 0 {
		valid = fed.valid
	}
	switch {
	case valid < time.Second:
		return "", "", time.Time{}, errors.New("the validity of a JWT must be at least 1s")
	case fed.maxValid > 0 && valid > fed.maxValid:
		return "", "", time.Time{}, fmt.Errorf("the token type %s allows a validity of at most %s", fed.typeName,
			durationText(fed.maxValid))
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(valid)
	if !notAfter.IsZero() && notAfter.Before(expires) {
		expires = notAfter.UTC().Truncate(time.Second)
	}
	id := randomID()
	claims, err := json.Marshal(struct {
		ID        string `json:"jti"`
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Audience  string `json:"aud,omitempty"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}{id, fed.issuer, fed.subject, fed.audience, now.Unix(), expires.Unix()})
	if err != nil {
		return "", "", time.Time{}, err
	}
	if len(fed.claims) > 0 {
		custom, err := json.Marshal(fed.claims)
		if err != nil {
			return "", "", time.Time{}, err
		}
		claims = append(append(claims[:len(claims)-1], ','), custom[1:]...)
	}
	jwt, err := signJWT(caKey, claims)
	return jwt, id, expires, err
}

// federateAudit returns the keys of an audit record naming the token type and the audience a
// token with the scope federate gets, none without it.
func federateAudit(f *tokenFederate) []any {
	if f == nil {
		return nil
	}
	return []any{"federate", f.Type, "audience", f.Audience}
}

// ---- JWK --------------------------------------------------------------------

// jwk is the public key of a CA as a JSON Web Key of RFC 7517, without x5c and x5t: the modulus
// and the exponent of an RSA key, or the curve and the coordinates of an EC key.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// publicJWK returns the JWK of the RSA or ECDSA P-256 public key pub, its key ID the JWK
// thumbprint of RFC 7638, the SHA-256 of its required members in lexicographic order.
func publicJWK(pub crypto.PublicKey) jwk {
	b64 := base64.RawURLEncoding.EncodeToString
	var k jwk
	var members string
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		bytes, _ := p.Bytes()
		k = jwk{Kty: "EC", Crv: "P-256", X: b64(bytes[1:33]), Y: b64(bytes[33:65])}
		members = `{"crv":"` + k.Crv + `","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case *rsa.PublicKey:
		k = jwk{Kty: "RSA", N: b64(p.N.Bytes()), E: b64(big.NewInt(int64(p.E)).Bytes())}
		members = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	}
	thumbprint := sha256.Sum256([]byte(members))
	k.Use, k.Alg, k.Kid = "sig", jwtAlg(pub), b64(thumbprint[:])
	return k
}

// caJWKS returns the JSON Web Key Set of the CA in caDir, the public key of its certificate.
func caJWKS(caDir string) ([]byte, error) {
	cert, err := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string][]jwk{"keys": {publicJWK(cert.PublicKey)}}, "", "  ")
}

// serveTokenIssuer answers, for the CA caID of rootDir, GET .well-known/openid-configuration with
// the OpenID Connect discovery document of its JWTs, and GET jwks.json with their keys; a CA
// without an issuer is not found.
func serveTokenIssuer(w http.ResponseWriter, r *http.Request, rootDir, caID string, discovery bool) {
	dir := filepath.Join(rootDir, caID)
	if caID != "" && (!kebabCaseRE.MatchString(caID) || !fileExists(filepath.Join(dir, "ca_cert.pem"))) {
		http.NotFound(w, r)
		return
	}
	cfg, err := loadConfig(rootDir)
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	issuer := cfg.tokenIssuer(caID)
	if issuer == "" {
		http.NotFound(w, r)
		return
	}
	var b []byte
	if discovery {
		var cert *x509.Certificate
		if cert, err = loadCert(filepath.Join(dir, "ca_cert.pem")); err == nil {
			b, err = json.MarshalIndent(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks.json",
				"id_token_signing_alg_values_supported": []string{jwtAlg(cert.PublicKey)},
				"response_types_supported":              []string{"id_token"}, "subject_types_supported": []string{"public"}}, "", "  ")
		}
	} else {
		b, err = caJWKS(dir)
	}
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(append(b, '\n'))
}
