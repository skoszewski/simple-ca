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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// tokenTypeDef is a token type: the audience of its JWTs, whether a token needs one, the template
// of their subject, the longest validity of a token, the longest subject in bytes, and the claims
// its JWTs carry.
type tokenTypeDef struct {
	audience      string
	needsAudience bool
	subject       string
	maxValid      time.Duration
	maxSubject    int
	claims        map[string]string
}

// builtinTokenTypes are the token types simple-ca.json can redefine and base its own types on.
var builtinTokenTypes = map[string]tokenTypeDef{
	"api":    {subject: "{name}"},
	"google": {needsAudience: true, subject: "{name}", maxValid: 24 * time.Hour, maxSubject: 127},
	"azure":  {audience: "api://AzureADTokenExchange", subject: "{name}", maxSubject: 600},
}

// reservedClaims are the claims simple-ca writes itself, which a token type and --claim cannot set.
var reservedClaims = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "simple_ca_token"}

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
			return fmt.Errorf("%s: the claim '%s' is written by simple-ca and cannot be given", where, name)
		case !claimNameRE.MatchString(name):
			return fmt.Errorf("%s: the claim '%s' is not a snake_case name, such as deploy_env", where, name)
		}
	}
	return nil
}

// tokenTypes returns the built-in token types with the token types of simple-ca.json defined or
// redefined over them. A type of the file redefines only the fields it gives; a new type starts
// from the built-in type its base names, api without it.
func (c *config) tokenTypes() (map[string]tokenTypeDef, error) {
	types := maps.Clone(builtinTokenTypes)
	for _, name := range slices.Sorted(maps.Keys(c.TokenTypes)) {
		t := c.TokenTypes[name]
		where := fmt.Sprintf("token type '%s' in %s", name, c.path)
		if !kebabCaseRE.MatchString(name) {
			return nil, fmt.Errorf("%s: the name is not a kebab-case name, such as gcp-deploy", where)
		}
		def, builtin := builtinTokenTypes[name]
		switch {
		case builtin && t.Base != "":
			return nil, fmt.Errorf("%s: a built-in type takes no base", where)
		case !builtin:
			base, ok := builtinTokenTypes[cmp.Or(t.Base, "api")]
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

// tokenIssuer returns the issuer of the JWTs of the CA caID, empty for the root CA: tokens.issuer,
// else ca_publish_base_url, followed by /caID for an issuing CA, or empty without both.
func (c *config) tokenIssuer(caID string) string {
	base := strings.TrimSuffix(cmp.Or(c.Tokens.Issuer, c.CAPublishBaseURL), "/")
	if base == "" || caID == "" {
		return base
	}
	return base + "/" + caID
}

// tokenKind is what a token is made for: its token type, api without it, the audience given in
// place of that of the type, and the claims given over those of the type.
type tokenKind struct {
	Type     string
	Audience string
	Claims   map[string]string
}

// apply gives the token name of the CA caID, valid for valid, the token type of k with its issuer,
// audience, subject and claims, as types and cfg define them, or returns why it cannot have them.
func (k tokenKind) apply(tok *apiToken, cfg *config, types map[string]tokenTypeDef, caID, name string, valid time.Duration) error {
	typeName := cmp.Or(k.Type, "api")
	if err := (&apiToken{TokenType: typeName}).checkValid(types, valid); err != nil {
		return err
	}
	def := types[typeName]
	audience := cmp.Or(k.Audience, def.audience)
	if def.needsAudience && audience == "" {
		return fmt.Errorf("the token type %s needs an audience", typeName)
	}
	if err := checkClaims("the claims", k.Claims); err != nil {
		return err
	}
	claims := maps.Clone(def.claims)
	if claims == nil && len(k.Claims) > 0 {
		claims = map[string]string{}
	}
	maps.Copy(claims, k.Claims)
	issuer := ""
	if audience != "" {
		if issuer = cfg.tokenIssuer(caID); issuer == "" {
			return fmt.Errorf("the token type %s needs an issuer: set tokens.issuer or ca_publish_base_url of %s",
				typeName, cfg.path)
		}
	}
	subject := strings.NewReplacer("{name}", name, "{ca}", caID).Replace(def.subject)
	if def.maxSubject > 0 && len(subject) > def.maxSubject {
		return fmt.Errorf("the subject '%s' of the token type %s is longer than %d bytes", subject, typeName, def.maxSubject)
	}
	if subject == name {
		subject = ""
	}
	if typeName == "api" {
		typeName = ""
	}
	tok.TokenType, tok.Issuer, tok.Audience, tok.Subject, tok.Claims = typeName, issuer, audience, subject, claims
	return nil
}

// checkValid returns an error when the token type of tok, as types define it, does not allow the
// validity valid.
func (tok *apiToken) checkValid(types map[string]tokenTypeDef, valid time.Duration) error {
	typeName := cmp.Or(tok.TokenType, "api")
	def, ok := types[typeName]
	switch {
	case !ok:
		return fmt.Errorf("unknown token type '%s': must be one of %s", typeName, tokenTypeNames(types))
	case def.maxValid > 0 && valid > def.maxValid:
		return fmt.Errorf("the token type %s allows a validity of at most %s", typeName, durationText(def.maxValid))
	}
	return nil
}

// tokenKindAudit returns the keys of an audit record naming the token type and the audience of the
// token name of caDir, none for a token of the type api.
func tokenKindAudit(caDir, name string) []any {
	db, err := loadTokens(caDir)
	if err != nil || db.Tokens[name] == nil || db.Tokens[name].TokenType == "" {
		return nil
	}
	t := db.Tokens[name]
	return []any{"token_type", t.TokenType, "audience", t.Audience}
}

// ---- JWK --------------------------------------------------------------------

// jwk is the public key of a CA as a JSON Web Key of RFC 7517, without x5c and x5t.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// publicJWK returns the JWK of the RSA public key pub, its key ID the JWK thumbprint of RFC 7638.
func publicJWK(pub *rsa.PublicKey) jwk {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	thumbprint := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return jwk{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: base64.RawURLEncoding.EncodeToString(thumbprint[:]), N: n, E: e}
}

// caJWKS returns the JSON Web Key Set of the CA in caDir, the public key of its certificate.
func caJWKS(caDir string) ([]byte, error) {
	cert, err := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the key of %s is not an RSA key", filepath.Join(caDir, "ca_cert.pem"))
	}
	return json.MarshalIndent(map[string][]jwk{"keys": {publicJWK(pub)}}, "", "  ")
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
		b, err = json.MarshalIndent(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks.json",
			"id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"id_token"},
			"subject_types_supported": []string{"public"}}, "", "  ")
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
