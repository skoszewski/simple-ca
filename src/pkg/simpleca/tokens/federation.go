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

package tokens

import (
	"cmp"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
)

// TokenTypeDef is a token type, the kind of the JWTs simple-ca issues for a verifier other than
// itself: the built-in type it is, or is based on, empty for none, the audience of its JWTs,
// whether one is needed, the template of their subject, their validity, the longest validity of
// one, the longest subject in bytes, and the claims they carry.
type TokenTypeDef struct {
	Base          string
	Audience      string
	NeedsAudience bool
	Subject       string
	Valid         time.Duration
	MaxValid      time.Duration
	MaxSubject    int
	Claims        map[string]string
}

// newTokenType is the token type a type of simple-ca.json without a base starts from.
var newTokenType = TokenTypeDef{Subject: "{name}", Valid: time.Hour}

// builtinTokenTypes are the token types simple-ca.json can redefine and base its own types on.
var builtinTokenTypes = map[string]TokenTypeDef{
	"google": {Base: "google", NeedsAudience: true, Subject: "{name}", Valid: time.Hour, MaxValid: 24 * time.Hour, MaxSubject: 127},
	"azure":  {Base: "azure", Audience: "api://AzureADTokenExchange", Subject: "{name}", Valid: time.Hour, MaxSubject: 600},
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

// Types returns the built-in token types with federation.types of simple-ca.json defined or
// redefined over them. A type of the file redefines only the fields it gives; a new type starts
// from the built-in type its base names, or from newTokenType without one.
func Types(c *simpleca.Config) (map[string]TokenTypeDef, error) {
	types := maps.Clone(builtinTokenTypes)
	for _, name := range slices.Sorted(maps.Keys(c.Federation.Types)) {
		t := c.Federation.Types[name]
		where := fmt.Sprintf("token type '%s' in %s", name, c.Path)
		if !simpleca.KebabCaseRE.MatchString(name) {
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
		def.Claims = maps.Clone(def.Claims)
		if t.Audience != "" {
			def.Audience = t.Audience
		}
		if t.Subject != "" {
			for _, p := range placeholderRE.FindAllString(t.Subject, -1) {
				if p != "{name}" && p != "{ca}" {
					return nil, fmt.Errorf("%s: unknown placeholder %s in the subject: must be {name} or {ca}", where, p)
				}
			}
			def.Subject = t.Subject
		}
		if t.MaxValid != "" {
			d, err := simpleca.ParseDuration(t.MaxValid)
			if err == nil && d == 0 {
				err = errors.New("max_valid must be at least 1 minute")
			}
			if err != nil {
				return nil, fmt.Errorf("%s: max_valid: %w", where, err)
			}
			if def.MaxValid > 0 && d > def.MaxValid {
				return nil, fmt.Errorf("%s: max_valid %s is longer than the %s its base allows", where, t.MaxValid,
					simpleca.DurationText(def.MaxValid))
			}
			def.MaxValid = d
		}
		if t.Valid != "" {
			d, err := simpleca.ParseDuration(t.Valid)
			if err == nil && d == 0 {
				err = errors.New("valid must be at least 1 minute")
			}
			if err != nil {
				return nil, fmt.Errorf("%s: valid: %w", where, err)
			}
			def.Valid = d
		}
		if def.MaxValid > 0 && def.Valid > def.MaxValid {
			return nil, fmt.Errorf("%s: valid %s is longer than max_valid %s", where, simpleca.DurationText(def.Valid),
				simpleca.DurationText(def.MaxValid))
		}
		if err := checkClaims(where, t.Claims); err != nil {
			return nil, err
		}
		if def.Claims == nil && len(t.Claims) > 0 {
			def.Claims = map[string]string{}
		}
		maps.Copy(def.Claims, t.Claims)
		types[name] = def
	}
	return types, nil
}

// tokenTypeNames returns the names of the token types, sorted, joined by commas.
func tokenTypeNames(types map[string]TokenTypeDef) string {
	return strings.Join(slices.Sorted(maps.Keys(types)), ", ")
}

// Issuer returns the issuer of the JWTs of the CA caID, empty for the root CA:
// federation.issuer, else ca_publish_base_url, followed by /caID for an issuing CA, or empty
// without both.
func Issuer(c *simpleca.Config, caID string) string {
	base := strings.TrimSuffix(cmp.Or(c.Federation.Issuer, c.CAPublishBaseURL), "/")
	if base == "" || caID == "" {
		return base
	}
	return base + "/" + caID
}

// TokenFederate is the JWT a token with the scope federate gets: its token type, the audience
// given in place of that of the type, and the claims given over those of the type.
type TokenFederate struct {
	Type     string            `json:"type"`
	Audience string            `json:"audience,omitempty"`
	Claims   map[string]string `json:"claims,omitempty"`
}

// Federation is what the JWTs of a TokenFederate for one name hold: their token type, issuer,
// audience, subject and claims, with the validity and the longest validity of the type.
type Federation struct {
	TypeName, Issuer, Audience, Subject string
	Claims                              map[string]string
	Valid, MaxValid                     time.Duration
}

// Resolve returns the federation of f for the name of the CA caID, as cfg defines its token type,
// or why a JWT of f cannot be issued.
func (f TokenFederate) Resolve(cfg *simpleca.Config, caID, name string) (*Federation, error) {
	types, err := Types(cfg)
	if err != nil {
		return nil, err
	}
	def, ok := types[f.Type]
	if !ok {
		return nil, fmt.Errorf("unknown token type '%s': must be one of %s", f.Type, tokenTypeNames(types))
	}
	audience := cmp.Or(f.Audience, def.Audience)
	if def.NeedsAudience && audience == "" {
		return nil, fmt.Errorf("the token type %s needs an audience", f.Type)
	}
	if err := checkClaims("the claims", f.Claims); err != nil {
		return nil, err
	}
	issuer := Issuer(cfg, caID)
	if issuer == "" {
		return nil, fmt.Errorf("the token type %s needs an issuer: set federation.issuer or ca_publish_base_url of %s",
			f.Type, cfg.Path)
	}
	subject := strings.NewReplacer("{name}", name, "{ca}", caID).Replace(def.Subject)
	if def.MaxSubject > 0 && len(subject) > def.MaxSubject {
		return nil, fmt.Errorf("the subject '%s' of the token type %s is longer than %d bytes", subject, f.Type, def.MaxSubject)
	}
	claims := maps.Clone(def.Claims)
	if claims == nil {
		claims = map[string]string{}
	}
	maps.Copy(claims, f.Claims)
	return &Federation{TypeName: f.Type, Issuer: issuer, Audience: audience, Subject: subject, Claims: claims,
		Valid: def.Valid, MaxValid: def.MaxValid}, nil
}

// IssueJWT returns a JWT of fed signed with caKey, valid for valid, the validity of its type for
// zero, and never after notAfter unless it is zero, with its JWT ID and expiry; it is not stored.
func IssueJWT(caKey crypto.Signer, fed *Federation, valid time.Duration, notAfter time.Time) (string, string, time.Time, error) {
	if valid == 0 {
		valid = fed.Valid
	}
	switch {
	case valid < time.Second:
		return "", "", time.Time{}, errors.New("the validity of a JWT must be at least 1s")
	case fed.MaxValid > 0 && valid > fed.MaxValid:
		return "", "", time.Time{}, fmt.Errorf("the token type %s allows a validity of at most %s", fed.TypeName,
			simpleca.DurationText(fed.MaxValid))
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(valid)
	if !notAfter.IsZero() && notAfter.Before(expires) {
		expires = notAfter.UTC().Truncate(time.Second)
	}
	id := simpleca.RandomID()
	claims, err := json.Marshal(struct {
		ID        string `json:"jti"`
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Audience  string `json:"aud,omitempty"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}{id, fed.Issuer, fed.Subject, fed.Audience, now.Unix(), expires.Unix()})
	if err != nil {
		return "", "", time.Time{}, err
	}
	if len(fed.Claims) > 0 {
		custom, err := json.Marshal(fed.Claims)
		if err != nil {
			return "", "", time.Time{}, err
		}
		claims = append(append(claims[:len(claims)-1], ','), custom[1:]...)
	}
	jwt, err := jose.SignJWT(caKey, claims)
	return jwt, id, expires, err
}

// FederateAudit returns the keys of an audit record naming the token type and the audience a
// token with the scope federate gets, none without it.
func FederateAudit(f *TokenFederate) []any {
	if f == nil {
		return nil
	}
	return []any{"federate", f.Type, "audience", f.Audience}
}

// CAJWKS returns the JSON Web Key Set of the CA in caDir, the public key of its certificate.
func CAJWKS(caDir string) ([]byte, error) {
	cert, err := simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string][]jose.JWK{"keys": {jose.PublicJWK(cert.PublicKey)}}, "", "  ")
}
