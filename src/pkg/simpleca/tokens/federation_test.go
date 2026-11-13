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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
)

// federationConfig returns the config of simple-ca.json of a new directory holding the JSON
// settings.
func federationConfig(t *testing.T, settings string) *simpleca.Config {
	t.Helper()
	dir := t.TempDir()
	writeConfig(t, dir, settings)
	cfg, err := simpleca.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestTokenIssuer(t *testing.T) {
	for _, c := range []struct {
		issuer, base, caID, want string
	}{
		{"", "", "", ""},
		{"", "", "servers", ""},
		{"", "http://pki.example.com/", "", "http://pki.example.com"},
		{"", "http://pki.example.com", "servers", "http://pki.example.com/servers"},
		{"https://ca.example.com/", "http://pki.example.com", "", "https://ca.example.com"},
		{"https://ca.example.com", "http://pki.example.com", "servers", "https://ca.example.com/servers"},
	} {
		cfg := &simpleca.Config{CAPublishBaseURL: c.base, Federation: simpleca.FederationConfig{Issuer: c.issuer}}
		if got := Issuer(cfg, c.caID); got != c.want {
			t.Errorf("TokenIssuer(%q) of issuer %q and base %q = %q, want %q", c.caID, c.issuer, c.base, got, c.want)
		}
	}
}

func TestBuiltinTokenTypes(t *testing.T) {
	types, err := Types(&simpleca.Config{Path: simpleca.ConfigFile})
	if err != nil || tokenTypeNames(types) != "azure, google" {
		t.Fatalf("built-in token types %v, %v, want azure and google", tokenTypeNames(types), err)
	}
	google, azure := types["google"], types["azure"]
	if google.Base != "google" || !google.NeedsAudience || google.Audience != "" || google.Subject != "{name}" ||
		google.Valid != time.Hour || google.MaxValid != 24*time.Hour || google.MaxSubject != 127 {
		t.Errorf("the token type google: %+v", google)
	}
	if azure.Base != "azure" || azure.NeedsAudience || azure.Audience != "api://AzureADTokenExchange" ||
		azure.Subject != "{name}" || azure.Valid != time.Hour || azure.MaxValid != 0 || azure.MaxSubject != 600 {
		t.Errorf("the token type azure: %+v", azure)
	}
}

func TestConfigTokenTypes(t *testing.T) {
	cfg := federationConfig(t, `{"federation": {"types": {
		"google": {"audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/simple-ca",
			"valid": "2h"},
		"azure": {"claims": {"deploy_env": "lab"}},
		"azure-deploy": {"base": "azure", "subject": "{ca}:{name}", "max_valid": "8h", "claims": {"deploy_env": "prod"}},
		"custom": {"audience": "https://verifier.example.com", "valid": "30", "max_valid": "8h", "claims": {"team": "ops"}}
	}}}`)
	types, err := Types(cfg)
	if err != nil {
		t.Fatalf("TokenTypes: %v", err)
	}
	if names := tokenTypeNames(types); names != "azure, azure-deploy, custom, google" {
		t.Fatalf("token types %s, want the built-in types and those of the file", names)
	}

	// A built-in type redefines only the fields given.
	if g := types["google"]; !strings.HasPrefix(g.Audience, "//iam.googleapis.com/") || g.Valid != 2*time.Hour ||
		g.MaxValid != 24*time.Hour || !g.NeedsAudience || g.MaxSubject != 127 || g.Base != "google" {
		t.Errorf("the redefined type google: %+v", g)
	}
	if a := types["azure"]; a.Audience != "api://AzureADTokenExchange" || !maps.Equal(a.Claims, map[string]string{"deploy_env": "lab"}) {
		t.Errorf("the redefined type azure: %+v", a)
	}

	// A new type starts from its base, or from newTokenType without one.
	if d := types["azure-deploy"]; d.Base != "azure" || d.Audience != "api://AzureADTokenExchange" || d.Subject != "{ca}:{name}" ||
		d.Valid != time.Hour || d.MaxValid != 8*time.Hour || d.MaxSubject != 600 ||
		!maps.Equal(d.Claims, map[string]string{"deploy_env": "prod"}) {
		t.Errorf("the type azure-deploy: %+v", d)
	}
	if c := types["custom"]; c.Base != "" || c.NeedsAudience || c.Audience != "https://verifier.example.com" ||
		c.Subject != "{name}" || c.Valid != 30*time.Minute || c.MaxValid != 8*time.Hour || c.MaxSubject != 0 ||
		!maps.Equal(c.Claims, map[string]string{"team": "ops"}) {
		t.Errorf("the type custom: %+v", c)
	}

	// The built-in types and the types of an earlier call are not changed.
	types["custom"].Claims["team"] = "changed"
	if builtinTokenTypes["azure"].Claims != nil || newTokenType.Claims != nil {
		t.Errorf("TokenTypes changed the built-in types: %+v %+v", builtinTokenTypes["azure"], newTokenType)
	}
	if again, err := Types(cfg); err != nil || again["custom"].Claims["team"] != "ops" {
		t.Errorf("TokenTypes again: %v, %v, want the claims of the file", again["custom"].Claims, err)
	}
}

func TestConfigTokenTypesRefused(t *testing.T) {
	for _, c := range []struct{ name, def, want string }{
		{"Bad_Name", `{}`, "not a kebab-case name"},
		{"api", `{}`, "api names the tokens of simple-ca itself"},
		{"google", `{"base": "azure"}`, "a built-in type takes no base"},
		{"x", `{"base": "nosuch"}`, `unknown base "nosuch": must be one of azure, google`},
		{"x", `{"subject": "{name}-{user}"}`, `unknown placeholder "{user}"`},
		{"x", `{"max_valid": "0"}`, "max_valid must be at least 1 minute"},
		{"x", `{"max_valid": "8 hours"}`, `max_valid: "8 hours" is not a duration`},
		{"google", `{"max_valid": "2d"}`, `max_valid "2d" is longer than the 1d its base allows`},
		{"x", `{"valid": "0"}`, "valid must be at least 1 minute"},
		{"x", `{"valid": "bad"}`, `valid: "bad" is not a duration`},
		{"x", `{"valid": "9h", "max_valid": "8h"}`, "valid 9h is longer than max_valid 8h"},
		{"google", `{"valid": "2d"}`, "valid 2d is longer than max_valid 1d"},
		{"x", `{"claims": {"sub": "a"}}`, `the claim "sub" is reserved`},
		{"x", `{"claims": {"DeployEnv": "a"}}`, `the claim "DeployEnv" is not a snake_case name`},
	} {
		cfg := federationConfig(t, `{"federation": {"types": {"`+c.name+`": `+c.def+`}}}`)
		_, err := Types(cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), fmt.Sprintf("token type %q in %q", c.name, cfg.Path)) {
			t.Errorf("TokenTypes of %s %s: %v, want an error with %q", c.name, c.def, err, c.want)
		}
	}
}

func TestCheckClaims(t *testing.T) {
	if err := checkClaims("here", nil); err != nil {
		t.Errorf("checkClaims of none: %v", err)
	}
	if err := checkClaims("here", map[string]string{"deploy_env": "prod", "a1_b2": "x", "team": ""}); err != nil {
		t.Errorf("checkClaims of snake_case claims: %v", err)
	}
	for _, name := range append(slices.Clone(reservedClaims), "Deploy", "deploy-env", "_x", "x__y", "x_", "1x", "") {
		if err := checkClaims("here", map[string]string{name: "v"}); err == nil || !strings.HasPrefix(err.Error(), "here: ") {
			t.Errorf("checkClaims of the claim %q: %v, want an error", name, err)
		}
	}
}

func TestResolve(t *testing.T) {
	cfg := federationConfig(t, `{"federation": {"issuer": "https://ca.example.com", "types": {
		"azure-deploy": {"base": "azure", "subject": "{ca}:{name}", "claims": {"deploy_env": "prod", "team": "web"}}}}}`)
	fed, err := TokenFederate{Type: "azure-deploy", Claims: map[string]string{"deploy_env": "dev"}}.Resolve(cfg, "servers", "web")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := &Federation{TypeName: "azure-deploy", Issuer: "https://ca.example.com/servers", Audience: "api://AzureADTokenExchange",
		Subject: "servers:web", Claims: map[string]string{"deploy_env": "dev", "team": "web"}, Valid: time.Hour}
	if fed.TypeName != want.TypeName || fed.Issuer != want.Issuer || fed.Audience != want.Audience || fed.Subject != want.Subject ||
		!maps.Equal(fed.Claims, want.Claims) || fed.Valid != want.Valid || fed.MaxValid != 0 {
		t.Errorf("Resolve = %+v, want %+v", fed, want)
	}
	if types, _ := Types(cfg); types["azure-deploy"].Claims["deploy_env"] != "prod" {
		t.Error("Resolve changed the claims of the token type")
	}

	// The root CA has the issuer alone and an empty {ca}; an audience given replaces that of the type.
	fed, err = TokenFederate{Type: "azure-deploy", Audience: "api://custom"}.Resolve(cfg, "", "web")
	if err != nil || fed.Issuer != "https://ca.example.com" || fed.Subject != ":web" || fed.Audience != "api://custom" ||
		!maps.Equal(fed.Claims, map[string]string{"deploy_env": "prod", "team": "web"}) {
		t.Errorf("Resolve for the root CA: %+v, %v", fed, err)
	}
	fed, err = TokenFederate{Type: "google", Audience: "//iam.googleapis.com/x"}.Resolve(cfg, "servers", "deploy")
	if err != nil || fed.Subject != "deploy" || fed.Valid != time.Hour || fed.MaxValid != 24*time.Hour || fed.Claims == nil ||
		len(fed.Claims) != 0 {
		t.Errorf("Resolve of google: %+v, %v", fed, err)
	}

	for _, c := range []struct {
		cfg  *simpleca.Config
		f    TokenFederate
		name string
		want string
	}{
		{cfg, TokenFederate{Type: "nosuch"}, "web", `unknown token type "nosuch": must be one of azure, azure-deploy, google`},
		{cfg, TokenFederate{Type: "google"}, "web", "the token type google needs an audience"},
		{cfg, TokenFederate{Type: "azure", Claims: map[string]string{"aud": "x"}}, "web", `the claim "aud" is reserved`},
		{cfg, TokenFederate{Type: "google", Audience: "x"}, strings.Repeat("a", 128), "longer than 127 bytes"},
		{&simpleca.Config{Path: simpleca.ConfigFile}, TokenFederate{Type: "azure"}, "web", "needs an issuer: set federation.issuer or ca_publish_base_url"},
		{federationConfig(t, `{"federation": {"types": {"api": {}}}}`), TokenFederate{Type: "azure"}, "web", "api names the tokens"},
	} {
		if _, err := c.f.Resolve(c.cfg, "servers", c.name); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Resolve of %+v: %v, want an error with %q", c.f, err, c.want)
		}
	}
	if _, err := (TokenFederate{Type: "google", Audience: "x"}).Resolve(cfg, "", strings.Repeat("a", 127)); err != nil {
		t.Errorf("Resolve of a subject of 127 bytes: %v", err)
	}
}

func TestIssueJWT(t *testing.T) {
	for _, keyType := range []string{"rsa", "ec"} {
		root := newRoot(t, keyType)
		jwks, err := CAJWKS(root.dir)
		if err != nil {
			t.Fatal(err)
		}
		fed := &Federation{TypeName: "custom", Issuer: "https://ca.example.com", Audience: "https://verifier.example.com",
			Subject: "web", Claims: map[string]string{"deploy_env": "prod"}, Valid: time.Hour, MaxValid: 8 * time.Hour}
		jwt, id, expires, err := IssueJWT(root.key, fed, 0, time.Time{})
		if err != nil {
			t.Fatalf("IssueJWT with an %s key: %v", keyType, err)
		}
		header, claims := verifyJWT(t, jwt, jwks)
		if want := map[string]string{"rsa": "RS256", "ec": "ES256"}[keyType]; header["alg"] != want {
			t.Errorf("the algorithm of an %s key: %v, want %s", keyType, header["alg"], want)
		}
		iat, _ := claims["iat"].(float64)
		if claims["jti"] != id || claims["iss"] != fed.Issuer || claims["sub"] != "web" || claims["aud"] != fed.Audience ||
			claims["deploy_env"] != "prod" || claims["exp"] != float64(expires.Unix()) || claims["exp"] != iat+3600 ||
			time.Since(time.Unix(int64(iat), 0)) > time.Minute || len(claims) != 7 {
			t.Errorf("claims %v, want those of the federation, valid for an hour", claims)
		}

		// A validity given replaces that of the type, and notAfter cuts it.
		_, _, _, err = IssueJWT(root.key, fed, 2*time.Hour, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		notAfter := time.Now().Add(10*time.Minute + 500*time.Millisecond)
		jwt, _, expires, err = IssueJWT(root.key, fed, 2*time.Hour, notAfter)
		if err != nil || !expires.Equal(notAfter.UTC().Truncate(time.Second)) {
			t.Errorf("IssueJWT with notAfter: %v, %v, want %v", expires, err, notAfter.UTC().Truncate(time.Second))
		}
		if _, claims := verifyJWT(t, jwt, jwks); claims["exp"] != float64(expires.Unix()) {
			t.Errorf("exp %v, want %d", claims["exp"], expires.Unix())
		}

		// A JWT without an audience and claims has the registered claims alone.
		bare := &Federation{TypeName: "azure", Issuer: "https://ca.example.com/servers", Subject: "servers:web", Valid: time.Hour}
		jwt, _, _, err = IssueJWT(root.key, bare, 0, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if _, claims := verifyJWT(t, jwt, jwks); len(claims) != 5 || claims["aud"] != nil {
			t.Errorf("claims %v, want jti, iss, sub, iat and exp", claims)
		}

		for _, c := range []struct {
			fed   *Federation
			valid time.Duration
			want  string
		}{
			{fed, 9 * time.Hour, "the token type custom allows a validity of at most 8h"},
			{fed, 500 * time.Millisecond, "at least 1s"},
			{&Federation{TypeName: "x", Issuer: "https://ca.example.com", Subject: "web"}, 0, "at least 1s"},
		} {
			if _, _, _, err := IssueJWT(root.key, c.fed, c.valid, time.Time{}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("IssueJWT valid for %v: %v, want an error with %q", c.valid, err, c.want)
			}
		}
	}
}

func TestCAJWKS(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	for _, keyType := range []string{"rsa", "ec"} {
		root := newRoot(t, keyType)
		issuing := newIssuing(t, root, "servers", keyType)
		b, err := CAJWKS(issuing.dir)
		if err != nil {
			t.Fatal(err)
		}
		var set struct {
			Keys []jose.JWK `json:"keys"`
		}
		if err := json.Unmarshal(b, &set); err != nil || len(set.Keys) != 1 {
			t.Fatalf("JWKS %s: %v, want one key", b, err)
		}
		k := set.Keys[0]
		var members map[string]string
		switch pub := issuing.key.Public().(type) {
		case *rsa.PublicKey:
			if k.Kty != "RSA" || k.Alg != "RS256" || k.N != b64(pub.N.Bytes()) || k.E != b64(big.NewInt(int64(pub.E)).Bytes()) ||
				k.Crv != "" || k.X != "" {
				t.Errorf("JWK of an RSA key %+v", k)
			}
			members = map[string]string{"e": k.E, "kty": "RSA", "n": k.N}
		case *ecdsa.PublicKey:
			raw, err := pub.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if k.Kty != "EC" || k.Alg != "ES256" || k.Crv != "P-256" || k.X != b64(raw[1:33]) || k.Y != b64(raw[33:]) || k.N != "" {
				t.Errorf("JWK of an EC key %+v", k)
			}
			members = map[string]string{"crv": "P-256", "kty": "EC", "x": k.X, "y": k.Y}
		}

		// The key ID is the JWK thumbprint of RFC 7638.
		canonical, err := json.Marshal(members)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(canonical); k.Use != "sig" || k.Kid != b64(sum[:]) {
			t.Errorf("JWK use %q, kid %q, want sig and the thumbprint of %s", k.Use, k.Kid, canonical)
		}
		if rootJWKS, _ := CAJWKS(root.dir); string(rootJWKS) == string(b) {
			t.Error("the JWKS of the issuing CA is that of the root CA")
		}
	}
	if _, err := CAJWKS(t.TempDir()); err == nil {
		t.Error("CAJWKS without ca_cert.pem succeeded, want an error")
	}
}

func TestFederateAudit(t *testing.T) {
	if got := FederateAudit(nil); got != nil {
		t.Errorf("FederateAudit(nil) = %v, want none", got)
	}
	got := FederateAudit(&TokenFederate{Type: "google", Audience: "//iam.googleapis.com/x"})
	if !slices.Equal(got, []any{"federate", "google", "audience", "//iam.googleapis.com/x"}) {
		t.Errorf("FederateAudit = %v", got)
	}
}
