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

package oidc

import (
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestOIDCResolved(t *testing.T) {
	const path = "simple-ca.json"
	if c, on, err := Resolved(simpleca.OIDCConfig{ClientID: "x"}, path); err != nil || on || c.Provider != "" {
		t.Errorf("Resolved without an issuer: %+v, %v, %v, want it off", c, on, err)
	}
	for _, c := range []struct {
		in                  simpleca.OIDCConfig
		label               string
		scopes              []string
		user, groups, roles simpleca.ClaimPaths
	}{
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "simple-ca"}, "OIDC",
			[]string{"openid", "profile", "email"}, simpleca.ClaimPaths{"sub"}, simpleca.ClaimPaths{"groups"}, simpleca.ClaimPaths{"roles"}},
		{simpleca.OIDCConfig{Provider: "keycloak", Issuer: "http://idp.example.com/realms/lab", ClientID: "simple-ca"}, "Keycloak",
			[]string{"openid", "profile", "email"}, simpleca.ClaimPaths{"preferred_username"}, simpleca.ClaimPaths{"groups"},
			simpleca.ClaimPaths{"realm_access.roles", "resource_access.CLIENT_ID.roles"}},
		{simpleca.OIDCConfig{Provider: "entra", Issuer: "https://login.example.com/tenant/v2.0", ClientID: "simple-ca",
			Scopes: []string{"email"}}, "Entra ID",
			[]string{"openid", "email"}, simpleca.ClaimPaths{"preferred_username"}, simpleca.ClaimPaths{"groups"}, simpleca.ClaimPaths{"roles"}},
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "simple-ca", Scopes: []string{"profile", "openid"},
			Label: "Lab", UserClaim: simpleca.ClaimPaths{"email"}, GroupsClaim: simpleca.ClaimPaths{"teams"}, RolesClaim: simpleca.ClaimPaths{"app.roles"}},
			"Lab", []string{"profile", "openid"}, simpleca.ClaimPaths{"email"}, simpleca.ClaimPaths{"teams"}, simpleca.ClaimPaths{"app.roles"}},
	} {
		got, on, err := Resolved(c.in, path)
		if err != nil || !on || got.Label != c.label || !slices.Equal(got.Scopes, c.scopes) ||
			!slices.Equal(got.UserClaim, c.user) || !slices.Equal(got.GroupsClaim, c.groups) ||
			!slices.Equal(got.RolesClaim, c.roles) {
			t.Errorf("Resolved of %+v: %+v, %v, %v", c.in, got, on, err)
		}
	}
	// The email and name claims of each provider, and the scopes of the client of request-cert.
	got, _, err := Resolved(simpleca.OIDCConfig{Provider: "entra", Issuer: "https://idp.example.com", ClientID: "simple-ca",
		CLIClientID: "simple-ca-cli"}, path)
	if err != nil || !slices.Equal(got.EmailClaim, simpleca.ClaimPaths{"email", "preferred_username"}) ||
		!slices.Equal(got.NameClaim, simpleca.ClaimPaths{"name"}) || !slices.Equal(got.CLIScopes, []string{"openid", "profile", "email"}) {
		t.Errorf("Resolved of Entra ID with a CLI client: %+v, %v", got, err)
	}
	got, _, err = Resolved(simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "simple-ca", CLIClientID: "cli",
		CLIScopes: []string{"email"}, EmailClaim: simpleca.ClaimPaths{"mail"}}, path)
	if err != nil || !slices.Equal(got.EmailClaim, simpleca.ClaimPaths{"mail"}) || !slices.Equal(got.CLIScopes, []string{"openid", "email"}) {
		t.Errorf("Resolved with CLI scopes and an email claim: %+v, %v", got, err)
	}
	if got, _, _ := Resolved(simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "simple-ca"}, path); got.CLIScopes != nil {
		t.Errorf("Resolved without a CLI client: CLI scopes %v, want none", got.CLIScopes)
	}
	for _, c := range []struct {
		in   simpleca.OIDCConfig
		want string
	}{
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "x", CLIClientID: "x"}, "oidc.cli_client_id"},
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com", ClientID: "x", CLIScopes: []string{"openid"}}, "oidc.cli_scopes"},
		{simpleca.OIDCConfig{Provider: "other", Issuer: "https://idp.example.com", ClientID: "x"}, "must be one of entra, generic, keycloak"},
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com"}, "oidc.client_id"},
		{simpleca.OIDCConfig{Issuer: "idp.example.com", ClientID: "x"}, "not an http or https URL"},
		{simpleca.OIDCConfig{Issuer: "https://idp.example.com/realms/lab#x", ClientID: "x"}, "has a fragment"},
	} {
		if _, on, err := Resolved(c.in, path); err == nil || on || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), path) {
			t.Errorf("Resolved of %+v: %v, want an error with %q", c.in, err, c.want)
		}
	}
}
