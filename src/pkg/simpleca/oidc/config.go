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
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// oidcProviders are the label and claim defaults of each provider.
var oidcProviders = map[string]struct {
	label               string
	user, groups, roles simpleca.ClaimPaths
}{
	"generic":  {"OIDC", simpleca.ClaimPaths{"sub"}, simpleca.ClaimPaths{"groups"}, simpleca.ClaimPaths{"roles"}},
	"keycloak": {"Keycloak", simpleca.ClaimPaths{"preferred_username"}, simpleca.ClaimPaths{"groups"}, simpleca.ClaimPaths{"realm_access.roles", "resource_access.CLIENT_ID.roles"}},
	"entra":    {"Entra ID", simpleca.ClaimPaths{"preferred_username"}, simpleca.ClaimPaths{"groups"}, simpleca.ClaimPaths{"roles"}},
}

// Resolved returns c validated, with the defaults of its provider, and false when it is off.
func Resolved(c simpleca.OIDCConfig, path string) (simpleca.OIDCConfig, bool, error) {
	if c.Issuer == "" {
		return c, false, nil
	}
	if c.Provider == "" {
		c.Provider = "generic"
	}
	preset, ok := oidcProviders[c.Provider]
	switch {
	case !ok:
		return c, false, fmt.Errorf("oidc.provider of %s: unknown provider '%s': must be one of %s", path, c.Provider,
			strings.Join(slices.Sorted(maps.Keys(oidcProviders)), ", "))
	case !strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://"):
		return c, false, fmt.Errorf("oidc.issuer of %s: '%s' is not an HTTP or HTTPS URL", path, c.Issuer)
	case c.ClientID == "":
		return c, false, fmt.Errorf("oidc.client_id of %s is required with oidc.issuer", path)
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	if !slices.Contains(c.Scopes, "openid") {
		c.Scopes = append([]string{"openid"}, c.Scopes...)
	}
	if c.Label == "" {
		c.Label = preset.label
	}
	if len(c.UserClaim) == 0 {
		c.UserClaim = preset.user
	}
	if len(c.GroupsClaim) == 0 {
		c.GroupsClaim = preset.groups
	}
	if len(c.RolesClaim) == 0 {
		c.RolesClaim = preset.roles
	}
	return c, true, nil
}
