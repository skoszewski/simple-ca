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
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// ---- configuration ----------------------------------------------------------

// oidcUsersFile is the file of the root CA directory holding an oidcUsers.
const oidcUsersFile = "oidc-users.json"

// oidcUsers are the token profiles of the OIDC sign-in and the rules giving them to users.
type oidcUsers struct {
	path     string
	Profiles []oidcProfile `json:"profiles"`
	Rules    []oidcRule    `json:"rules"`
}

// oidcProfile is a token profile: its name, its CA, empty for the root CA, and its token settings.
type oidcProfile struct {
	Name  string       `json:"name"`
	CA    string       `json:"ca"`
	Token profileToken `json:"token"`
}

// profileToken is the token of a profile: the settings of simpleca.TokensConfig, and localhost, which a
// profile gives its tokens itself, as token create --localhost does, and is never a default.
type profileToken struct {
	simpleca.TokensConfig
	Localhost bool `json:"localhost,omitempty"`
}

// oidcRule gives the profile Profile to the users of Users and to the members of Groups.
type oidcRule struct {
	Users   []string `json:"users,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Profile string   `json:"profile"`
}

// loadOIDCUsers reads and validates oidc-users.json of rootDir, empty when it does not exist.
func loadOIDCUsers(rootDir string) (*oidcUsers, error) {
	users := &oidcUsers{path: filepath.Join(rootDir, oidcUsersFile)}
	b, err := os.ReadFile(users.path)
	if errors.Is(err, os.ErrNotExist) {
		return users, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(users); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", users.path, err)
	}
	var names []string
	for i, p := range users.Profiles {
		switch {
		case !simpleca.KebabCaseRE.MatchString(p.Name):
			return nil, fmt.Errorf("profiles[%d] of %s: name '%s' is not a kebab-case name, such as ca-admin", i, users.path, p.Name)
		case slices.Contains(names, p.Name):
			return nil, fmt.Errorf("profiles[%d] of %s: the profile '%s' is given twice", i, users.path, p.Name)
		case p.Token.KeepExpired != "":
			return nil, fmt.Errorf("profile %s of %s: keep_expired belongs to the tokens section of simple-ca.json", p.Name, users.path)
		}
		names = append(names, p.Name)
	}
	for i, r := range users.Rules {
		switch {
		case len(r.Users) == 0 && len(r.Groups) == 0:
			return nil, fmt.Errorf("rules[%d] of %s: a rule needs users or groups", i, users.path)
		case !slices.Contains(names, r.Profile):
			return nil, fmt.Errorf("rules[%d] of %s: unknown profile '%s'", i, users.path, r.Profile)
		}
	}
	return users, nil
}

// themeFile is the file of a CA directory, root or issuing CA, holding the colours of the pages
// of serve about that CA, a themeConfig.
const themeFile = "theme.json"

// themeConfig holds the colours of the pages of serve in place of the built-in ones, for the
// light and the dark theme, each by its role, a name of themeRoles, and a CSS colour.
type themeConfig struct {
	Light map[string]string `json:"light,omitempty"`
	Dark  map[string]string `json:"dark,omitempty"`
}

// loadTheme reads theme.json of caDir, refusing unknown settings, a role it does not know and a
// value that is not a colour, and returns its colours, none when the file does not exist.
func loadTheme(caDir string) (themeConfig, error) {
	var theme themeConfig
	path := filepath.Join(caDir, themeFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return theme, nil
	}
	if err != nil {
		return theme, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&theme); err != nil {
		return themeConfig{}, fmt.Errorf("could not read %s: %w", path, err)
	}
	if _, err := theme.css(path); err != nil {
		return themeConfig{}, err
	}
	return theme, nil
}

// themeRoles are the roles of the colours of the pages, as templates/theme.html names them.
var themeRoles = []string{"page", "ink", "muted", "card", "line", "head", "head-ink", "head-muted",
	"head-link", "link", "accent", "accent-line", "accent-title", "accent-ink", "action", "action-hover",
	"action-ink", "solid", "solid-hover", "solid-ink", "subtle", "subtle-ink", "field", "field-line",
	"good", "good-ink", "warn", "warn-line", "warn-ink", "bad", "bad-line", "bad-ink"}

// themeColorRE matches a CSS colour of the theme: #RGB, #RGBA, #RRGGBB or #RRGGBBAA, a colour
// function such as rgb(), hsl() or oklch() of numbers, or a colour name.
var themeColorRE = regexp.MustCompile(`^(#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})|` +
	`(rgba?|hsla?|oklch|oklab|lch|lab)\([0-9a-zA-Z .,%/+-]*\)|[a-zA-Z]+)$`)

// css returns the colours of the theme as the CSS of the pages, which sets the variables of their
// roles for the light and the dark theme, or an error naming a role or a colour it does not know.
func (t themeConfig) css(path string) (template.CSS, error) {
	var b strings.Builder
	for _, set := range []struct {
		name, selector string
		colors         map[string]string
	}{{"light", ":root", t.Light}, {"dark", `:root[data-theme="dark"]`, t.Dark}} {
		if len(set.colors) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s {", set.selector)
		for _, role := range slices.Sorted(maps.Keys(set.colors)) {
			color := strings.TrimSpace(set.colors[role])
			switch {
			case !slices.Contains(themeRoles, role):
				return "", fmt.Errorf("%s of %s: unknown role '%s': must be one of %s", set.name, path, role,
					strings.Join(themeRoles, ", "))
			case !themeColorRE.MatchString(color):
				return "", fmt.Errorf("%s.%s of %s: '%s' is not a CSS colour such as #0369a1", set.name, role, path, color)
			}
			fmt.Fprintf(&b, " --%s: %s;", role, color)
		}
		b.WriteString(" }\n")
	}
	return template.CSS(b.String()), nil
}
