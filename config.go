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
)

// ---- configuration ----------------------------------------------------------

const (
	configFile = "simple-ca.json"
)

// daysConfig holds the default validity periods in days.
type daysConfig struct {
	CA   int `json:"ca,omitempty"`
	Cert int `json:"cert,omitempty"`
	CRL  int `json:"crl,omitempty"`
}

// typeConfig is a certificate type of simple-ca.json; a field left out keeps the value of the
// built-in type of the same name.
type typeConfig struct {
	Names       string    `json:"names,omitempty"`
	KeyUsage    *[]string `json:"key_usage,omitempty"`
	ExtKeyUsage *[]string `json:"ext_key_usage,omitempty"`
}

// acmeConfig holds the ACME settings of serve: the domains whose names, and the names below them,
// the ACME server issues certificates for, ACME being off without them, and the validity of its
// certificates in days; and its limits: the accounts of a CA, the open orders and the contacts of
// an account, the names of an order, and the unused nonces of the server.
type acmeConfig struct {
	Domains     []string `json:"domains,omitempty"`
	Days        int      `json:"days,omitempty"`
	MaxAccounts int      `json:"max_accounts,omitempty"`
	MaxOrders   int      `json:"max_orders,omitempty"`
	MaxNames    int      `json:"max_names,omitempty"`
	MaxContacts int      `json:"max_contacts,omitempty"`
	MaxNonces   int      `json:"max_nonces,omitempty"`
}

// limits returns the settings with the default of each limit that is not set.
func (c acmeConfig) limits() acmeConfig {
	set := func(limit *int, byDefault int) {
		if *limit < 1 {
			*limit = byDefault
		}
	}
	set(&c.MaxAccounts, 1000)
	set(&c.MaxOrders, 50)
	set(&c.MaxNames, 100)
	set(&c.MaxContacts, 10)
	set(&c.MaxNonces, 100000)
	return c
}

// serveConfig holds the settings of serve: the addresses and prefixes of the proxies whose
// X-Forwarded-For header names the client of a request, and whether each request is logged.
type serveConfig struct {
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	RequestLog     bool     `json:"request_log,omitempty"`
}

// tokenTypeConfig is a token type of simple-ca.json: the built-in type a new type starts from,
// and the audience, the subject template, the validity, the longest validity and the claims of its
// JWTs; a field left out keeps the value of the built-in type.
type tokenTypeConfig struct {
	Base     string            `json:"base,omitempty"`
	Audience string            `json:"audience,omitempty"`
	Subject  string            `json:"subject,omitempty"`
	Valid    string            `json:"valid,omitempty"`
	MaxValid string            `json:"max_valid,omitempty"`
	Claims   map[string]string `json:"claims,omitempty"`
}

// federationConfig holds the settings of the JWTs for workload identity federation: their issuer
// for the root CA, followed by /NAME for the issuing CA NAME, and the token types by name.
type federationConfig struct {
	Issuer string                     `json:"issuer,omitempty"`
	Types  map[string]tokenTypeConfig `json:"types,omitempty"`
}

// tokensConfig holds the defaults of token create, each replaced by the option of the same name:
// the validity, a duration such as 8h, the scopes, the certificate types, the domains, the IP
// addresses, and the client addresses and prefixes; and how long serve keeps an expired token, a
// duration, kept until token purge without it.
type tokensConfig struct {
	Valid       string   `json:"valid,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Types       []string `json:"types,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	KeepExpired string   `json:"keep_expired,omitempty"`
}

// auditConfig holds the audit log settings: the path of the file, relative to the root CA
// directory, auditFile by default.
type auditConfig struct {
	File string `json:"file,omitempty"`
}

// oidcConfig is the oidc section of simple-ca.json, the OIDC sign-in of serve, off without an
// issuer.
type oidcConfig struct {
	Provider    string     `json:"provider,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	ClientID    string     `json:"client_id,omitempty"`
	Scopes      []string   `json:"scopes,omitempty"`
	Label       string     `json:"label,omitempty"`
	UserClaim   claimPaths `json:"user_claim,omitempty"`
	GroupsClaim claimPaths `json:"groups_claim,omitempty"`
	RolesClaim  claimPaths `json:"roles_claim,omitempty"`
	ReuseToken  bool       `json:"reuse_token,omitempty"`
}

// claimPaths are the dotted paths of claims of an ID token, given as one string or a list.
type claimPaths []string

func (p *claimPaths) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*p = claimPaths{one}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return errors.New("a claim must be a dotted path or a list of them")
	}
	*p = list
	return nil
}

// oidcProviders are the label and claim defaults of each provider.
var oidcProviders = map[string]struct {
	label               string
	user, groups, roles claimPaths
}{
	"generic":  {"OIDC", claimPaths{"sub"}, claimPaths{"groups"}, claimPaths{"roles"}},
	"keycloak": {"Keycloak", claimPaths{"preferred_username"}, claimPaths{"groups"}, claimPaths{"realm_access.roles", "resource_access.CLIENT_ID.roles"}},
	"entra":    {"Entra ID", claimPaths{"preferred_username"}, claimPaths{"groups"}, claimPaths{"roles"}},
}

// resolved returns c validated, with the defaults of its provider, and false when it is off.
func (c oidcConfig) resolved(path string) (oidcConfig, bool, error) {
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

// profileToken is the token of a profile: the settings of tokensConfig, and localhost, which a
// profile gives its tokens itself, as token create --localhost does, and is never a default.
type profileToken struct {
	tokensConfig
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
		case !kebabCaseRE.MatchString(p.Name):
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

// config is the simple-ca.json file of a root CA directory, the settings of the root CA and its
// issuing CAs.
type config struct {
	path             string
	CAPublishBaseURL string                `json:"ca_publish_base_url,omitempty"`
	Days             daysConfig            `json:"days,omitzero"`
	Types            map[string]typeConfig `json:"types,omitempty"`
	Federation       federationConfig      `json:"federation,omitzero"`
	ACME             acmeConfig            `json:"acme,omitzero"`
	Serve            serveConfig           `json:"serve,omitzero"`
	Tokens           tokensConfig          `json:"tokens,omitzero"`
	OIDC             oidcConfig            `json:"oidc,omitzero"`
	Audit            auditConfig           `json:"audit,omitzero"`
}

// loadConfig reads simple-ca.json of caDir, refusing unknown settings, or returns an empty config
// when the file does not exist.
func loadConfig(caDir string) (*config, error) {
	cfg := &config{path: filepath.Join(caDir, configFile)}
	b, err := os.ReadFile(cfg.path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", cfg.path, err)
	}
	return cfg, nil
}

// save writes the config back to the file it was loaded from, indented by two spaces.
func (c *config) save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(b, '\n'), 0o644)
}
