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
// certificates in days.
type acmeConfig struct {
	Domains []string `json:"domains,omitempty"`
	Days    int      `json:"days,omitempty"`
}

// serveConfig holds the settings of serve: the addresses and prefixes of the proxies whose
// X-Forwarded-For header names the client of a request.
type serveConfig struct {
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
}

// tokensConfig holds the defaults of token create, each replaced by the option of the same name:
// the validity, a duration such as 8h, the scopes, the certificate types, the domains, the IP
// addresses, localhost, and the client addresses and prefixes; and how long serve keeps an expired
// token, a duration, kept until token purge without it.
type tokensConfig struct {
	Valid       string   `json:"valid,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Types       []string `json:"types,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Localhost   bool     `json:"localhost,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	KeepExpired string   `json:"keep_expired,omitempty"`
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

// loadTheme reads theme.json of caDir, refusing unknown settings, and returns its colours as the
// CSS of the pages, empty when the file does not exist.
func loadTheme(caDir string) (template.CSS, error) {
	path := filepath.Join(caDir, themeFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var theme themeConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&theme); err != nil {
		return "", fmt.Errorf("could not read %s: %w", path, err)
	}
	return theme.css(path)
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
		b.WriteString(set.selector + " {")
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
	ACME             acmeConfig            `json:"acme,omitzero"`
	Serve            serveConfig           `json:"serve,omitzero"`
	Tokens           tokensConfig          `json:"tokens,omitzero"`
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
