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

package simpleca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	ConfigFile = "simple-ca.json"
)

// DaysConfig holds the default validity periods in days.
type DaysConfig struct {
	CA   int `json:"ca,omitempty"`
	Cert int `json:"cert,omitempty"`
	CRL  int `json:"crl,omitempty"`
}

// TypeConfig is a certificate type of simple-ca.json; a field left out keeps the value of the
// built-in type of the same name.
type TypeConfig struct {
	Names       string    `json:"names,omitempty"`
	KeyUsage    *[]string `json:"key_usage,omitempty"`
	ExtKeyUsage *[]string `json:"ext_key_usage,omitempty"`
}

// ACMEConfig holds the ACME settings of serve: the domains whose names, and the names below them,
// the ACME server issues certificates for, ACME being off without them, and the validity of its
// certificates in days; and its limits: the accounts of a CA, the open orders and the contacts of
// an account, the names of an order, and the unused nonces of the server.
type ACMEConfig struct {
	Domains     []string `json:"domains,omitempty"`
	Days        int      `json:"days,omitempty"`
	MaxAccounts int      `json:"max_accounts,omitempty"`
	MaxOrders   int      `json:"max_orders,omitempty"`
	MaxNames    int      `json:"max_names,omitempty"`
	MaxContacts int      `json:"max_contacts,omitempty"`
	MaxNonces   int      `json:"max_nonces,omitempty"`
}

// Limits returns the settings with the default of each limit that is not set.
func (c ACMEConfig) Limits() ACMEConfig {
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

// ServeConfig holds the settings of serve: the addresses and prefixes of the proxies whose
// X-Forwarded-For header names the client of a request, and whether each request is logged.
type ServeConfig struct {
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	RequestLog     bool     `json:"request_log,omitempty"`
}

// TokenTypeConfig is a token type of simple-ca.json: the built-in type a new type starts from,
// and the audience, the subject template, the validity, the longest validity and the claims of its
// JWTs; a field left out keeps the value of the built-in type.
type TokenTypeConfig struct {
	Base     string            `json:"base,omitempty"`
	Audience string            `json:"audience,omitempty"`
	Subject  string            `json:"subject,omitempty"`
	Valid    string            `json:"valid,omitempty"`
	MaxValid string            `json:"max_valid,omitempty"`
	Claims   map[string]string `json:"claims,omitempty"`
}

// FederationConfig holds the settings of the JWTs for workload identity federation: their issuer
// for the root CA, followed by /NAME for the issuing CA NAME, and the token types by name.
type FederationConfig struct {
	Issuer string                     `json:"issuer,omitempty"`
	Types  map[string]TokenTypeConfig `json:"types,omitempty"`
}

// TokensConfig holds the defaults of token create, each replaced by the option of the same name:
// the validity, a duration such as 8h, the scopes, the certificate types, the domains, the IP
// addresses, and the client addresses and prefixes; and how long serve keeps an expired token, a
// duration, kept until token purge without it.
type TokensConfig struct {
	Valid       string   `json:"valid,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Types       []string `json:"types,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	KeepExpired string   `json:"keep_expired,omitempty"`
}

// AuditConfig holds the audit log settings: the path of the file, relative to the root CA
// directory, AuditFile by default.
type AuditConfig struct {
	File string `json:"file,omitempty"`
}

// OIDCConfig is the oidc section of simple-ca.json, the OIDC sign-in of serve, off without an
// issuer.
type OIDCConfig struct {
	Provider    string     `json:"provider,omitempty"`
	Issuer      string     `json:"issuer,omitempty"`
	ClientID    string     `json:"client_id,omitempty"`
	Scopes      []string   `json:"scopes,omitempty"`
	Label       string     `json:"label,omitempty"`
	UserClaim   ClaimPaths `json:"user_claim,omitempty"`
	GroupsClaim ClaimPaths `json:"groups_claim,omitempty"`
	RolesClaim  ClaimPaths `json:"roles_claim,omitempty"`
	ReuseToken  bool       `json:"reuse_token,omitempty"`
}

// ClaimPaths are the dotted paths of claims of an ID token, given as one string or a list.
type ClaimPaths []string

func (p *ClaimPaths) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*p = ClaimPaths{one}
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
	user, groups, roles ClaimPaths
}{
	"generic":  {"OIDC", ClaimPaths{"sub"}, ClaimPaths{"groups"}, ClaimPaths{"roles"}},
	"keycloak": {"Keycloak", ClaimPaths{"preferred_username"}, ClaimPaths{"groups"}, ClaimPaths{"realm_access.roles", "resource_access.CLIENT_ID.roles"}},
	"entra":    {"Entra ID", ClaimPaths{"preferred_username"}, ClaimPaths{"groups"}, ClaimPaths{"roles"}},
}

// Resolved returns c validated, with the defaults of its provider, and false when it is off.
func (c OIDCConfig) Resolved(path string) (OIDCConfig, bool, error) {
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

// ContextConfig is the context section of simple-ca.json: the option values of the commands of
// the root CA, by the snake_case name of the option, and those of each issuing CA under cas.
type ContextConfig struct {
	Values map[string][]string  `json:"values,omitempty"`
	CAs    map[string]ContextCA `json:"cas,omitempty"`
}

// ContextCA holds the option values of the commands of one issuing CA.
type ContextCA struct {
	Values map[string][]string `json:"values,omitempty"`
}

// ContextValues returns the option values of the CA caID, the root CA for "", and nil without
// any.
func (c *Config) ContextValues(caID string) map[string][]string {
	if caID == "" {
		return c.Context.Values
	}
	return c.Context.CAs[caID].Values
}

// SetContextValues replaces the option values of the CA caID, the root CA for "", removing its
// entry when values is empty.
func (c *Config) SetContextValues(caID string, values map[string][]string) {
	if len(values) == 0 {
		values = nil
	}
	if caID == "" {
		c.Context.Values = values
		return
	}
	if values == nil {
		delete(c.Context.CAs, caID)
		if len(c.Context.CAs) == 0 {
			c.Context.CAs = nil
		}
		return
	}
	if c.Context.CAs == nil {
		c.Context.CAs = map[string]ContextCA{}
	}
	c.Context.CAs[caID] = ContextCA{Values: values}
}

// Config is the simple-ca.json file of a root CA directory, the settings of the root CA and its
// issuing CAs.
type Config struct {
	Path             string                `json:"-"`
	CAPublishBaseURL string                `json:"ca_publish_base_url,omitempty"`
	Days             DaysConfig            `json:"days,omitzero"`
	Types            map[string]TypeConfig `json:"types,omitempty"`
	Federation       FederationConfig      `json:"federation,omitzero"`
	ACME             ACMEConfig            `json:"acme,omitzero"`
	Serve            ServeConfig           `json:"serve,omitzero"`
	Tokens           TokensConfig          `json:"tokens,omitzero"`
	OIDC             OIDCConfig            `json:"oidc,omitzero"`
	Audit            AuditConfig           `json:"audit,omitzero"`
	Context          ContextConfig         `json:"context,omitzero"`
}

// LoadConfig reads simple-ca.json of caDir, refusing unknown settings, or returns an empty config
// when the file does not exist.
func LoadConfig(caDir string) (*Config, error) {
	cfg := &Config{Path: filepath.Join(caDir, ConfigFile)}
	b, err := os.ReadFile(cfg.Path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", cfg.Path, err)
	}
	return cfg, nil
}

// Save writes the config back to the file it was loaded from, indented by two spaces.
func (c *Config) Save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.Path, append(b, '\n'), 0o644)
}

// LoadRootConfig loads simple-ca.json of the root CA of the CA in caDir.
func LoadRootConfig(caDir string) (*Config, error) {
	rootDir, _, err := LocateCA(caDir)
	if err != nil {
		return nil, err
	}
	return LoadConfig(rootDir)
}
