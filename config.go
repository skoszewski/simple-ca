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
	"os"
	"path/filepath"
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
// the validity, a duration such as 8h, the certificate types, the domains, the IP addresses,
// localhost, and the client addresses and prefixes; and how long serve keeps an expired token, a
// duration, kept until token purge without it.
type tokensConfig struct {
	Valid       string   `json:"valid,omitempty"`
	Types       []string `json:"types,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Localhost   bool     `json:"localhost,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	KeepExpired string   `json:"keep_expired,omitempty"`
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
