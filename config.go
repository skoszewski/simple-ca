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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// ---- configuration ----------------------------------------------------------

const (
	configFile = "simple-ca.yaml"
)

// daysConfig holds the default validity periods in days.
type daysConfig struct {
	CA   int `yaml:"ca,omitempty"`
	Cert int `yaml:"cert,omitempty"`
	CRL  int `yaml:"crl,omitempty"`
}

// typeConfig is a certificate type of simple-ca.yaml; a field left out keeps the value of the
// built-in type of the same name.
type typeConfig struct {
	Names       string    `yaml:"names,omitempty"`
	KeyUsage    *[]string `yaml:"key_usage,omitempty"`
	ExtKeyUsage *[]string `yaml:"ext_key_usage,omitempty"`
}

// config is the simple-ca.yaml file of a root CA directory, the settings of the root CA and its
// issuing CAs.
type config struct {
	path             string
	CAPublishBaseURL string                `yaml:"ca_publish_base_url,omitempty"`
	Days             daysConfig            `yaml:"days,omitempty"`
	Types            map[string]typeConfig `yaml:"types,omitempty"`
}

// loadConfig reads simple-ca.yaml of caDir, or returns an empty config when the file does not exist.
func loadConfig(caDir string) (*config, error) {
	cfg := &config{path: filepath.Join(caDir, configFile)}
	b, err := os.ReadFile(cfg.path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", cfg.path, err)
	}
	return cfg, nil
}

// save writes the config back to the file it was loaded from, indented by two spaces.
func (c *config) save() error {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return os.WriteFile(c.path, b.Bytes(), 0o644)
}
