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
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadConfigWithoutFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(dir)
	if err != nil || cfg.Path != filepath.Join(dir, ConfigFile) || cfg.CAPublishBaseURL != "" || cfg.Types != nil {
		t.Fatalf("LoadConfig without %s: %+v, %v, want an empty config of that path", ConfigFile, cfg, err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(cfg.Path); err != nil || string(b) != "{}\n" {
		t.Fatalf("an empty config saved: %q, %v, want {}", b, err)
	}
}

func TestLoadConfigRefusesUnknownSettings(t *testing.T) {
	dir := t.TempDir()
	for _, settings := range []string{
		`{"types": {"device": {"key_usages": ["digitalSignature"]}}}`,
		`{"ca_url": "http://pki.example.com"}`,
		"types:\n  device:\n    key_usage: [digitalSignature]\n",
	} {
		writeConfig(t, dir, settings)
		if _, err := LoadConfig(dir); err == nil || !strings.Contains(err.Error(), filepath.Join(dir, ConfigFile)) {
			t.Errorf("LoadConfig of %q: %v, want an error naming the file", settings, err)
		}
	}
}

func TestConfigSave(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"ca_publish_base_url": "http://pki.example.com", "types": {`+
		`"device": {"key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]}, `+
		`"person": {"names": "user", "key_usage": ["digitalSignature", "keyEncipherment"], "ext_key_usage": []}, `+
		`"user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}}}`)
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg.Path)
	if err != nil || !strings.HasPrefix(string(b), "{\n  \"ca_publish_base_url\"") || !strings.HasSuffix(string(b), "}\n") {
		t.Fatalf("saved %s: %v\n%s\nwant JSON indented by two spaces and a line end", ConfigFile, err, b)
	}
	saved, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig after Save: %v", err)
	}
	if saved.CAPublishBaseURL != "http://pki.example.com" || saved.Types["device"].Names != "" ||
		!slices.Equal(*saved.Types["device"].ExtKeyUsage, []string{"clientAuth", "1.3.6.1.4.1.99999.10"}) {
		t.Fatalf("saved config %+v, want the settings read", saved)
	}
	if p := saved.Types["person"].ExtKeyUsage; p == nil || len(*p) != 0 {
		t.Fatalf("the empty ext_key_usage of person did not survive a save: %v", p)
	}
	if saved.Types["user"].ExtKeyUsage != nil {
		t.Fatal("the ext_key_usage left out of user was written by a save")
	}
}

func TestLoadConfigURLs(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"ca_publish_base_url": "http://pki.example.com:8080", "federation": {"issuer": "https://pki.example.com/"}}`)
	if _, err := LoadConfig(dir); err != nil {
		t.Errorf("server URLs: %v", err)
	}
	for config, want := range map[string]string{
		`{"ca_publish_base_url": "http://pki.example.com/pki"}`:         "ca_publish_base_url of",
		`{"ca_publish_base_url": "pki.example.com"}`:                    "ca_publish_base_url of",
		`{"federation": {"issuer": "https://pki.example.com/gcp-wif"}}`: "federation.issuer of",
		`{"federation": {"issuer": "http://pki.example.com"}}`:          "not an https URL",
	} {
		writeConfig(t, dir, config)
		if _, err := LoadConfig(dir); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LoadConfig of %s: %v, want %q", config, err, want)
		}
	}
}

func TestIssuingCAExists(t *testing.T) {
	root := newRoot(t, "ec")
	newIssuing(t, root, "servers", "ec")
	for name, want := range map[string]bool{"servers": true, "users": false, "../servers": false, "": false} {
		if got := IssuingCAExists(root.dir, name); got != want {
			t.Errorf("IssuingCAExists(%q) = %v", name, got)
		}
	}
	for raw, want := range map[string]string{"https://pki.example.com": "", "https://pki.example.com/servers/": "servers"} {
		if ca, err := CheckCAURL(root.dir, raw); err != nil || ca != want {
			t.Errorf("CheckCAURL(%q) = %q, %v", raw, ca, err)
		}
	}
	if _, err := CheckCAURL(root.dir, "https://pki.example.com/users"); err == nil || !strings.Contains(err.Error(), "does not have") {
		t.Errorf("CheckCAURL of a missing issuing CA: %v", err)
	}
}

func TestLoadRootConfig(t *testing.T) {
	root := newRoot(t, "ec")
	issuing := newIssuing(t, root, "servers", "ec")
	writeConfig(t, root.dir, `{"ca_publish_base_url": "http://pki.example.com"}`)
	for _, dir := range []string{root.dir, issuing.dir} {
		cfg, err := LoadRootConfig(dir)
		if err != nil || cfg.CAPublishBaseURL != "http://pki.example.com" || cfg.Path != filepath.Join(root.dir, ConfigFile) {
			t.Errorf("LoadRootConfig(%s): %+v, %v, want the settings of the root CA", dir, cfg, err)
		}
	}
	if _, err := LoadRootConfig(t.TempDir()); err == nil {
		t.Error("LoadRootConfig outside a CA succeeded, want an error")
	}
}

func TestContextValues(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetContextValues("", map[string][]string{"otc_valid": {"1h"}})
	cfg.SetContextValues("servers", map[string][]string{"domain": {"a.example", "c.example"}})
	cfg.SetContextValues("clients", map[string][]string{"days": {"30"}})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg.Path)
	if err != nil || !strings.Contains(string(b), `"otc_valid"`) || !strings.Contains(string(b), `"cas"`) {
		t.Fatalf("%s: %v\n%s\nwant the values of the root CA and those under cas", ConfigFile, err, b)
	}
	if cfg, err = LoadConfig(dir); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ContextValues(""); !slices.Equal(got["otc_valid"], []string{"1h"}) || len(got) != 1 {
		t.Errorf("values of the root CA = %v", got)
	}
	if got := cfg.ContextValues("servers"); !slices.Equal(got["domain"], []string{"a.example", "c.example"}) || len(got) != 1 {
		t.Errorf("values of servers = %v", got)
	}
	if got := cfg.ContextValues("nosuch"); got != nil {
		t.Errorf("values of an issuing CA without any = %v, want nil", got)
	}

	// Empty values remove the entry of the CA.
	cfg.SetContextValues("servers", map[string][]string{})
	cfg.SetContextValues("clients", nil)
	cfg.SetContextValues("", map[string][]string{})
	if cfg.Context.CAs != nil || cfg.Context.Values != nil {
		t.Errorf("context after removing the values: %+v, want none", cfg.Context)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(cfg.Path); err != nil || strings.Contains(string(b), `"context"`) {
		t.Errorf("%s without values: %v\n%s\nwant no context", ConfigFile, err, b)
	}
}

func TestClaimPaths(t *testing.T) {
	var c OIDCConfig
	if err := json.Unmarshal([]byte(`{"user_claim": "email", "groups_claim": ["a.b", "c"]}`), &c); err != nil ||
		!slices.Equal(c.UserClaim, ClaimPaths{"email"}) || !slices.Equal(c.GroupsClaim, ClaimPaths{"a.b", "c"}) {
		t.Errorf("claims of one path and of a list: %+v, %v", c, err)
	}
	if err := json.Unmarshal([]byte(`{"roles_claim": 5}`), &c); err == nil || !strings.Contains(err.Error(), "dotted path") {
		t.Errorf("a claim of a number: %v, want an error", err)
	}
}
