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

package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// writeFile writes data to name in dir and returns its path.
func writeFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadConfigKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fed.json", `{
		"ca_url": "https://pki.example.com",
		"token": "api-token",
		"provider": "provider",
		"service_account": "ca@project.iam.gserviceaccount.com",
		"google_scope": "google-scope",
		"tenant_id": "tenant",
		"client_id": "app-id",
		"scope": "entra-scope"
	}`)
	s, got, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Errorf("path %q, want %q", got, path)
	}
	want := Settings{CAURL: "https://pki.example.com", Token: "api-token", Provider: "provider",
		ServiceAccount: "ca@project.iam.gserviceaccount.com", GoogleScope: "google-scope",
		TenantID: "tenant", ClientID: "app-id", Scope: "entra-scope"}
	if s != want {
		t.Errorf("settings %+v, want %+v", s, want)
	}
}

func TestReadConfigTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "fed.json", `{"token_file": "secrets/token"}`)
	s, _, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "secrets", "token"); s.TokenFile != want {
		t.Errorf("relative token_file %q, want %q", s.TokenFile, want)
	}
	abs := filepath.Join(t.TempDir(), "token")
	b, _ := json.Marshal(map[string]string{"token_file": abs})
	path = writeFile(t, dir, "abs.json", string(b))
	if s, _, err = ReadConfig(path); err != nil {
		t.Fatal(err)
	}
	if s.TokenFile != abs {
		t.Errorf("absolute token_file %q, want %q", s.TokenFile, abs)
	}
}

func TestReadConfigRefused(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, data, message string }{
		{"unknown key", `{"ca_url": "https://pki.example.com", "url": "x"}`, `unknown field "url"`},
		{"camel case key", `{"caUrl": "https://pki.example.com"}`, `unknown field "caUrl"`},
		{"not JSON", `ca_url = x`, "could not read"},
		{"not an object", `["ca_url"]`, "could not read"},
		{"token and token_file", `{"token": "a", "token_file": "b"}`, "give token or token_file, not both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeFile(t, dir, "fed.json", tc.data)
			_, got, err := ReadConfig(path)
			if err == nil || !strings.Contains(err.Error(), tc.message) || !strings.Contains(err.Error(), path) {
				t.Errorf("error %v, want one with %q and the path", err, tc.message)
			}
			if got != "" {
				t.Errorf("path %q returned with an error", got)
			}
		})
	}
}

func TestReadConfigMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fed.json")
	s, got, err := ReadConfig(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v, want os.ErrNotExist", err)
	}
	if got != "" || s != (Settings{}) {
		t.Errorf("ReadConfig = %+v, %q with an error", s, got)
	}
}

func TestReadConfigDefault(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	s, got, err := ReadConfig("")
	if err != nil || got != "" || s != (Settings{}) {
		t.Errorf("without federation.json: ReadConfig = %+v, %q, %v, want nothing", s, got, err)
	}
	writeFile(t, dir, DefaultConfig, `{"ca_url": "https://pki.example.com", "token_file": "token"}`)
	s, got, err = ReadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if got != DefaultConfig {
		t.Errorf("path %q, want %q", got, DefaultConfig)
	}
	if s.CAURL != "https://pki.example.com" || s.TokenFile != "token" {
		t.Errorf("settings %+v", s)
	}
	writeFile(t, dir, DefaultConfig, `{"unknown": 1}`)
	if _, _, err = ReadConfig(""); err == nil {
		t.Error("an unknown key of federation.json is not refused")
	}
}

func TestSettingsOmitEmpty(t *testing.T) {
	b, err := json.Marshal(Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Errorf("empty settings %s, want {}", b)
	}
	b, err = json.Marshal(Settings{CAURL: "https://pki.example.com", Scope: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"ca_url":"https://pki.example.com","scope":"s"}`; string(b) != want {
		t.Errorf("settings %s, want %s", b, want)
	}
	s := Settings{
		CAURL:          "https://pki.example.com",
		TokenFile:      filepath.Join(t.TempDir(), "token"),
		Provider:       "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		ServiceAccount: "ca@project.iam.gserviceaccount.com",
		GoogleScope:    DefaultGoogleScope,
		TenantID:       "tenant",
		ClientID:       "app-id",
		Scope:          DefaultEntraScope,
	}
	b, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]string
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	want := []string{"ca_url", "client_id", "google_scope", "provider", "scope", "service_account",
		"tenant_id", "token_file"}
	var got []string
	for k := range keys {
		got = append(got, k)
	}
	if len(got) != len(want) {
		t.Errorf("keys %v, want %v", got, want)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Errorf("key %s missing from %s", k, b)
		}
	}
	path := writeFile(t, t.TempDir(), "fed.json", string(b))
	read, _, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, s) {
		t.Errorf("settings read back %+v, want %+v", read, s)
	}
}

// entries returns the names in dir.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

// checkFile checks the content of path, and its mode 0600 where Unix modes apply.
func checkFile(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Errorf("content %q, want %q", b, want)
	}
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode %o, want 600", mode)
	}
}

func TestReplaceFileNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.jwt")
	if err := ReplaceFile(path, "jwt"); err != nil {
		t.Fatal(err)
	}
	checkFile(t, path, "jwt")
	if names := entries(t, dir); !reflect.DeepEqual(names, []string{"token.jwt"}) {
		t.Errorf("directory holds %v, want the file alone", names)
	}
}

func TestReplaceFileExisting(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "token.jwt", "an older and longer token")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ReplaceFile(path, "new"); err != nil {
		t.Fatal(err)
	}
	checkFile(t, path, "new")
	if names := entries(t, dir); !reflect.DeepEqual(names, []string{"token.jwt"}) {
		t.Errorf("directory holds %v, want the file alone", names)
	}
}

func TestReplaceFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.jwt")
	if err := ReplaceFile(path, ""); err != nil {
		t.Fatal(err)
	}
	checkFile(t, path, "")
}

func TestReplaceFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := ReplaceFile(filepath.Join(dir, "missing", "token.jwt"), "jwt"); err == nil {
		t.Error("a missing directory is not an error")
	}
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(filepath.Join(target, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(target, "jwt"); err == nil {
		t.Error("a directory holding files is replaced")
	}
	if names := entries(t, dir); !reflect.DeepEqual(names, []string{"target"}) {
		t.Errorf("directory holds %v, want the target alone and no temporary file", names)
	}
}
