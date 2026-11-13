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
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// runWith runs request-cert with args, a new command line and the token token, and returns its
// error.
func runWith(t *testing.T, token string, args ...string) error {
	t.Helper()
	t.Setenv("SIMPLE_CA_TOKEN", token)
	t.Setenv("SIMPLE_CA_TOKEN_FILE", "")
	t.Setenv("SIMPLE_CA_TYPE", "")
	t.Setenv("SIMPLE_CA_DAYS", "")
	savedArgs, savedCommandLine := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = savedArgs, savedCommandLine })
	os.Args = append([]string{"request-cert"}, args...)
	flag.CommandLine = flag.NewFlagSet("request-cert", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	return run()
}

func TestCAURLRefused(t *testing.T) {
	for caURL, want := range map[string]string{
		"https://pki.example.com/a/b":      `CA_URL: "https://pki.example.com/a/b" has the path "/a/b", not /NAME`,
		"https://pki.example.com/?x=1":     `CA_URL: "https://pki.example.com/?x=1" has a query`,
		"https://pki.example.com/\nforged": `CA_URL: "https://pki.example.com/\nforged" is not a URL`,
		"pki.example.com":                  `CA_URL: "pki.example.com" is not an http or https URL`,
	} {
		dir := t.TempDir()
		err := runWith(t, "tok", "--out-dir", dir, caURL, "web.example.com")
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("CA_URL %q: %v, want %s", caURL, err, want)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("CA_URL %q left %v", caURL, entries)
		}
	}
}

func TestNoIssuingCA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	dir := t.TempDir()
	err := runWith(t, "tok", "--out-dir", dir, srv.URL+"/nosuch", "web.example.com")
	if want := strconv.Quote(srv.URL) + " has no issuing CA nosuch"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %s", err, want)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refused request left %v", entries)
	}
}

func TestRequestCert(t *testing.T) {
	var path, auth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]string{"serial": "01", "certificate": "CERT\n", "chain": "CHAIN\n"})
	}))
	defer srv.Close()
	dir := t.TempDir()
	if err := runWith(t, "tok", "--out-dir", dir, srv.URL+"/servers/", "web.example.com"); err != nil {
		t.Fatal(err)
	}
	if path != "/servers/api/sign" || auth != "Bearer tok" || body["type"] != "server" || body["name"] != "web.example.com" {
		t.Errorf("request to %q with %q, body %v", path, auth, body)
	}
	for name, want := range map[string]string{"web.example.com_cert.pem": "CERT\n", "web.example.com_chain.pem": "CHAIN\n"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(b) != want {
			t.Errorf("%s: %q, %v, want %q", name, b, err, want)
		}
	}
	info, err := os.Stat(filepath.Join(dir, "web.example.com_key.pem"))
	if err != nil || info.Size() == 0 {
		t.Fatalf("key: %v, %v", info, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("key mode %o, want 600", info.Mode().Perm())
	}
}
