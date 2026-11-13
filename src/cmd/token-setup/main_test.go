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
	"strings"
	"testing"
)

// runWith runs token-setup with args and a new command line, and returns its error.
func runWith(t *testing.T, args ...string) error {
	t.Helper()
	t.Setenv("SIMPLE_CA_URL", "")
	t.Setenv("SIMPLE_CA_TOKEN_FILE", "")
	savedArgs, savedCommandLine := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = savedArgs, savedCommandLine })
	os.Args = append([]string{"token-setup"}, args...)
	flag.CommandLine = flag.NewFlagSet("token-setup", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	return run()
}

func TestURLRefused(t *testing.T) {
	for url, want := range map[string]string{
		"https://pki.example.com/servers": `--url: "https://pki.example.com/servers" has a path or a query`,
		"https://pki.example.com:0":       `--url: "https://pki.example.com:0" has the port "0"`,
		"https://pki.example.com/\x1b[2J": `--url: "https://pki.example.com/\x1b[2J" is not a URL`,
	} {
		file := filepath.Join(t.TempDir(), "token")
		err := runWith(t, "--url", url, "--token-file", file, "CODE")
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("--url %q: %v, want %s", url, err, want)
		}
		if _, err := os.Stat(file); err == nil {
			t.Errorf("--url %q made the token file", url)
		}
	}
}

func TestTokenSetup(t *testing.T) {
	var path string
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]string{"token": "the-token"})
	}))
	defer srv.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := runWith(t, "--url", srv.URL+"/", "--token-file", file, " CODE \n"); err != nil {
		t.Fatal(err)
	}
	if path != "/api/token-setup" || body["code"] != "CODE" {
		t.Errorf("request to %q with %v", path, body)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "the-token\n" {
		t.Errorf("token file %q, %v", b, err)
	}
}
