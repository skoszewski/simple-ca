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

package weburl

import (
	"strings"
	"testing"
)

func TestServer(t *testing.T) {
	valid := map[string]string{
		"https://pki.example.com":       "https://pki.example.com",
		"https://pki.example.com/":      "https://pki.example.com",
		"https://pki.example.com:8443":  "https://pki.example.com:8443",
		"http://127.0.0.1:8080/":        "http://127.0.0.1:8080",
		"https://[2001:db8::1]:8443":    "https://[2001:db8::1]:8443",
		"HTTPS://pki.example.com:65535": "https://pki.example.com:65535",
	}
	for raw, want := range valid {
		if got, err := Server(raw, false); err != nil || got != want {
			t.Errorf("Server(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
	refused := map[string]string{
		"https://pki.example.com/gcp-wif": "has a path",
		"https://pki.example.com/?a=b":    "has a path or a query",
		"https://pki.example.com?":        "has a path or a query",
		"https://pki.example.com#top":     "has a fragment",
		"https://pki.example.com#":        "has a fragment",
		"https://user@pki.example.com":    "has a user name",
		"ftp://pki.example.com":           "not an http or https URL",
		"pki.example.com":                 "not an http or https URL",
		"https://":                        "has no host",
		"https://:8443":                   "has no host",
		"https://pki.example.com:":        "has the port \"\"",
		"https://pki.example.com:0":       "has the port \"0\"",
		"https://pki.example.com:65536":   "has the port \"65536\"",
		"https://pki.example.com:x":       "is not a URL",
		"mailto:ca@example.com":           "not an http or https URL",
	}
	for raw, want := range refused {
		if _, err := Server(raw, false); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Server(%q): %v, want %q", raw, err, want)
		}
	}
	if _, err := Server("http://pki.example.com", true); err == nil || !strings.Contains(err.Error(), "not an https URL") {
		t.Errorf("Server of http with https only: %v", err)
	}
}

func TestErrorsEscapeURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://pki.example.com/\nforged": `"https://pki.example.com/\nforged" is not a URL`,
		"\x1b[31mhttps://pki.example.com":  `"\x1b[31mhttps://pki.example.com" is not a URL`,
		"ftp://pki.example.com/\u200b":     `"ftp://pki.example.com/\u200b" is not an http or https URL`,
	} {
		_, err := Server(raw, false)
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("Server(%q): %v, want %s", raw, err, want)
		}
	}
	_, _, err := CA("https://pki.example.com/a\"b")
	if want := `"https://pki.example.com/a\"b" has the path "/a\"b"`; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("CA with a quote: %v, want %s", err, want)
	}
}

func TestCA(t *testing.T) {
	valid := map[string][2]string{
		"https://pki.example.com":              {"https://pki.example.com", ""},
		"https://pki.example.com/":             {"https://pki.example.com", ""},
		"https://pki.example.com:8443/servers": {"https://pki.example.com:8443", "servers"},
		"https://pki.example.com/gcp-wif/":     {"https://pki.example.com", "gcp-wif"},
		"http://localhost:8080/web-servers-2":  {"http://localhost:8080", "web-servers-2"},
	}
	for raw, want := range valid {
		if srv, ca, err := CA(raw); err != nil || srv != want[0] || ca != want[1] {
			t.Errorf("CA(%q) = %q, %q, %v, want %q", raw, srv, ca, err, want)
		}
	}
	refused := map[string]string{
		"https://pki.example.com/a/b":             "not /NAME",
		"https://pki.example.com/gcp-wif/gcp-wif": "not /NAME",
		"https://pki.example.com/api/sign":        "not /NAME",
		"https://pki.example.com/Servers":         "not /NAME",
		"https://pki.example.com//":               "not /NAME",
		"https://pki.example.com/servers?x=1":     "has a query",
		"https://pki.example.com:99999/servers":   "has the port",
		"https:///servers":                        "has no host",
	}
	for raw, want := range refused {
		if _, _, err := CA(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CA(%q): %v, want %q", raw, err, want)
		}
	}
}

func TestEndpoint(t *testing.T) {
	for _, raw := range []string{"https://sso.example.com/realms/lab", "https://login.example.com/t/v2.0/",
		"https://oauth2.example.com/token?x=1"} {
		if got, err := Endpoint(raw, true); err != nil || got != raw {
			t.Errorf("Endpoint(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"http://sso.example.com", "https://sso.example.com/x#f", "https://u:p@sso.example.com",
		"https:///realms/lab"} {
		if _, err := Endpoint(raw, true); err == nil {
			t.Errorf("Endpoint(%q) is taken", raw)
		}
	}
	if _, err := Endpoint("http://sso.example.com/realms/lab", false); err != nil {
		t.Errorf("Endpoint of http: %v", err)
	}
}
