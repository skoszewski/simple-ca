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
	"regexp"
	"strings"
	"testing"
	"time"
)

const day = 24 * time.Hour

func TestParseDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{
		"30":    30 * time.Minute,
		"0":     0,
		"8h":    8 * time.Hour,
		"180d":  180 * day,
		"6m":    180 * day,
		"1y":    365 * day,
		" 2 d ": 2 * day,
	} {
		if got, err := ParseDuration(s); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v, want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "h", "8 hours", "1.5h", "-1h", "8s", "1w", "99999999999y"} {
		if _, err := ParseDuration(s); err == nil {
			t.Errorf("ParseDuration(%q) succeeded, want an error", s)
		}
	}
}

func TestDurationText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		365 * day:                   "1y",
		730 * day:                   "2y",
		180 * day:                   "6m",
		400 * day:                   "400d",
		2 * day:                     "2d",
		25 * time.Hour:              "25h",
		8 * time.Hour:               "8h",
		90 * time.Minute:            "90",
		30 * time.Second:            "1",
		29 * time.Second:            "0",
		0:                           "0",
		time.Hour + 20*time.Second:  "1h",
		time.Hour + 40*time.Second:  "61",
		365*day + 30*time.Minute:    "525630",
		24*time.Hour + time.Second:  "1d",
		7*24*time.Hour + time.Hour:  "169h",
		30*day + 24*time.Hour:       "31d",
		12 * 30 * day:               "12m",
		5*time.Minute + time.Second: "5",
	} {
		if got := DurationText(d); got != want {
			t.Errorf("DurationText(%v) = %q, want %q", d, got, want)
		}
	}
	for _, d := range []time.Duration{0, 15 * time.Minute, 8 * time.Hour, 3 * day, 60 * day, 2 * 365 * day} {
		if got, err := ParseDuration(DurationText(d)); err != nil || got != d {
			t.Errorf("ParseDuration(DurationText(%v)) = %v, %v", d, got, err)
		}
	}
}

func TestParseIP(t *testing.T) {
	for s, want := range map[string]bool{
		"192.0.2.1": true, "2001:db8::1": true, "::1": true,
		"fe80::1%en0": false, "300.1.2.3": false, "10.0.0.0/8": false, "example.com": false, "": false,
	} {
		if _, ok := ParseIP(s); ok != want {
			t.Errorf("ParseIP(%q) = %v, want %v", s, ok, want)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	for s, want := range map[string]string{
		"192.0.2.10":    "192.0.2.10/32",
		"10.1.2.3/8":    "10.0.0.0/8",
		"2001:db8::1":   "2001:db8::1/128",
		"2001:db8::/32": "2001:db8::/32",
		"0.0.0.0/0":     "0.0.0.0/0",
	} {
		if got, ok := ParsePrefix(s); !ok || got.String() != want {
			t.Errorf("ParsePrefix(%q) = %v, %v, want %s", s, got, ok, want)
		}
	}
	for _, s := range []string{"300.1.2.3", "10.0.0.0/33", "fe80::1%en0", "example.com", "*", ""} {
		if _, ok := ParsePrefix(s); ok {
			t.Errorf("ParsePrefix(%q) succeeded, want it refused", s)
		}
	}
}

func TestIsHostname(t *testing.T) {
	for _, s := range []string{"example.com", "Example.COM", "web-1.example.com", "localhost", "a.b2", "1a.example.com"} {
		if !IsHostname(s) {
			t.Errorf("IsHostname(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", "192.0.2.1", "::1", "1.2.3", "123", "example.123", "-a.example.com", "a-.example.com", "a..example.com",
		"under_score.example.com", "*.example.com", "example.com.", strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("abcdefghi.", 25) + "example", "two words.example.com",
	} {
		if IsHostname(s) {
			t.Errorf("IsHostname(%q) = true, want false", s)
		}
	}
}

func TestKebabCaseRE(t *testing.T) {
	for _, s := range []string{"web-server", "lab-servers2", "a", "2fa"} {
		if !KebabCaseRE.MatchString(s) {
			t.Errorf("%q is not kebab-case, want it to be", s)
		}
	}
	for _, s := range []string{"", "Servers", "lab_servers", "lab--servers", "-lab", "lab-", "lab.servers", "lab servers"} {
		if KebabCaseRE.MatchString(s) {
			t.Errorf("%q is kebab-case, want it not to be", s)
		}
	}
}

func TestRandomID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := RandomID()
		if ok, _ := regexp.MatchString(`^[A-Za-z0-9_-]{22}$`, id); !ok || seen[id] {
			t.Fatalf("RandomID() = %q, want 22 new base64url characters", id)
		}
		seen[id] = true
	}
}
