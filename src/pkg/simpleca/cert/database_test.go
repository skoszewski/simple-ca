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

package cert

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestIndex(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := MakeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	if simpleca.FileExists(filepath.Join(caDir, simpleca.ConfigFile)) {
		t.Fatalf("%s written without settings", simpleca.ConfigFile)
	}

	for _, c := range []struct{ dir, cert, subject string }{
		{caDir, filepath.Join(caDir, "issuing-ca", "ca_cert.pem"), "/CN=Issuing CA"},
		{filepath.Join(caDir, "issuing-ca"), filepath.Join(caDir, "issuing-ca", "test_cert.pem"), "/CN=test"},
	} {
		out, err := exec.Command("openssl", "x509", "-in", c.cert, "-noout", "-serial").Output()
		if err != nil {
			t.Fatalf("openssl x509 -serial: %v", err)
		}
		opensslSerial := strings.TrimPrefix(strings.TrimSpace(string(out)), "serial=")
		crt, err := simpleca.LoadCert(c.cert)
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		want := []IndexEntry{{Status: "V", Expires: crt.NotAfter.UTC().Format(utcTimeFormat), Serial: opensslSerial, File: "unknown", Subject: c.subject}}
		entries, err := ReadIndex(c.dir)
		if err != nil {
			t.Fatalf("readIndex: %v", err)
		}
		if !slices.Equal(entries, want) {
			t.Fatalf("index of %s is %+v, want %+v", c.dir, entries, want)
		}
	}
}

func TestEntryStatus(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		entry IndexEntry
		want  string
	}{
		{IndexEntry{Status: "V", Expires: "261030120001Z"}, "valid"},
		{IndexEntry{Status: "V", Expires: "261030120000Z"}, "expired"},
		{IndexEntry{Status: "V", Expires: "20501030120000Z"}, "valid"},
		{IndexEntry{Status: "E", Expires: "271030120000Z"}, "expired"},
		{IndexEntry{Status: "R", Expires: "271030120000Z", Revoked: "261029120000Z"}, "revoked"},
	} {
		got, err := EntryStatus(c.entry, now)
		if err != nil {
			t.Fatalf("entryStatus %+v: %v", c.entry, err)
		}
		if got != c.want {
			t.Fatalf("entryStatus %+v = %q, want %q", c.entry, got, c.want)
		}
	}
}
