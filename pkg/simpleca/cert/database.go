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
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

const (
	indexFile     = "index.txt"
	indexAttrFile = "index.txt.attr"
	CRLNumberFile = "crlnumber"

	utcTimeFormat         = "060102150405Z"
	generalizedTimeFormat = "20060102150405Z"
)

// IndexEntry is one line of the index.txt of a CA, in the format of "openssl ca".
type IndexEntry struct {
	Status  string // V valid, R revoked, E expired
	Expires string // UTCTime, or GeneralizedTime from 2050
	Revoked string // UTCTime, empty unless revoked
	Serial  string // upper-case hex
	File    string
	Subject string // one-line form, /CN=...
}

// initCADatabase writes an empty index.txt, its index.txt.attr and a crlnumber of 01 to the CA
// directory dir.
func initCADatabase(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, indexFile), nil, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, indexAttrFile), []byte("unique_subject = no\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, CRLNumberFile), []byte("01\n"), 0o644)
}

// ReadIndex reads index.txt of the CA directory dir, or returns no entries when it does not exist.
func ReadIndex(dir string) ([]IndexEntry, error) {
	path := filepath.Join(dir, indexFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []IndexEntry
	for i, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("%s:%d: %d fields, want 6", path, i+1, len(f))
		}
		entries = append(entries, IndexEntry{f[0], f[1], f[2], f[3], f[4], f[5]})
	}
	return entries, nil
}

// ParseIndexTime parses an index.txt date, UTCTime or GeneralizedTime, ignoring what follows a
// comma.
func ParseIndexTime(s string) (time.Time, error) {
	s, _, _ = strings.Cut(s, ",")
	if len(s) == len(generalizedTimeFormat) {
		return time.Parse(generalizedTimeFormat, s)
	}
	return time.Parse(utcTimeFormat, s)
}

// EntryStatus returns "revoked", "expired" or "valid" for an index.txt entry at the time now.
func EntryStatus(e IndexEntry, now time.Time) (string, error) {
	if e.Status == "R" {
		return "revoked", nil
	}
	if e.Status == "E" {
		return "expired", nil
	}
	expires, err := ParseIndexTime(e.Expires)
	if err != nil {
		return "", fmt.Errorf("invalid expiry of serial %s: %w", e.Serial, err)
	}
	if !now.Before(expires) {
		return "expired", nil
	}
	return "valid", nil
}

// recordIssued adds cert as a valid certificate to index.txt of the CA directory dir.
func recordIssued(dir string, cert *x509.Certificate) error {
	unlock, err := simpleca.LockFile(filepath.Join(dir, indexFile))
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := ReadIndex(dir)
	if err != nil {
		return err
	}
	expires := cert.NotAfter.UTC().Format(utcTimeFormat)
	if cert.NotAfter.UTC().Year() >= 2050 {
		expires = cert.NotAfter.UTC().Format(generalizedTimeFormat)
	}
	entries = append(entries, IndexEntry{
		Status:  "V",
		Expires: expires,
		Serial:  SerialHex(cert.SerialNumber),
		File:    "unknown",
		Subject: NameString(cert.Subject),
	})
	return writeIndex(dir, entries)
}

// writeIndex writes entries to index.txt of the CA directory dir, replacing the file at once; an
// entry with a tab or a line end in a field is an error.
func writeIndex(dir string, entries []IndexEntry) error {
	var b strings.Builder
	for _, e := range entries {
		fields := []string{e.Status, e.Expires, e.Revoked, e.Serial, e.File, e.Subject}
		if slices.ContainsFunc(fields, func(f string) bool { return strings.ContainsAny(f, "\t\r\n") }) {
			return fmt.Errorf("the entry of serial %s holds a tab or a line end", e.Serial)
		}
		b.WriteString(strings.Join(fields, "\t") + "\n")
	}
	path := filepath.Join(dir, indexFile)
	if err := os.WriteFile(path+".tmp", []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
