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

// ---- OpenSSL CA database ----------------------------------------------------

const (
	indexFile     = "index.txt"
	indexAttrFile = "index.txt.attr"
	crlNumberFile = "crlnumber"

	utcTimeFormat         = "060102150405Z"
	generalizedTimeFormat = "20060102150405Z"
)

// indexEntry is one line of the index.txt of a CA, in the format of "openssl ca".
type indexEntry struct {
	status  string // V valid, R revoked, E expired
	expires string // UTCTime, or GeneralizedTime from 2050
	revoked string // UTCTime, empty unless revoked
	serial  string // upper-case hex
	file    string
	subject string // one-line form, /CN=...
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
	return os.WriteFile(filepath.Join(dir, crlNumberFile), []byte("01\n"), 0o644)
}

// readIndex reads index.txt of the CA directory dir, or returns no entries when it does not exist.
func readIndex(dir string) ([]indexEntry, error) {
	path := filepath.Join(dir, indexFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []indexEntry
	for i, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("%s:%d: %d fields, want 6", path, i+1, len(f))
		}
		entries = append(entries, indexEntry{f[0], f[1], f[2], f[3], f[4], f[5]})
	}
	return entries, nil
}

// parseIndexTime parses an index.txt date, UTCTime or GeneralizedTime, ignoring what follows a
// comma.
func parseIndexTime(s string) (time.Time, error) {
	s, _, _ = strings.Cut(s, ",")
	if len(s) == len(generalizedTimeFormat) {
		return time.Parse(generalizedTimeFormat, s)
	}
	return time.Parse(utcTimeFormat, s)
}

// entryStatus returns "revoked", "expired" or "valid" for an index.txt entry at the time now.
func entryStatus(e indexEntry, now time.Time) (string, error) {
	if e.status == "R" {
		return "revoked", nil
	}
	if e.status == "E" {
		return "expired", nil
	}
	expires, err := parseIndexTime(e.expires)
	if err != nil {
		return "", fmt.Errorf("invalid expiry of serial %s: %w", e.serial, err)
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
	entries, err := readIndex(dir)
	if err != nil {
		return err
	}
	expires := cert.NotAfter.UTC().Format(utcTimeFormat)
	if cert.NotAfter.UTC().Year() >= 2050 {
		expires = cert.NotAfter.UTC().Format(generalizedTimeFormat)
	}
	entries = append(entries, indexEntry{
		status:  "V",
		expires: expires,
		serial:  serialHex(cert.SerialNumber),
		file:    "unknown",
		subject: nameString(cert.Subject),
	})
	return writeIndex(dir, entries)
}

// writeIndex writes entries to index.txt of the CA directory dir, replacing the file at once; an
// entry with a tab or a line end in a field is an error.
func writeIndex(dir string, entries []indexEntry) error {
	var b strings.Builder
	for _, e := range entries {
		fields := []string{e.status, e.expires, e.revoked, e.serial, e.file, e.subject}
		if slices.ContainsFunc(fields, func(f string) bool { return strings.ContainsAny(f, "\t\r\n") }) {
			return fmt.Errorf("the entry of serial %s holds a tab or a line end", e.serial)
		}
		b.WriteString(strings.Join(fields, "\t") + "\n")
	}
	path := filepath.Join(dir, indexFile)
	if err := os.WriteFile(path+".tmp", []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}
