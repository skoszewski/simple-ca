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

// Package simpleca is the base of simple-ca: the settings of simple-ca.json, the files and keys of
// a CA, the helpers, the file lock and the audit log.
package simpleca

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// LocateCA returns the root CA directory of the CA in caDir and the name of that CA as an
// issuing CA: caDir and "" for a self-signed root CA, else the directory above caDir, where the
// root CA keeps its issuing CAs, and the name of caDir.
func LocateCA(caDir string) (rootDir, issuingCA string, err error) {
	abs, err := filepath.Abs(caDir)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(abs, "ca_cert.pem")
	if !FileExists(certPath) {
		return "", "", fmt.Errorf("CA certificate not found in %q", caDir)
	}
	cert, err := LoadCert(certPath)
	if err != nil {
		return "", "", err
	}
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return abs, "", nil
	}
	return filepath.Dir(abs), filepath.Base(abs), nil
}

// LoadCert reads the first PEM block of path as a certificate.
func LoadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block in %q", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// FileExists reports whether path exists and is not a directory.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// CAIDs returns the IDs of the root CA in rootDir, empty, and of its issuing CAs.
func CAIDs(rootDir string) []string {
	ids := []string{""}
	entries, _ := os.ReadDir(rootDir)
	for _, e := range entries {
		if e.IsDir() && KebabCaseRE.MatchString(e.Name()) && FileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
			ids = append(ids, e.Name())
		}
	}
	return ids
}
