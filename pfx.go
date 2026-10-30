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
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ---- makePFX ----------------------------------------------------------------

// makePFX writes a PKCS#12 bundle of the certificate at certPath, its key and the chain of the CA
// in caDir that signed it next to the certificate.
func makePFX(certPath, caDir, password string) error {
	certDir := filepath.Dir(certPath)
	certName := strings.TrimSuffix(filepath.Base(certPath), "_cert.pem")
	keyPath := filepath.Join(certDir, certName+"_key.pem")
	pfxPath := filepath.Join(certDir, certName+".pfx")

	if !dirExists(certDir) {
		return fmt.Errorf("certificate directory %s does not exist", certDir)
	}
	if !dirExists(caDir) {
		return fmt.Errorf("CA directory %s does not exist", caDir)
	}
	if !fileExists(certPath) || !fileExists(keyPath) {
		return errors.New("server certificate or key not found")
	}
	rootDir, issuingCA, err := locateCA(caDir)
	if err != nil {
		return err
	}
	rootCertPath := filepath.Join(rootDir, "ca_cert.pem")
	if !fileExists(rootCertPath) {
		return fmt.Errorf("root CA certificate not found in %s", rootDir)
	}
	if password == "" {
		password = "changeit"
	}
	if fileExists(pfxPath) {
		return errors.New("PKCS#12 (PFX) file already exists, aborting generation")
	}

	fmt.Print("Generating PKCS#12 (PFX) file...")

	cert, err := loadCert(certPath)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	root, err := loadCert(rootCertPath)
	if err != nil {
		return err
	}
	chain := []*x509.Certificate{root}
	if issuingCA != "" {
		issuing, err := loadCert(filepath.Join(caDir, "ca_cert.pem"))
		if err != nil {
			return err
		}
		chain = append(chain, issuing)
	}

	pfxBytes, err := pkcs12.Modern.Encode(key, cert, chain, password)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pfxPath, pfxBytes, 0o600); err != nil {
		return err
	}
	fmt.Println("done.")
	return nil
}
