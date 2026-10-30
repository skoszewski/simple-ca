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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ---- makeCRL ----------------------------------------------------------------

// makeCRL writes crl.pem of the CA in caDir, listing the certificates its index.txt marks as
// revoked, with the CRL number of its crlnumber, which it then raises.
func makeCRL(caDir string, days int) error {
	if days < 1 {
		return errors.New("--days must be a positive integer")
	}

	signingDir := caDir
	caCertPath := filepath.Join(signingDir, "ca_cert.pem")
	caKeyPath := filepath.Join(signingDir, "ca_key.pem")
	if !fileExists(caCertPath) || !fileExists(caKeyPath) {
		return fmt.Errorf("CA certificate or key not found in %s", signingDir)
	}
	caCert, err := loadCert(caCertPath)
	if err != nil {
		return err
	}
	if len(caCert.SubjectKeyId) == 0 {
		return fmt.Errorf("CA certificate %s has no subject key identifier", caCertPath)
	}
	caKey, err := loadKey(caKeyPath)
	if err != nil {
		return err
	}
	entries, err := readIndex(signingDir)
	if err != nil {
		return err
	}
	var revoked []x509.RevocationListEntry
	for _, e := range entries {
		if e.status != "R" {
			continue
		}
		serial, ok := new(big.Int).SetString(e.serial, 16)
		if !ok {
			return fmt.Errorf("invalid serial '%s' in %s", e.serial, filepath.Join(signingDir, indexFile))
		}
		revokedAt, err := parseIndexTime(e.revoked)
		if err != nil {
			return fmt.Errorf("invalid revocation date of serial %s in %s: %w", e.serial, filepath.Join(signingDir, indexFile), err)
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt})
	}

	numberPath := filepath.Join(signingDir, crlNumberFile)
	number := big.NewInt(1)
	b, err := os.ReadFile(numberPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if _, ok := number.SetString(strings.TrimSpace(string(b)), 16); !ok {
			return fmt.Errorf("invalid CRL number in %s", numberPath)
		}
	}

	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                now.AddDate(0, 0, days),
		RevokedCertificateEntries: revoked,
	}, caCert, caKey)
	if err != nil {
		return err
	}
	crlPath := filepath.Join(signingDir, "crl.pem")
	if err := writePEMFile(crlPath, "X509 CRL", der, 0o644); err != nil {
		return err
	}

	next := new(big.Int).Add(number, big.NewInt(1))
	if err := os.WriteFile(numberPath, []byte(serialHex(next)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("CRL written to %s\n", crlPath)
	return nil
}

// ---- revokeCert -------------------------------------------------------------

// revokeCert marks the certificate at certPath as revoked in index.txt of the CA in caDir.
func revokeCert(certPath, caDir string) error {
	if !fileExists(certPath) {
		return fmt.Errorf("certificate not found: %s", certPath)
	}
	signingDir := caDir
	if !dirExists(signingDir) {
		return fmt.Errorf("CA directory not found: %s", signingDir)
	}

	cert, err := loadCert(certPath)
	if err != nil {
		return err
	}
	serial := serialHex(cert.SerialNumber)
	entries, err := readIndex(signingDir)
	if err != nil {
		return err
	}

	i := slices.IndexFunc(entries, func(e indexEntry) bool { return strings.EqualFold(e.serial, serial) })
	if i < 0 {
		return fmt.Errorf("certificate with serial %s not found in %s", serial, filepath.Join(signingDir, indexFile))
	}
	if entries[i].status == "R" {
		fmt.Printf("Certificate %s (serial %s) is already revoked.\n", certPath, serial)
		return nil
	}
	entries[i].status = "R"
	entries[i].revoked = time.Now().UTC().Format(utcTimeFormat)
	if err := writeIndex(signingDir, entries); err != nil {
		return err
	}
	fmt.Printf("Certificate %s (serial %s) marked as revoked.\n", certPath, serial)
	return nil
}
