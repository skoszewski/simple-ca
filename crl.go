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

// ---- revocation reasons -----------------------------------------------------

// crlReasons are the revocation reasons of index.txt in the names of "openssl ca", with their
// reason codes of RFC 5280; revoke-cert takes the first six, and the last three are the pseudo
// reasons OpenSSL writes with an extra field.
var crlReasons = []struct {
	name string
	code int
}{
	{"unspecified", 0},
	{"keyCompromise", 1},
	{"CACompromise", 2},
	{"affiliationChanged", 3},
	{"superseded", 4},
	{"cessationOfOperation", 5},
	{"certificateHold", 6},
	{"removeFromCRL", 8},
	{"holdInstruction", 6},
	{"keyTime", 1},
	{"CAkeyTime", 2},
}

// revocationReason returns the name and the reason code of the reason in the revocation field of
// an index.txt entry, date[,reason[,extra]], and "" when it has none.
func revocationReason(revoked string) (string, int, error) {
	_, rest, found := strings.Cut(revoked, ",")
	if !found {
		return "", 0, nil
	}
	name, _, _ := strings.Cut(rest, ",")
	for _, r := range crlReasons {
		if strings.EqualFold(r.name, name) {
			return r.name, r.code, nil
		}
	}
	return "", 0, fmt.Errorf("unknown revocation reason '%s'", name)
}

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
		_, reasonCode, err := revocationReason(e.revoked)
		if err != nil {
			return fmt.Errorf("serial %s in %s: %w", e.serial, filepath.Join(signingDir, indexFile), err)
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt, ReasonCode: reasonCode})
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

// revokeCert marks the certificate at certPath as revoked in index.txt of the CA in caDir, for
// reason, one of the first six of crlReasons in any letter case, or for no reason when empty.
func revokeCert(certPath, caDir, reason string) error {
	if reason != "" {
		var names []string
		for _, r := range crlReasons[:6] {
			names = append(names, r.name)
		}
		i := slices.IndexFunc(names, func(name string) bool { return strings.EqualFold(name, reason) })
		if i < 0 {
			return fmt.Errorf("unknown revocation reason '%s': must be one of %s", reason, strings.Join(names, ", "))
		}
		reason = names[i]
	}
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
	if reason != "" {
		entries[i].revoked += "," + reason
	}
	if err := writeIndex(signingDir, entries); err != nil {
		return err
	}
	if reason != "" {
		fmt.Printf("Certificate %s (serial %s) marked as revoked, reason %s.\n", certPath, serial, reason)
	} else {
		fmt.Printf("Certificate %s (serial %s) marked as revoked.\n", certPath, serial)
	}
	return nil
}
