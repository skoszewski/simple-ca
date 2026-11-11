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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// rebuildCABundle writes ca_bundle.pem containing the root CA cert followed by
// all issuing CA certs found in immediate subdirectories.
func rebuildCABundle(caDir string) error {
	var bundle []byte

	rootPath := filepath.Join(caDir, "ca_cert.pem")
	if simpleca.FileExists(rootPath) {
		data, err := os.ReadFile(rootPath)
		if err != nil {
			return err
		}
		bundle = append(bundle, data...)
	}

	entries, _ := os.ReadDir(caDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		subCert := filepath.Join(caDir, e.Name(), "ca_cert.pem")
		if !simpleca.FileExists(subCert) {
			continue
		}
		data, err := os.ReadFile(subCert)
		if err != nil {
			return err
		}
		bundle = append(bundle, data...)
	}

	return os.WriteFile(filepath.Join(caDir, "ca_bundle.pem"), bundle, 0o644)
}

// MakeCA creates the root CA in caDir, or with issuingCA, a kebab-case name, an issuing CA in
// caDir/issuingCA signed by the root CA in caDir, with a key of keyType, rsa or ec, its database
// and an empty first CRL valid for days.crl of simple-ca.json, 30 days without it, and skips a CA
// that exists. An issuing CA with days of zero is valid as long as its root CA.
func MakeCA(caDir, caName string, days int, issuingCA, baseURL, keyType string) error {
	if days < 1 && (days != 0 || issuingCA == "") {
		return errors.New("--days must be a positive integer")
	}
	if !slices.Contains(keyTypes, keyType) {
		return fmt.Errorf("--key-type '%s' must be rsa or ec", keyType)
	}
	if !DirExists(caDir) {
		return fmt.Errorf("CA directory %s does not exist", caDir)
	}
	if caName == "" {
		return errors.New("CA name is required")
	}
	if issuingCA != "" && !simpleca.KebabCaseRE.MatchString(issuingCA) {
		return fmt.Errorf("issuing CA name '%s' is not a kebab-case name, such as servers or lab-servers", issuingCA)
	}
	if slices.Contains(ReservedNames, issuingCA) {
		return fmt.Errorf("issuing CA name '%s' is taken by the pages that serve shows at /%s/", issuingCA, issuingCA)
	}
	if simpleca.FileExists(filepath.Join(caDir, "ca_cert.pem")) {
		rootDir, name, err := simpleca.LocateCA(caDir)
		if err != nil {
			return err
		}
		if name != "" {
			return fmt.Errorf("%s holds the issuing CA '%s'; run ca create with --ca-dir of its root CA, %s",
				caDir, name, rootDir)
		}
	}

	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		return err
	}
	if baseURL != "" {
		cfg.CAPublishBaseURL = baseURL
		if err := cfg.Save(); err != nil {
			return err
		}
	}
	baseURL = cfg.CAPublishBaseURL
	crlDays := 30
	if cfg.Days.CRL > 0 {
		crlDays = cfg.Days.CRL
	}

	rootCertPath := filepath.Join(caDir, "ca_cert.pem")
	rootKeyPath := filepath.Join(caDir, "ca_key.pem")

	// ---- root CA ----
	if !simpleca.FileExists(rootCertPath) || !simpleca.FileExists(rootKeyPath) {
		if issuingCA != "" {
			return fmt.Errorf(
				"cannot create issuing CA '%s' without existing root CA. "+
					"Please create the root CA first", caName)
		}
		fmt.Printf("Generating root CA certificate '%s' and key...\n", caName)
		key, err := newKey(keyType)
		if err != nil {
			return err
		}
		serial, err := randomSerial()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: caName},
			NotBefore:             now,
			NotAfter:              now.AddDate(0, 0, days),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            1,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			return err
		}
		if err := writeKey(key, rootKeyPath); err != nil {
			return err
		}
		if err := writeCert(der, rootCertPath); err != nil {
			return err
		}
		if err := initCADatabase(caDir); err != nil {
			return err
		}
		if err := MakeCRL(caDir, crlDays); err != nil {
			return err
		}
		fmt.Printf("CRL written to %s\n", filepath.Join(caDir, "crl.pem"))
		return rebuildCABundle(caDir)
	}

	if issuingCA == "" {
		fmt.Printf("Root CA already exists in %s, skipping.\n", caDir)
		return nil
	}

	// ---- issuing CA ----
	issuingCADir := filepath.Join(caDir, issuingCA)
	issuingCACert := filepath.Join(issuingCADir, "ca_cert.pem")
	issuingCAKey := filepath.Join(issuingCADir, "ca_key.pem")

	if simpleca.FileExists(issuingCACert) && simpleca.FileExists(issuingCAKey) {
		fmt.Printf("Issuing CA '%s' already exists in %s, skipping.\n", issuingCA, issuingCADir)
	} else {
		fmt.Printf("Generating issuing CA certificate '%s' and key...\n", caName)
		if err := os.MkdirAll(issuingCADir, 0o755); err != nil {
			return err
		}
		rootCert, err := simpleca.LoadCert(rootCertPath)
		if err != nil {
			return err
		}
		rootKey, err := simpleca.LoadKey(rootKeyPath)
		if err != nil {
			return err
		}
		key, err := newKey(keyType)
		if err != nil {
			return err
		}
		serial, err := randomSerial()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		notAfter := rootCert.NotAfter
		if days > 0 {
			if err := CheckValidity(rootCert, now, days); err != nil {
				return err
			}
			notAfter = now.AddDate(0, 0, days)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: caName},
			NotBefore:             now,
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		if baseURL != "" {
			tmpl.IssuingCertificateURL = []string{baseURL + "/ca_cert.crt"}
			tmpl.CRLDistributionPoints = []string{baseURL + "/crl.pem"}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, key.Public(), rootKey)
		if err != nil {
			return err
		}
		if err := writeKey(key, issuingCAKey); err != nil {
			return err
		}
		if err := writeCert(der, issuingCACert); err != nil {
			return err
		}
		if err := initCADatabase(issuingCADir); err != nil {
			return err
		}
		issued, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if err := recordIssued(caDir, issued); err != nil {
			return err
		}
		if err := MakeCRL(issuingCADir, crlDays); err != nil {
			return err
		}
		fmt.Printf("CRL written to %s\n", filepath.Join(issuingCADir, "crl.pem"))
	}

	return rebuildCABundle(caDir)
}

// ReservedNames are the issuing CA names that the pages of serve take as their paths.
var ReservedNames = []string{"help", "docs", "tokens", "certificates", "audit", "downloads", "apt"}
