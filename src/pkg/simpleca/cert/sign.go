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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// IssueMu serializes the certificates serve issues, by ACME, the signing API and the signing form,
// and guards the ACME states.
var IssueMu sync.Mutex

// RequestCert issues a certificate of the type certType for the certificate signing request
// csrData, PEM or DER, signed by the CA in caDir, without writing or recording it.
//
// Only the subject and the subjectAltName extension of the request are copied, as they are; the
// key usages and extended key usages are those of the type with kus and ekus added, as parsed by
// ParseUsages, and the other extensions of the request are left out.
func RequestCert(caDir string, csrData []byte, certType string, days int, ekus, kus []string) (*x509.Certificate, error) {
	if days < 1 {
		return nil, errors.New("the validity in days must be a positive integer")
	}
	if !DirExists(caDir) {
		return nil, fmt.Errorf("CA directory %s does not exist", caDir)
	}
	csr, err := ParseCSR(csrData)
	if err != nil {
		return nil, err
	}
	san := CSRSAN(csr)
	if len(csr.Subject.Names) == 0 && san == nil {
		return nil, errors.New("the request has neither a subject nor subject alternative names")
	}
	tmpl := &x509.Certificate{RawSubject: csr.RawSubject}
	if san != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	return IssueLeaf(caDir, certType, days, ekus, kus, tmpl, csr.PublicKey)
}

// StoreCert writes cert, issued by the CA in caDir, to the file certOut and records it in
// index.txt of that CA.
func StoreCert(caDir, certOut string, cert *x509.Certificate) error {
	if err := writeCert(cert.Raw, certOut); err != nil {
		return err
	}
	return recordIssued(caDir, cert)
}

// ParseCSR parses a certificate signing request, PEM or DER, and checks its signature.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, errors.New("no CERTIFICATE REQUEST PEM block")
		}
		der = block.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}
	if err := checkSubject(csr.Subject); err != nil {
		return nil, err
	}
	return csr, nil
}

// CSRSAN returns the subjectAltName extension of csr, critical when its subject is empty, or nil
// when it has none.
func CSRSAN(csr *x509.CertificateRequest) *pkix.Extension {
	var san *pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			san = &pkix.Extension{Id: oidSubjectAltName, Critical: len(csr.Subject.Names) == 0, Value: ext.Value}
		}
	}
	return san
}

// maxValidityDays is the most days a validity is computed for.
const maxValidityDays = 1000000

// CheckValidity returns an error when a certificate valid for days from now ends after caCert.
func CheckValidity(caCert *x509.Certificate, now time.Time, days int) error {
	if days <= maxValidityDays && !now.AddDate(0, 0, days).After(caCert.NotAfter) {
		return nil
	}
	return fmt.Errorf("the validity of %d days ends after the CA certificate, which allows at most %d days",
		days, max(int(caCert.NotAfter.Sub(now).Hours()/24), 0))
}

// checkSubject returns an error when an attribute value of name holds a control character.
func checkSubject(name pkix.Name) error {
	for _, attr := range name.Names {
		if strings.ContainsFunc(fmt.Sprint(attr.Value), unicode.IsControl) {
			return errors.New("the subject holds a control character")
		}
	}
	return nil
}

// leafKeyUsage returns the key usages ku of a certificate for the public key pub, without
// keyEncipherment for an ECDSA key, which cannot encipher keys (RFC 5480).
func leafKeyUsage(ku x509.KeyUsage, pub any) x509.KeyUsage {
	if _, ok := pub.(*ecdsa.PublicKey); ok {
		return ku &^ x509.KeyUsageKeyEncipherment
	}
	return ku
}

// IssueLeaf signs a certificate of the type certType for the public key pub with the CA in caDir,
// valid for days from now, and returns it without recording it in index.txt. The subject and the
// extensions of tmpl are kept; the key usages and extended key usages are those of the type with
// kus and ekus added, and the AIA and CRL Distribution Point URLs those of the CA.
func IssueLeaf(caDir, certType string, days int, ekus, kus []string, tmpl *x509.Certificate, pub any) (*x509.Certificate, error) {
	rootDir, issuingCA, err := simpleca.LocateCA(caDir)
	if err != nil {
		return nil, err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return nil, err
	}
	types, err := Types(cfg)
	if err != nil {
		return nil, err
	}
	def, ok := types[certType]
	if !ok {
		return nil, fmt.Errorf("unknown type '%s': must be one of %s", certType, TypeNames(types))
	}
	keyUsage, extKeyUsages, extKeyUsageOIDs, err := ParseUsages(
		append(slices.Clone(def.KeyUsage), kus...), append(slices.Clone(def.ExtKeyUsage), ekus...))
	if err != nil {
		return nil, err
	}

	caCertPath := filepath.Join(caDir, "ca_cert.pem")
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !simpleca.FileExists(caCertPath) || !simpleca.FileExists(caKeyPath) {
		return nil, fmt.Errorf("CA certificate and key not found in %s, which is not a CA directory", caDir)
	}
	caCert, err := simpleca.LoadCert(caCertPath)
	if err != nil {
		return nil, err
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := CheckValidity(caCert, now, days); err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now
	tmpl.NotAfter = now.AddDate(0, 0, days)
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = leafKeyUsage(keyUsage, pub)
	tmpl.ExtKeyUsage = extKeyUsages
	tmpl.UnknownExtKeyUsage = extKeyUsageOIDs
	if cfg.CAPublishBaseURL != "" {
		publishURL := cfg.CAPublishBaseURL
		if issuingCA != "" {
			publishURL += "/" + issuingCA
		}
		tmpl.IssuingCertificateURL = []string{publishURL + "/ca_cert.crt"}
		tmpl.CRLDistributionPoints = []string{publishURL + "/crl.pem"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// CertFile returns the file of the certificate the name gives, NAME_cert.pem, each run of
// characters besides letters, digits, - and _ in name as one _; a name that gives no file name,
// or gives ca_cert.pem, the file of the CA certificate, is an error.
func CertFile(name string) (string, error) {
	clean := strings.Trim(FileNameRE.ReplaceAllString(strings.TrimSpace(name), "_"), "_")
	switch {
	case clean == "":
		return "", fmt.Errorf("'%s' gives no file name: it needs a letter or a digit", name)
	case clean == "ca":
		return "", errors.New("the name ca gives ca_cert.pem, the file of the CA certificate")
	}
	return clean + "_cert.pem", nil
}
