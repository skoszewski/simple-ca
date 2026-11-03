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
	"bufio"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ---- signing requests -------------------------------------------------------

// requestCert issues a certificate of the type certType for the certificate signing request
// csrData, PEM or DER, signed by the CA in caDir, without writing or recording it.
//
// Only the subject and the subjectAltName extension of the request are copied, as they are; the
// key usages and extended key usages are those of the type with kus and ekus added, as parsed by
// parseUsages, and the other extensions of the request are left out.
func requestCert(caDir string, csrData []byte, certType string, days int, ekus, kus []string) (*x509.Certificate, error) {
	if days < 1 {
		return nil, errors.New("--days must be a positive integer")
	}
	if !dirExists(caDir) {
		return nil, fmt.Errorf("CA directory %s does not exist", caDir)
	}
	csr, err := parseCSR(csrData)
	if err != nil {
		return nil, err
	}
	san := csrSAN(csr)
	if len(csr.Subject.Names) == 0 && san == nil {
		return nil, errors.New("the request has neither a subject nor subject alternative names")
	}
	tmpl := &x509.Certificate{RawSubject: csr.RawSubject}
	if san != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*san}
	}
	return issueLeaf(caDir, certType, days, ekus, kus, tmpl, csr.PublicKey)
}

// storeCert writes cert, issued by the CA in caDir, to the file certOut and records it in
// index.txt of that CA.
func storeCert(caDir, certOut string, cert *x509.Certificate) error {
	if err := writeCert(cert.Raw, certOut); err != nil {
		return err
	}
	return recordIssued(caDir, cert)
}

// signCSR signs the request in csrPath as cert sign does, as requestCert, and writes it with
// storeCert to certDir, the CA directory when empty, as NAME_cert.pem for the request file
// NAME.EXT, each run of characters besides letters, digits, - and _ in NAME as one _, and returns
// it. The certificate is shown on stdout before it is written, and written when the answer read
// from confirm is y or yes, or without asking with force.
func signCSR(csrPath, caDir, certDir, certType string, days int, ekus, kus []string, force bool, confirm io.Reader) (*x509.Certificate, error) {
	if certDir == "" {
		certDir = caDir
	}
	if !dirExists(certDir) {
		return nil, fmt.Errorf("certificate directory %s does not exist", certDir)
	}
	base := filepath.Base(csrPath)
	certName := strings.Trim(fileNameRE.ReplaceAllString(strings.TrimSuffix(base, filepath.Ext(base)), "_"), "_")
	if certName == "" {
		return nil, fmt.Errorf("'%s' gives no file name: it needs a letter or a digit", base)
	}
	certOut := filepath.Join(certDir, certName+"_cert.pem")
	if fileExists(certOut) {
		return nil, fmt.Errorf("certificate %s exists", certOut)
	}
	data, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, err
	}
	cert, err := requestCert(caDir, data, certType, days, ekus, kus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", csrPath, err)
	}

	// The certificate is shown, and written only once it is approved or with force.
	fmt.Printf("The %s certificate for %s:\n\n", certType, csrPath)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	writeCertFields(tw, cert, time.Now())
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	fmt.Println()
	if !force {
		fmt.Print("Sign this certificate? [y/N] ")
		answer, err := bufio.NewReader(confirm).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			if errors.Is(err, io.EOF) {
				fmt.Println()
			}
			return nil, errors.New("the certificate was not signed")
		}
	}
	if err := storeCert(caDir, certOut, cert); err != nil {
		return nil, err
	}
	fmt.Printf("Certificate written to %s\n", certOut)
	return cert, nil
}

// parseCSR parses a certificate signing request, PEM or DER, and checks its signature.
func parseCSR(data []byte) (*x509.CertificateRequest, error) {
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
	return csr, nil
}

// csrSAN returns the subjectAltName extension of csr, critical when its subject is empty, or nil
// when it has none.
func csrSAN(csr *x509.CertificateRequest) *pkix.Extension {
	var san *pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			san = &pkix.Extension{Id: oidSubjectAltName, Critical: len(csr.Subject.Names) == 0, Value: ext.Value}
		}
	}
	return san
}

// ---- issueLeaf --------------------------------------------------------------

// issueLeaf signs a certificate of the type certType for the public key pub with the CA in caDir,
// valid for days from now, and returns it without recording it in index.txt. The subject and the
// extensions of tmpl are kept; the key usages and extended key usages are those of the type with
// kus and ekus added, and the AIA and CRL Distribution Point URLs those of the CA.
func issueLeaf(caDir, certType string, days int, ekus, kus []string, tmpl *x509.Certificate, pub any) (*x509.Certificate, error) {
	rootDir, issuingCA, err := locateCA(caDir)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(rootDir)
	if err != nil {
		return nil, err
	}
	types, err := cfg.certTypes()
	if err != nil {
		return nil, err
	}
	def, ok := types[certType]
	if !ok {
		return nil, fmt.Errorf("unknown type '%s': must be one of %s", certType, typeNames(types))
	}
	keyUsage, extKeyUsages, extKeyUsageOIDs, err := parseUsages(
		append(slices.Clone(def.keyUsage), kus...), append(slices.Clone(def.extKeyUsage), ekus...))
	if err != nil {
		return nil, err
	}

	caCertPath := filepath.Join(caDir, "ca_cert.pem")
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !fileExists(caCertPath) || !fileExists(caKeyPath) {
		return nil, fmt.Errorf(
			"CA certificate and key not found in %s. Please point --ca-dir to a CA directory",
			caDir)
	}
	caCert, err := loadCert(caCertPath)
	if err != nil {
		return nil, err
	}
	caKey, err := loadKey(caKeyPath)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now
	tmpl.NotAfter = now.AddDate(0, 0, days)
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = keyUsage
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
