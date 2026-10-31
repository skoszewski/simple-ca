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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ---- ca show, cert show and cert list ---------------------------------------

const displayTimeFormat = "2006-01-02 15:04:05 MST"

// keyUsageNames names the key usage bits in the order of RFC 5280.
var keyUsageNames = []struct {
	usage x509.KeyUsage
	name  string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// extKeyUsageNames names the extended key usages crypto/x509 knows.
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msSGC",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "nsSGC",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCodeCom",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "msKernelCodeSigning",
}

// colonHex formats b as upper-case hex bytes separated by colons.
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

// keyDescription names the type and size of the public key of cert, such as "RSA 4096 bits".
func keyDescription(cert *x509.Certificate) string {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", cert.PublicKey)
}

// writeCertFields writes the fields of cert to w as tab-separated lines, its validity judged at
// the time now; a field the certificate does not have is left out.
func writeCertFields(w io.Writer, cert *x509.Certificate, now time.Time) {
	fmt.Fprintf(w, "Subject:\t%s\n", nameString(cert.Subject))
	fmt.Fprintf(w, "Issuer:\t%s\n", nameString(cert.Issuer))
	fmt.Fprintf(w, "Serial:\t%s\n", serialHex(cert.SerialNumber))
	fmt.Fprintf(w, "Valid from:\t%s\n", cert.NotBefore.UTC().Format(displayTimeFormat))
	fmt.Fprintf(w, "Valid until:\t%s\n", cert.NotAfter.UTC().Format(displayTimeFormat))
	validity := "valid"
	if now.Before(cert.NotBefore) {
		validity = "not yet valid"
	} else if now.After(cert.NotAfter) {
		validity = "expired"
	}
	fmt.Fprintf(w, "Validity:\t%s\n", validity)
	fmt.Fprintf(w, "Signature algorithm:\t%s\n", cert.SignatureAlgorithm)
	fmt.Fprintf(w, "Key:\t%s\n", keyDescription(cert))

	if cert.BasicConstraintsValid && cert.IsCA {
		pathLen := "unlimited"
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			pathLen = fmt.Sprint(cert.MaxPathLen)
		}
		fmt.Fprintf(w, "CA:\tyes, path length %s\n", pathLen)
	} else {
		fmt.Fprintf(w, "CA:\tno\n")
	}

	var usages []string
	for _, u := range keyUsageNames {
		if cert.KeyUsage&u.usage != 0 {
			usages = append(usages, u.name)
		}
	}
	if len(usages) > 0 {
		fmt.Fprintf(w, "Key usage:\t%s\n", strings.Join(usages, ", "))
	}
	var extUsages []string
	for _, u := range cert.ExtKeyUsage {
		name, ok := extKeyUsageNames[u]
		if !ok {
			name = fmt.Sprintf("unknown (%d)", u)
		}
		extUsages = append(extUsages, name)
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		extUsages = append(extUsages, oid.String())
	}
	if len(extUsages) > 0 {
		fmt.Fprintf(w, "Extended key usage:\t%s\n", strings.Join(extUsages, ", "))
	}

	for _, name := range cert.DNSNames {
		fmt.Fprintf(w, "DNS name:\t%s\n", name)
	}
	for _, ip := range cert.IPAddresses {
		fmt.Fprintf(w, "IP address:\t%s\n", ip)
	}
	for _, email := range cert.EmailAddresses {
		fmt.Fprintf(w, "Email address:\t%s\n", email)
	}
	for _, uri := range cert.URIs {
		fmt.Fprintf(w, "URI:\t%s\n", uri)
	}
	// The registeredID names, which crypto/x509 does not parse.
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &names); err != nil {
			continue
		}
		for _, n := range names {
			var oid x509.OID
			if n.Class == asn1.ClassContextSpecific && n.Tag == 8 && oid.UnmarshalBinary(n.Bytes) == nil {
				fmt.Fprintf(w, "Registered ID:\t%s\n", oid)
			}
		}
	}

	if len(cert.SubjectKeyId) > 0 {
		fmt.Fprintf(w, "Subject key ID:\t%s\n", colonHex(cert.SubjectKeyId))
	}
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Fprintf(w, "Authority key ID:\t%s\n", colonHex(cert.AuthorityKeyId))
	}
	for _, u := range cert.IssuingCertificateURL {
		fmt.Fprintf(w, "AIA CA issuers:\t%s\n", u)
	}
	for _, u := range cert.OCSPServer {
		fmt.Fprintf(w, "AIA OCSP:\t%s\n", u)
	}
	for _, u := range cert.CRLDistributionPoints {
		fmt.Fprintf(w, "CRL distribution point:\t%s\n", u)
	}
	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Fprintf(w, "SHA-256 fingerprint:\t%s\n", colonHex(fingerprint[:]))
}

// showCert writes the fields of every certificate in the PEM or DER file at path to w.
func showCert(w io.Writer, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return fmt.Errorf("no PEM or DER certificate in %s", path)
		}
		certs = append(certs, cert)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	now := time.Now()
	for i, cert := range certs {
		if len(certs) > 1 {
			if i > 0 {
				fmt.Fprintln(tw)
			}
			fmt.Fprintf(tw, "Certificate:\t%d of %d\n", i+1, len(certs))
		}
		writeCertFields(tw, cert, now)
	}
	return tw.Flush()
}

// showInfo writes the certificate, the certificate counts and the CRL of the CA in caDir to w,
// and for a root CA the names of its issuing CAs.
func showInfo(w io.Writer, caDir string) error {
	signingDir := caDir
	rootDir, issuingCA, err := locateCA(caDir)
	if err != nil {
		return err
	}
	kind := "root CA"
	if issuingCA != "" {
		kind = fmt.Sprintf("issuing CA '%s' of the root CA in %s", issuingCA, rootDir)
	}
	cert, err := loadCert(filepath.Join(signingDir, "ca_cert.pem"))
	if err != nil {
		return err
	}
	entries, err := readIndex(signingDir)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	now := time.Now()
	for _, e := range entries {
		status, err := entryStatus(e, now)
		if err != nil {
			return err
		}
		counts[status]++
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Role:\t%s\n", kind)
	fmt.Fprintf(tw, "Directory:\t%s\n", signingDir)
	writeCertFields(tw, cert, now)
	fmt.Fprintf(tw, "Certificates:\t%d valid, %d revoked, %d expired\n", counts["valid"], counts["revoked"], counts["expired"])

	// The CRL last written by crl create and the number of the next one.
	crlPath := filepath.Join(signingDir, "crl.pem")
	b, err := os.ReadFile(crlPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		fmt.Fprintf(tw, "CRL:\tnone\n")
	case err != nil:
		return err
	default:
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "X509 CRL" {
			return fmt.Errorf("no X509 CRL PEM block in %s", crlPath)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return fmt.Errorf("could not read %s: %w", crlPath, err)
		}
		fmt.Fprintf(tw, "CRL:\tnumber %s, %d revoked, updated %s, next update %s\n", crl.Number,
			len(crl.RevokedCertificateEntries), crl.ThisUpdate.UTC().Format(displayTimeFormat),
			crl.NextUpdate.UTC().Format(displayTimeFormat))
	}
	if b, err := os.ReadFile(filepath.Join(signingDir, crlNumberFile)); err == nil {
		if next, ok := new(big.Int).SetString(strings.TrimSpace(string(b)), 16); ok {
			fmt.Fprintf(tw, "Next CRL number:\t%s\n", next)
		}
	}

	if issuingCA == "" {
		var names []string
		dirs, _ := os.ReadDir(caDir)
		for _, d := range dirs {
			if d.IsDir() && fileExists(filepath.Join(caDir, d.Name(), "ca_cert.pem")) {
				names = append(names, d.Name())
			}
		}
		issuing := "none"
		if len(names) > 0 {
			issuing = strings.Join(names, ", ")
		}
		fmt.Fprintf(tw, "Issuing CAs:\t%s\n", issuing)
	}
	return tw.Flush()
}

// listCerts writes the index.txt entries of the CA in caDir whose status is one of statuses, all
// of them when statuses is empty, to w as a table.
func listCerts(w io.Writer, caDir string, statuses []string) error {
	signingDir := caDir
	if !dirExists(signingDir) {
		return fmt.Errorf("CA directory not found: %s", signingDir)
	}
	entries, err := readIndex(signingDir)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tEXPIRES\tREVOKED\tREASON\tSERIAL\tSUBJECT")
	now := time.Now()
	for _, e := range entries {
		status, err := entryStatus(e, now)
		if err != nil {
			return err
		}
		if len(statuses) > 0 && !slices.Contains(statuses, status) {
			continue
		}
		expires, err := parseIndexTime(e.expires)
		if err != nil {
			return fmt.Errorf("invalid expiry of serial %s: %w", e.serial, err)
		}
		revoked, reason := "-", "-"
		if e.revoked != "" {
			t, err := parseIndexTime(e.revoked)
			if err != nil {
				return fmt.Errorf("invalid revocation date of serial %s: %w", e.serial, err)
			}
			revoked = t.UTC().Format(displayTimeFormat)
			name, _, err := revocationReason(e.revoked)
			if err != nil {
				return fmt.Errorf("serial %s: %w", e.serial, err)
			}
			if name != "" {
				reason = name
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", status, expires.UTC().Format(displayTimeFormat), revoked, reason, e.serial, e.subject)
	}
	return tw.Flush()
}
