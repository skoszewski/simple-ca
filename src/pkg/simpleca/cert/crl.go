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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// CRLReasons are the revocation reasons of index.txt in the names of "openssl ca", with their
// reason codes of RFC 5280; cert revoke takes the first six, and the last three are the pseudo
// reasons OpenSSL writes with an extra field.
var CRLReasons = []struct {
	Name string
	Code int
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

// RevocationReason returns the name and the reason code of the reason in the revocation field of
// an index.txt entry, date[,reason[,extra]], and "" when it has none.
func RevocationReason(revoked string) (string, int, error) {
	_, rest, found := strings.Cut(revoked, ",")
	if !found {
		return "", 0, nil
	}
	name, _, _ := strings.Cut(rest, ",")
	for _, r := range CRLReasons {
		if strings.EqualFold(r.Name, name) {
			return r.Name, r.Code, nil
		}
	}
	return "", 0, fmt.Errorf("unknown revocation reason %q", name)
}

// MakeCRL writes crl.pem of the CA in caDir, listing the certificates its index.txt marks as
// revoked, with the CRL number of its crlnumber, which it then raises.
func MakeCRL(caDir string, days int) error {
	if days < 1 {
		return errors.New("the validity in days must be a positive integer")
	}

	signingDir := caDir
	caCertPath := filepath.Join(signingDir, "ca_cert.pem")
	caKeyPath := filepath.Join(signingDir, "ca_key.pem")
	if !simpleca.FileExists(caCertPath) || !simpleca.FileExists(caKeyPath) {
		return fmt.Errorf("CA certificate or key not found in %q", signingDir)
	}
	caCert, err := simpleca.LoadCert(caCertPath)
	if err != nil {
		return err
	}
	if len(caCert.SubjectKeyId) == 0 {
		return fmt.Errorf("CA certificate %q has no subject key identifier", caCertPath)
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return err
	}
	entries, err := ReadIndex(signingDir)
	if err != nil {
		return err
	}
	var revoked []x509.RevocationListEntry
	for _, e := range entries {
		if e.Status != "R" {
			continue
		}
		serial, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return fmt.Errorf("invalid serial %q in %q", e.Serial, filepath.Join(signingDir, indexFile))
		}
		revokedAt, err := ParseIndexTime(e.Revoked)
		if err != nil {
			return fmt.Errorf("invalid revocation date of serial %s in %q: %w", e.Serial, filepath.Join(signingDir, indexFile), err)
		}
		_, reasonCode, err := RevocationReason(e.Revoked)
		if err != nil {
			return fmt.Errorf("serial %s in %q: %w", e.Serial, filepath.Join(signingDir, indexFile), err)
		}
		revoked = append(revoked, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revokedAt, ReasonCode: reasonCode})
	}

	numberPath := filepath.Join(signingDir, CRLNumberFile)
	number := big.NewInt(1)
	b, err := os.ReadFile(numberPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if _, ok := number.SetString(strings.TrimSpace(string(b)), 16); !ok {
			return fmt.Errorf("invalid CRL number in %q", numberPath)
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
	return os.WriteFile(numberPath, []byte(SerialHex(next)+"\n"), 0o644)
}

// AuditCRL audits the CRL of the CA in caDir that MakeCRL wrote, by its number, with the actor
// pairs of args.
func AuditCRL(caDir string, args ...any) {
	number := ""
	if b, err := os.ReadFile(filepath.Join(caDir, "crl.pem")); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
				number = crl.Number.String()
			}
		}
	}
	simpleca.Audit(caDir, "crl.write", append([]any{"number", number}, args...)...)
}

// MarkRevoked marks the certificate with the serial number serial as revoked in index.txt of the
// CA in caDir, for reason, a name of CRLReasons, or for no reason when empty; it returns false
// when the certificate was revoked already.
func MarkRevoked(caDir, serial, reason string) (bool, error) {
	unlock, err := simpleca.LockFile(filepath.Join(caDir, indexFile))
	if err != nil {
		return false, err
	}
	defer unlock()
	entries, err := ReadIndex(caDir)
	if err != nil {
		return false, err
	}
	i := slices.IndexFunc(entries, func(e IndexEntry) bool { return strings.EqualFold(e.Serial, serial) })
	if i < 0 {
		return false, fmt.Errorf("certificate with serial %q not found in %q", serial, filepath.Join(caDir, indexFile))
	}
	if entries[i].Status == "R" {
		return false, nil
	}
	entries[i].Status = "R"
	entries[i].Revoked = time.Now().UTC().Format(utcTimeFormat)
	if reason != "" {
		entries[i].Revoked += "," + reason
	}
	return true, writeIndex(caDir, entries)
}

// RevokeCert marks the certificate at certPath as revoked in index.txt of the CA in caDir, for
// reason, one of the first six of CRLReasons in any letter case, or for no reason when empty, and
// audits it as cert revoke.
func RevokeCert(certPath, caDir, reason string) error {
	if reason != "" {
		var names []string
		for _, r := range CRLReasons[:6] {
			names = append(names, r.Name)
		}
		i := slices.IndexFunc(names, func(name string) bool { return strings.EqualFold(name, reason) })
		if i < 0 {
			return fmt.Errorf("unknown revocation reason %q: must be one of %s", reason, strings.Join(names, ", "))
		}
		reason = names[i]
	}
	if !simpleca.FileExists(certPath) {
		return fmt.Errorf("certificate not found: %q", certPath)
	}
	signingDir := caDir
	if !DirExists(signingDir) {
		return fmt.Errorf("CA directory not found: %q", signingDir)
	}

	cert, err := simpleca.LoadCert(certPath)
	if err != nil {
		return err
	}
	serial := SerialHex(cert.SerialNumber)
	revoked, err := MarkRevoked(signingDir, serial, reason)
	if err != nil {
		return err
	}
	if !revoked {
		return fmt.Errorf("certificate %s is revoked already", serial)
	}
	simpleca.Audit(signingDir, "cert.revoke", "serial", serial, "reason", reason, "via", "cli", "actor", simpleca.CLIActor())
	if reason != "" {
		fmt.Printf("Certificate %q (serial %s) marked as revoked, reason %s.\n", certPath, serial, reason)
	} else {
		fmt.Printf("Certificate %q (serial %s) marked as revoked.\n", certPath, serial)
	}
	return nil
}
