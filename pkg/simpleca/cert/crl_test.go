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
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

func TestRevocationReason(t *testing.T) {
	for _, c := range []struct {
		revoked, name string
		code          int
	}{
		{"261030120000Z", "", 0},
		{"261030120000Z,unspecified", "unspecified", 0},
		{"261030120000Z,superseded", "superseded", 4},
		{"261030120000Z,keyTime,20261029120000Z", "keyTime", 1},
		{"261030120000Z,holdInstruction,1.2.840.10040.2.2", "holdInstruction", 6},
		{"261030120000Z,removeFromCRL", "removeFromCRL", 8},
	} {
		name, code, err := RevocationReason(c.revoked)
		if err != nil || name != c.name || code != c.code {
			t.Fatalf("revocationReason(%q) = %q, %d, %v, want %q, %d", c.revoked, name, code, err, c.name, c.code)
		}
	}
	if _, _, err := RevocationReason("261030120000Z,bogus"); err == nil {
		t.Fatal("revocationReason of an unknown reason succeeded, want an error")
	}
}

func TestRevokeAndCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := MakeCert(name, nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	alicePath := filepath.Join(caDir, "issuing-ca", "alice_cert.pem")
	alice, err := simpleca.LoadCert(alicePath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	bob, err := simpleca.LoadCert(filepath.Join(caDir, "issuing-ca", "bob_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}

	if err := RevokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "noSuchReason"); err == nil {
		t.Fatal("revokeCert with an unknown reason succeeded, want an error")
	}
	if err := RevokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "certificateHold"); err == nil {
		t.Fatal("revokeCert with certificateHold succeeded, want an error")
	}
	if err := RevokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "SUPERSEDED"); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if err := RevokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), ""); err == nil || !strings.Contains(err.Error(), "revoked already") {
		t.Fatalf("revokeCert second run: %v, want an error for the revoked certificate", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, "issuing-ca", indexFile)); err != nil || !strings.Contains(string(b), "Z,superseded\t") {
		t.Fatalf("index.txt lacks the revocation reason superseded: %q, %v", b, err)
	}

	crlPath := filepath.Join(caDir, "issuing-ca", "crl.pem")
	for want := int64(2); want <= 3; want++ {
		if err := MakeCRL(filepath.Join(caDir, "issuing-ca"), 30); err != nil {
			t.Fatalf("makeCRL: %v", err)
		}
		b, err := os.ReadFile(crlPath)
		if err != nil {
			t.Fatalf("read CRL: %v", err)
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "X509 CRL" {
			t.Fatal("no X509 CRL PEM block")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if crl.Number.Int64() != want {
			t.Fatalf("CRL number %d, want %d", crl.Number, want)
		}
		if len(crl.RevokedCertificateEntries) != 1 ||
			crl.RevokedCertificateEntries[0].SerialNumber.Cmp(alice.SerialNumber) != 0 ||
			crl.RevokedCertificateEntries[0].ReasonCode != 4 {
			t.Fatalf("CRL entries %+v, want only alice, superseded (4)", crl.RevokedCertificateEntries)
		}
	}

	out, err := exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_bundle.pem"),
		"-CRLfile", crlPath, alicePath).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "revoked") {
		t.Fatalf("expected alice to be reported revoked:\n%s", out)
	}
	out, err = exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_bundle.pem"),
		"-CRLfile", crlPath, filepath.Join(caDir, "issuing-ca", "bob_cert.pem")).CombinedOutput()
	if err != nil {
		t.Fatalf("bob (serial %X) should verify:\n%s", bob.SerialNumber, out)
	}
}
