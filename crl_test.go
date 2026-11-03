package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeCRLAll(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"servers", "users"} {
		if err := makeCA(caDir, name+" CA", 3650, name, ""); err != nil {
			t.Fatalf("makeCA %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(caDir, "other"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := run([]string{"crl", "create", "--ca-dir", filepath.Join(caDir, "users"), "--all"}); err != nil {
		t.Fatalf("crl create --all: %v", err)
	}
	for _, dir := range []string{caDir, filepath.Join(caDir, "servers"), filepath.Join(caDir, "users")} {
		if b, err := os.ReadFile(filepath.Join(dir, crlNumberFile)); err != nil || strings.TrimSpace(string(b)) != "03" {
			t.Fatalf("crlnumber of %s is %q, %v, want 03 after the second CRL", dir, b, err)
		}
	}
	if fileExists(filepath.Join(caDir, "other", "crl.pem")) {
		t.Fatal("crl create --all wrote a CRL in a directory without a CA")
	}
	if err := run([]string{"crl", "create", "--ca-dir", filepath.Join(caDir, "servers")}); err != nil {
		t.Fatalf("crl create: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, "users", crlNumberFile)); err != nil || strings.TrimSpace(string(b)) != "03" {
		t.Fatalf("crl create without --all changed the crlnumber of another CA: %q, %v", b, err)
	}
}

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
		name, code, err := revocationReason(c.revoked)
		if err != nil || name != c.name || code != c.code {
			t.Fatalf("revocationReason(%q) = %q, %d, %v, want %q, %d", c.revoked, name, code, err, c.name, c.code)
		}
	}
	if _, _, err := revocationReason("261030120000Z,bogus"); err == nil {
		t.Fatal("revocationReason of an unknown reason succeeded, want an error")
	}
}

func TestRevokeAndCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := makeCert(name, nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	alicePath := filepath.Join(caDir, "issuing-ca", "alice_cert.pem")
	alice, err := loadCert(alicePath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	bob, err := loadCert(filepath.Join(caDir, "issuing-ca", "bob_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}

	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "noSuchReason"); err == nil {
		t.Fatal("revokeCert with an unknown reason succeeded, want an error")
	}
	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "certificateHold"); err == nil {
		t.Fatal("revokeCert with certificateHold succeeded, want an error")
	}
	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), "SUPERSEDED"); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing-ca"), ""); err != nil {
		t.Fatalf("revokeCert second run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, "issuing-ca", indexFile)); err != nil || !strings.Contains(string(b), "Z,superseded\t") {
		t.Fatalf("index.txt lacks the revocation reason superseded: %q, %v", b, err)
	}

	crlPath := filepath.Join(caDir, "issuing-ca", "crl.pem")
	for want := int64(2); want <= 3; want++ {
		if err := makeCRL(filepath.Join(caDir, "issuing-ca"), 30); err != nil {
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
