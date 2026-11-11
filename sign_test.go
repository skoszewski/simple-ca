package main

import (
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

func TestSign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	csrPath := filepath.Join(csrDir, "web.csr")
	out, err := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
		"-nodes", "-keyout", filepath.Join(csrDir, "web_key.pem"), "-out", csrPath,
		"-subj", "/C=PL/O=Example/CN=web.example.com",
		"-addext", "subjectAltName=DNS:web.example.com,IP:192.0.2.1,RID:1.3.6.1.4.1.99999.1",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=keyCertSign,cRLSign",
		"-addext", "extendedKeyUsage=timeStamping").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}

	certPath := filepath.Join(issuingDir, "web_cert.pem")
	for _, answer := range []string{"n\n", "\n", ""} {
		if _, err := signCSR(csrPath, issuingDir, "", "server", 30, nil, nil, false, strings.NewReader(answer)); err == nil {
			t.Fatalf("signCSR answered %q succeeded, want an error", answer)
		}
		if simpleca.FileExists(certPath) {
			t.Fatalf("signCSR answered %q wrote %s", answer, certPath)
		}
		if entries, err := readIndex(issuingDir); err != nil || len(entries) != 0 {
			t.Fatalf("signCSR answered %q recorded %+v, %v", answer, entries, err)
		}
	}
	if _, err := signCSR(csrPath, issuingDir, "", "server", 30, []string{"codeSigning"}, nil, false, strings.NewReader("Yes\n")); err != nil {
		t.Fatalf("signCSR: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := simpleca.LoadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if got := nameString(cert.Subject); got != "/C=PL/O=Example/CN=web.example.com" {
		t.Fatalf("subject %q, want that of the request", got)
	}
	if !slices.Equal(cert.DNSNames, []string{"web.example.com"}) || len(cert.IPAddresses) != 1 ||
		cert.IPAddresses[0].String() != "192.0.2.1" {
		t.Fatalf("SANs %v %v, want those of the request", cert.DNSNames, cert.IPAddresses)
	}
	text, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v\n%s", err, text)
	}
	if !strings.Contains(string(text), "Registered ID:1.3.6.1.4.1.99999.1") {
		t.Fatalf("registeredID SAN of the request not copied:\n%s", text)
	}
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("IsCA %v, key usage %v, want those of the server type", cert.IsCA, cert.KeyUsage)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}) {
		t.Fatalf("extended key usage %v, want those of the server type and codeSigning", cert.ExtKeyUsage)
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; days != 30 {
		t.Fatalf("valid for %v days, want 30", days)
	}
	entries, err := readIndex(issuingDir)
	if err != nil {
		t.Fatalf("readIndex: %v", err)
	}
	if len(entries) != 1 || entries[0].serial != serialHex(cert.SerialNumber) {
		t.Fatalf("index.txt entries %+v, want the signed certificate", entries)
	}

	// Signing again replaces the file, and index.txt lists both certificates.
	again, err := signCSR(csrPath, issuingDir, "", "server", 30, nil, nil, true, nil)
	if err != nil {
		t.Fatalf("signing again: %v", err)
	}
	if replaced, err := simpleca.LoadCert(certPath); err != nil || replaced.SerialNumber.Cmp(again.SerialNumber) != 0 ||
		replaced.SerialNumber.Cmp(cert.SerialNumber) == 0 {
		t.Fatalf("%s after signing again: %v, want the new certificate", certPath, err)
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 2 {
		t.Fatalf("index.txt after signing again: %+v, %v, want both certificates", entries, err)
	}
	if _, err := signCSR(certPath, issuingDir, t.TempDir(), "server", 30, nil, nil, true, nil); err == nil {
		t.Fatal("signing a certificate file succeeded, want an error")
	}
	forceDir := t.TempDir()
	if _, err := signCSR(csrPath, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err != nil {
		t.Fatalf("signCSR with force: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(forceDir, "web_cert.pem"))

	for _, c := range []struct{ file, cert string }{{"my web.v2.csr", "my_web_v2_cert.pem"}, {"db", "db_cert.pem"}} {
		renamed := filepath.Join(csrDir, c.file)
		if err := os.Link(csrPath, renamed); err != nil {
			t.Fatalf("link %s: %v", renamed, err)
		}
		if _, err := signCSR(renamed, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err != nil {
			t.Fatalf("signCSR %s: %v", c.file, err)
		}
		verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(forceDir, c.cert))
	}
	empty := filepath.Join(csrDir, "+.csr")
	if err := os.Link(csrPath, empty); err != nil {
		t.Fatalf("link %s: %v", empty, err)
	}
	if _, err := signCSR(empty, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err == nil {
		t.Fatal("signing +.csr succeeded, want an error for the empty file name")
	}
}
