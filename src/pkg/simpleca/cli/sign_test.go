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

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

func TestSign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()

	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
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
		if entries, err := cert.ReadIndex(issuingDir); err != nil || len(entries) != 0 {
			t.Fatalf("signCSR answered %q recorded %+v, %v", answer, entries, err)
		}
	}
	if _, err := signCSR(csrPath, issuingDir, "", "server", 30, []string{"codeSigning"}, nil, false, strings.NewReader("Yes\n")); err != nil {
		t.Fatalf("signCSR: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	crt, err := simpleca.LoadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if got := cert.NameString(crt.Subject); got != "/C=PL/O=Example/CN=web.example.com" {
		t.Fatalf("subject %q, want that of the request", got)
	}
	if !slices.Equal(crt.DNSNames, []string{"web.example.com"}) || len(crt.IPAddresses) != 1 ||
		crt.IPAddresses[0].String() != "192.0.2.1" {
		t.Fatalf("SANs %v %v, want those of the request", crt.DNSNames, crt.IPAddresses)
	}
	text, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v\n%s", err, text)
	}
	if !strings.Contains(string(text), "Registered ID:1.3.6.1.4.1.99999.1") {
		t.Fatalf("registeredID SAN of the request not copied:\n%s", text)
	}
	if crt.IsCA || crt.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("IsCA %v, key usage %v, want those of the server type", crt.IsCA, crt.KeyUsage)
	}
	if !slices.Equal(crt.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning}) {
		t.Fatalf("extended key usage %v, want those of the server type and codeSigning", crt.ExtKeyUsage)
	}
	if days := crt.NotAfter.Sub(crt.NotBefore).Hours() / 24; days != 30 {
		t.Fatalf("valid for %v days, want 30", days)
	}
	entries, err := cert.ReadIndex(issuingDir)
	if err != nil {
		t.Fatalf("readIndex: %v", err)
	}
	if len(entries) != 1 || entries[0].Serial != cert.SerialHex(crt.SerialNumber) {
		t.Fatalf("index.txt entries %+v, want the signed certificate", entries)
	}

	// Signing again replaces the file, and index.txt lists both certificates.
	again, err := signCSR(csrPath, issuingDir, "", "server", 30, nil, nil, true, nil)
	if err != nil {
		t.Fatalf("signing again: %v", err)
	}
	if replaced, err := simpleca.LoadCert(certPath); err != nil || replaced.SerialNumber.Cmp(again.SerialNumber) != 0 ||
		replaced.SerialNumber.Cmp(crt.SerialNumber) == 0 {
		t.Fatalf("%s after signing again: %v, want the new certificate", certPath, err)
	}
	if entries, err := cert.ReadIndex(issuingDir); err != nil || len(entries) != 2 {
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

func TestCertSignCommand(t *testing.T) {
	caDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"days": {"cert": 45}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "ec"); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPath := filepath.Join(t.TempDir(), "api.csr")
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(caDir, "api_cert.pem")

	// cert sign takes the days of simple-ca.json, and adds the usages of --eku and --ku.
	if err := run([]string{"cert", "sign", "--ca-dir", caDir, "--force", "--eku", "codeSigning",
		"--ku", "keyAgreement, contentCommitment", csrPath}); err != nil {
		t.Fatalf("cert sign: %v", err)
	}
	crt, err := simpleca.LoadCert(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if days := crt.NotAfter.Sub(crt.NotBefore).Hours() / 24; days != 45 {
		t.Errorf("valid for %v days, want days.cert, 45", days)
	}
	if !slices.Contains(crt.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) ||
		crt.KeyUsage&(x509.KeyUsageKeyAgreement|x509.KeyUsageContentCommitment) != x509.KeyUsageKeyAgreement|x509.KeyUsageContentCommitment {
		t.Errorf("extended key usage %v, key usage %v, want codeSigning, keyAgreement and contentCommitment added", crt.ExtKeyUsage, crt.KeyUsage)
	}
	entries, err := simpleca.ReadAudit(caDir)
	if err != nil || len(entries) == 0 || entries[len(entries)-1].Event != "cert.issue" {
		t.Errorf("audit records %+v, %v, want cert.issue last", entries, err)
	}

	// --days replaces days.cert; an empty key usage and a missing CSR are refused.
	if err := run([]string{"cert", "sign", "--ca-dir", caDir, "--force", "--days", "10", csrPath}); err != nil {
		t.Fatalf("cert sign --days 10: %v", err)
	}
	if crt, err := simpleca.LoadCert(certPath); err != nil || crt.NotAfter.Sub(crt.NotBefore).Hours()/24 != 10 {
		t.Errorf("cert sign --days 10: %v, want 10 days", err)
	}
	if err := run([]string{"cert", "sign", "--ca-dir", caDir, "--force", "--ku", "keyAgreement,,contentCommitment", csrPath}); !errors.Is(err, ErrUsage) {
		t.Errorf("cert sign with an empty key usage: %v, want it refused", err)
	}
	if err := run([]string{"cert", "sign", "--ca-dir", caDir, "--force", filepath.Join(t.TempDir(), "missing.csr")}); err == nil {
		t.Error("cert sign of a missing CSR succeeded, want an error")
	}
}

func TestDurationVar(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	valid := DurationVar(fs, "valid", time.Hour, "validity `period`")
	if f := fs.Lookup("valid"); f == nil || f.Value.String() != simpleca.DurationText(time.Hour) || f.DefValue != f.Value.String() {
		t.Fatalf("the flag valid: %+v, want the default %q", f, simpleca.DurationText(time.Hour))
	}
	if err := fs.Parse([]string{"--valid", "8h"}); err != nil || *valid != 8*time.Hour {
		t.Errorf("--valid 8h: %v, %v, want 8h", *valid, err)
	}
	if fs.Lookup("valid").Value.String() != simpleca.DurationText(8*time.Hour) {
		t.Errorf("String of 8h: %q", fs.Lookup("valid").Value.String())
	}
	if err := fs.Set("valid", "soon"); err == nil || *valid != 8*time.Hour {
		t.Errorf("--valid soon: %v, %v, want an error and 8h kept", *valid, err)
	}
}
