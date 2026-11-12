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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestOpenSSLCA(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := MakeCert(name, nil, caDir, "", "server", 365, nil, nil, ""); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	alice, err := simpleca.LoadCert(filepath.Join(caDir, "alice_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	bob, err := simpleca.LoadCert(filepath.Join(caDir, "bob_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if err := RevokeCert(filepath.Join(caDir, "alice_cert.pem"), caDir, "keyCompromise"); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}

	cnf := filepath.Join(t.TempDir(), "openssl.cnf")
	if err := os.WriteFile(cnf, []byte("[ca]\ndefault_ca = test\n\n[test]\n"+
		"database = "+filepath.Join(caDir, indexFile)+"\n"+
		"crlnumber = "+filepath.Join(caDir, CRLNumberFile)+"\n"+
		"certificate = "+filepath.Join(caDir, "ca_cert.pem")+"\n"+
		"private_key = "+filepath.Join(caDir, "ca_key.pem")+"\n"+
		"default_md = sha256\ndefault_crl_days = 1\n"), 0o644); err != nil {
		t.Fatalf("write openssl.cnf: %v", err)
	}
	if out, err := exec.Command("openssl", "ca", "-config", cnf, "-revoke", filepath.Join(caDir, "bob_cert.pem"),
		"-crl_reason", "CACompromise").CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -revoke:\n%s", out)
	}

	// Both CRLs, of openssl ca and of crl create, list alice and bob with their reasons.
	opensslCRL := filepath.Join(t.TempDir(), "crl.pem")
	if out, err := exec.Command("openssl", "ca", "-config", cnf, "-gencrl", "-out", opensslCRL).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -gencrl:\n%s", out)
	}
	if err := MakeCRL(caDir, 30); err != nil {
		t.Fatalf("makeCRL: %v", err)
	}
	for i, crlPath := range []string{opensslCRL, filepath.Join(caDir, "crl.pem")} {
		b, err := os.ReadFile(crlPath)
		if err != nil {
			t.Fatalf("read CRL: %v", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("no PEM block in %s", crlPath)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		reasons := map[string]int{}
		for _, e := range crl.RevokedCertificateEntries {
			reasons[SerialHex(e.SerialNumber)] = e.ReasonCode
		}
		if len(reasons) != 2 || reasons[SerialHex(alice.SerialNumber)] != 1 || reasons[SerialHex(bob.SerialNumber)] != 2 {
			t.Fatalf("%s lists the reason codes %v, want alice keyCompromise (1) and bob CACompromise (2)", crlPath, reasons)
		}
		if want := int64(2 + i); crl.Number.Int64() != want {
			t.Fatalf("%s has number %d, want %d", crlPath, crl.Number, want)
		}
	}
}

func TestWriteOpenSSLConf(t *testing.T) {
	caDir := t.TempDir()
	issuingDir := filepath.Join(caDir, "issuing-ca")

	if err := MakeCA(caDir, "Test CA", 3650, "", "http://pki.example.com", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg.Days.Cert = 90
	ekus := []string{"clientAuth", "ipsecUser", "1.3.6.1.4.1.99999.10"}
	cfg.Types = map[string]simpleca.TypeConfig{"device": {ExtKeyUsage: &ekus}}
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	rootConf, err := WriteOpenSSLConf(caDir)
	if err != nil {
		t.Fatalf("writeOpenSSLConf root: %v", err)
	}
	b, err := os.ReadFile(rootConf)
	if err != nil {
		t.Fatalf("read %s: %v", rootConf, err)
	}
	if !strings.Contains(string(b), "[ ext_issuing_ca ]") {
		t.Fatalf("the configuration of the root CA lacks ext_issuing_ca:\n%s", b)
	}
	conf, err := WriteOpenSSLConf(issuingDir)
	if err != nil {
		t.Fatalf("writeOpenSSLConf issuing: %v", err)
	}
	b, err = os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read %s: %v", conf, err)
	}
	for _, s := range []string{"default_days     = 90", "[ ext_device ]", "[ ext_none ]", "[ ext_server ]", "[ ext_user ]",
		"extendedKeyUsage       = clientAuth, 1.3.6.1.5.5.7.3.7, 1.3.6.1.4.1.99999.10",
		"crlDistributionPoints  = URI:http://pki.example.com/issuing-ca/crl.pem"} {
		if !strings.Contains(string(b), s) {
			t.Fatalf("the configuration of the issuing CA lacks %q:\n%s", s, b)
		}
	}
	if strings.Contains(string(b), "ext_issuing_ca") {
		t.Fatalf("the configuration of the issuing CA has ext_issuing_ca:\n%s", b)
	}

	work := t.TempDir()
	csr := filepath.Join(work, "dev.csr")
	certPath := filepath.Join(work, "dev_cert.pem")
	if out, err := exec.Command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(work, "dev_key.pem"),
		"-subj", "/CN=dev1.example.com", "-addext", "subjectAltName=DNS:dev1.example.com", "-out", csr).CombinedOutput(); err != nil {
		t.Fatalf("openssl req:\n%s", out)
	}
	if out, err := exec.Command("openssl", "ca", "-batch", "-config", conf, "-extensions", "ext_device",
		"-in", csr, "-out", certPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca:\n%s", out)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	crt, err := simpleca.LoadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(crt.DNSNames, []string{"dev1.example.com"}) ||
		!slices.Equal(crt.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageIPSECUser}) ||
		len(crt.UnknownExtKeyUsage) != 1 || !slices.Equal(crt.CRLDistributionPoints, []string{"http://pki.example.com/issuing-ca/crl.pem"}) {
		t.Fatalf("certificate of openssl ca: DNS %v, EKUs %v %v, CDP %v", crt.DNSNames, crt.ExtKeyUsage, crt.UnknownExtKeyUsage, crt.CRLDistributionPoints)
	}

	var list bytes.Buffer
	if err := ListCerts(&list, issuingDir, nil); err != nil {
		t.Fatalf("listCerts: %v", err)
	}
	if !strings.Contains(list.String(), SerialHex(crt.SerialNumber)) {
		t.Fatalf("the certificate of openssl ca is not listed:\n%s", list.String())
	}
	if err := RevokeCert(certPath, issuingDir, ""); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if out, err := exec.Command("openssl", "ca", "-config", conf, "-gencrl", "-out", filepath.Join(work, "crl.pem")).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -gencrl:\n%s", out)
	}
	if out, err := exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_bundle.pem"),
		"-CRLfile", filepath.Join(work, "crl.pem"), certPath).CombinedOutput(); err == nil || !strings.Contains(string(out), "revoked") {
		t.Fatalf("expected the certificate to be reported revoked:\n%s", out)
	}
}
