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
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

func TestStandaloneCA(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if !simpleca.FileExists(filepath.Join(caDir, "ca_cert.pem")) {
		t.Fatal("ca_cert.pem not created")
	}
	if !simpleca.FileExists(filepath.Join(caDir, "ca_bundle.pem")) {
		t.Fatal("ca_bundle.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if _, err := MakeCert("test", []string{"test.example.com", "127.0.0.1"}, caDir, "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "test_cert.pem")
	if !simpleca.FileExists(certPath) {
		t.Fatal("test_cert.pem not created in caDir")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
}

func TestTwoLevelCA(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA root: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingCert := filepath.Join(caDir, "issuing-ca", "ca_cert.pem")
	if !simpleca.FileExists(issuingCert) {
		t.Fatal("issuing-ca/ca_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), issuingCert)

	if _, err := MakeCert("test", []string{"test.example.com", "127.0.0.1"}, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing-ca", "test_cert.pem")
	if !simpleca.FileExists(certPath) {
		t.Fatal("issuing-ca/test_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	assertEKU(t, certPath, "TLS Web Server Authentication")
	assertEKU(t, certPath, "TLS Web Client Authentication")

	if err := MakePFX(certPath, filepath.Join(caDir, "issuing-ca"), "s3cr3t"); err != nil {
		t.Fatalf("makePFX: %v", err)
	}
	pfxPath := filepath.Join(caDir, "issuing-ca", "test.pfx")
	if !simpleca.FileExists(pfxPath) {
		t.Fatal("issuing-ca/test.pfx not created")
	}
	out, err := exec.Command("openssl", "pkcs12", "-in", pfxPath, "-noout", "-info",
		"-password", "pass:s3cr3t").CombinedOutput()
	if err != nil {
		t.Fatalf("PFX verification failed:\n%s", out)
	}
}

func TestRootExists(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
}

func TestPublishURLs(t *testing.T) {
	caDir := t.TempDir()
	base := "http://pki.example.com"

	if err := MakeCA(caDir, "Test CA", 3650, "", base, "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CAPublishBaseURL != base {
		t.Fatalf("%s holds base URL %q, want %q", simpleca.ConfigFile, cfg.CAPublishBaseURL, base)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := MakeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}

	issuing, err := simpleca.LoadCert(filepath.Join(caDir, "issuing-ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(issuing.IssuingCertificateURL, []string{base + "/ca_cert.crt"}) ||
		!slices.Equal(issuing.CRLDistributionPoints, []string{base + "/crl.pem"}) {
		t.Fatalf("issuing CA URLs: AIA %v CDP %v", issuing.IssuingCertificateURL, issuing.CRLDistributionPoints)
	}

	leaf, err := simpleca.LoadCert(filepath.Join(caDir, "issuing-ca", "test_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(leaf.IssuingCertificateURL, []string{base + "/issuing-ca/ca_cert.crt"}) ||
		!slices.Equal(leaf.CRLDistributionPoints, []string{base + "/issuing-ca/crl.pem"}) {
		t.Fatalf("leaf URLs: AIA %v CDP %v", leaf.IssuingCertificateURL, leaf.CRLDistributionPoints)
	}
}

func TestCADirRoles(t *testing.T) {
	caDir := t.TempDir()
	issuingDir := filepath.Join(caDir, "issuing-ca")

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := MakeCA(issuingDir, "Nested CA", 3650, "nested", "", "rsa"); err == nil {
		t.Fatal("expected ca create to refuse an issuing CA directory")
	}

	if err := RevokeCert(filepath.Join(issuingDir, "ca_cert.pem"), caDir, ""); err != nil {
		t.Fatalf("revokeCert of the issuing CA: %v", err)
	}
	if err := MakeCRL(caDir, 30); err != nil {
		t.Fatalf("makeCRL root: %v", err)
	}
	out, err := exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_cert.pem"),
		"-CRLfile", filepath.Join(caDir, "crl.pem"), filepath.Join(issuingDir, "ca_cert.pem")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "revoked") {
		t.Fatalf("expected the issuing CA to be reported revoked:\n%s", out)
	}
}

func TestInitialCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"days": {"crl": 7}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", simpleca.ConfigFile, err)
	}
	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := MakeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, dir := range []string{caDir, filepath.Join(caDir, "issuing-ca")} {
		ca, err := simpleca.LoadCert(filepath.Join(dir, "ca_cert.pem"))
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "crl.pem"))
		if err != nil {
			t.Fatalf("ca create wrote no CRL in %s: %v", dir, err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("no PEM block in the CRL of %s", dir)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		if err := crl.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("the CRL of %s is not signed by its CA: %v", dir, err)
		}
		if crl.Number.Int64() != 1 || len(crl.RevokedCertificateEntries) != 0 {
			t.Fatalf("the first CRL of %s has number %d and %d entries", dir, crl.Number, len(crl.RevokedCertificateEntries))
		}
		if days := crl.NextUpdate.Sub(crl.ThisUpdate).Hours() / 24; days != 7 {
			t.Fatalf("the first CRL of %s is valid for %v days, want days.crl, 7", dir, days)
		}
	}
	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, CRLNumberFile)); err != nil || strings.TrimSpace(string(b)) != "02" {
		t.Fatalf("ca create of an existing CA changed its CRL number: %q, %v", b, err)
	}
}

func TestKebabCaseNames(t *testing.T) {
	caDir := t.TempDir()
	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"Servers", "lab_servers", "lab--servers", "-lab", "lab-", "lab.servers"} {
		if err := MakeCA(caDir, "Bad CA", 3650, name, "", "rsa"); err == nil || !strings.Contains(err.Error(), "kebab-case") {
			t.Fatalf("makeCA --issuing-ca %q: %v, want a kebab-case error", name, err)
		}
	}
	if err := MakeCA(caDir, "Lab Servers CA", 0, "lab-servers2", "", "rsa"); err != nil {
		t.Fatalf("makeCA --issuing-ca lab-servers2: %v", err)
	}
	issuingDir := filepath.Join(caDir, "lab-servers2")

	// A kebab-case type works with cert create and with openssl ca through openssl.cnf.
	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile),
		[]byte(`{"types": {"web-server": {"key_usage": ["digitalSignature"], "ext_key_usage": ["serverAuth"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MakeCert("web.example.com", nil, issuingDir, "", "web-server", 30, nil, nil, ""); err != nil {
		t.Fatalf("makeCert --type web-server: %v", err)
	}
	conf, err := WriteOpenSSLConf(issuingDir)
	if err != nil {
		t.Fatalf("writeOpenSSLConf: %v", err)
	}
	csrPath := filepath.Join(t.TempDir(), "api.csr")
	if out, err := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", os.DevNull, "-subj", "/CN=api.example.com", "-out", csrPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	certPath := filepath.Join(t.TempDir(), "api_cert.pem")
	if out, err := exec.Command("openssl", "ca", "-batch", "-config", conf, "-extensions", "ext_web-server",
		"-in", csrPath, "-out", certPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -extensions ext_web-server: %v\n%s", err, out)
	}
	assertEKU(t, certPath, "TLS Web Server Authentication")
}
