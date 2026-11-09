package main

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
)

func TestStandaloneCA(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) {
		t.Fatal("ca_cert.pem not created")
	}
	if !fileExists(filepath.Join(caDir, "ca_bundle.pem")) {
		t.Fatal("ca_bundle.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if _, err := makeCert("test", []string{"test.example.com", "127.0.0.1"}, caDir, "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "test_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("test_cert.pem not created in caDir")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
}

func TestTwoLevelCA(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test Root CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA root: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingCert := filepath.Join(caDir, "issuing-ca", "ca_cert.pem")
	if !fileExists(issuingCert) {
		t.Fatal("issuing-ca/ca_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), issuingCert)

	if _, err := makeCert("test", []string{"test.example.com", "127.0.0.1"}, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing-ca", "test_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("issuing-ca/test_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	assertEKU(t, certPath, "TLS Web Server Authentication")
	assertEKU(t, certPath, "TLS Web Client Authentication")

	if err := makePFX(certPath, filepath.Join(caDir, "issuing-ca"), "s3cr3t"); err != nil {
		t.Fatalf("makePFX: %v", err)
	}
	pfxPath := filepath.Join(caDir, "issuing-ca", "test.pfx")
	if !fileExists(pfxPath) {
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

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
}

func TestPublishURLs(t *testing.T) {
	caDir := t.TempDir()
	base := "http://pki.example.com"

	if err := makeCA(caDir, "Test CA", 3650, "", base, "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CAPublishBaseURL != base {
		t.Fatalf("%s holds base URL %q, want %q", configFile, cfg.CAPublishBaseURL, base)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := makeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}

	issuing, err := loadCert(filepath.Join(caDir, "issuing-ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(issuing.IssuingCertificateURL, []string{base + "/ca_cert.crt"}) ||
		!slices.Equal(issuing.CRLDistributionPoints, []string{base + "/crl.pem"}) {
		t.Fatalf("issuing CA URLs: AIA %v CDP %v", issuing.IssuingCertificateURL, issuing.CRLDistributionPoints)
	}

	leaf, err := loadCert(filepath.Join(caDir, "issuing-ca", "test_cert.pem"))
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

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	rootDir, name, err := locateCA(issuingDir)
	if err != nil || name != "issuing-ca" || filepath.Base(rootDir) != filepath.Base(caDir) {
		t.Fatalf("locateCA(%s) = %q, %q, %v", issuingDir, rootDir, name, err)
	}
	if _, name, err := locateCA(caDir); err != nil || name != "" {
		t.Fatalf("locateCA(%s) names an issuing CA %q, %v", caDir, name, err)
	}
	if err := makeCA(issuingDir, "Nested CA", 3650, "nested", "", "rsa"); err == nil {
		t.Fatal("expected ca create to refuse an issuing CA directory")
	}

	if err := revokeCert(filepath.Join(issuingDir, "ca_cert.pem"), caDir, ""); err != nil {
		t.Fatalf("revokeCert of the issuing CA: %v", err)
	}
	if err := makeCRL(caDir, 30); err != nil {
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

	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"days": {"crl": 7}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, dir := range []string{caDir, filepath.Join(caDir, "issuing-ca")} {
		ca, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
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
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, crlNumberFile)); err != nil || strings.TrimSpace(string(b)) != "02" {
		t.Fatalf("ca create of an existing CA changed its CRL number: %q, %v", b, err)
	}
}

func TestCAURLOption(t *testing.T) {
	for _, option := range []string{"--ca-url", "--ca-publish-base-url"} {
		caDir := t.TempDir()
		if err := run([]string{"ca", "create", "--ca-dir", caDir, option, "http://pki.example.com", "Test CA"}); err != nil {
			t.Fatalf("ca create %s: %v", option, err)
		}
		cfg, err := loadConfig(caDir)
		if err != nil || cfg.CAPublishBaseURL != "http://pki.example.com" {
			t.Fatalf("ca_publish_base_url after ca create %s: %q, %v", option, cfg.CAPublishBaseURL, err)
		}
	}

	// The usage lists --ca-url and leaves out its former name.
	fs := newFlagSet("ca create", "CA_NAME", "Create a root or issuing CA.")
	url := fs.String("ca-url", "", "base `URL`")
	fs.StringVar(url, "ca-publish-base-url", "", "former name of --ca-url")
	fs.Int("days", 3650, "validity period in `days`")
	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()
	if !strings.Contains(out.String(), "-ca-url URL") || strings.Contains(out.String(), "publish") ||
		!strings.Contains(out.String(), "(default 3650)") {
		t.Fatalf("usage:\n%s\nwant --ca-url and the defaults, without --ca-publish-base-url", out.String())
	}
}
