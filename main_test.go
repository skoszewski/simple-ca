package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func verifyCert(t *testing.T, bundle, cert string) {
	t.Helper()
	out, err := exec.Command("openssl", "verify", "-CAfile", bundle, cert).CombinedOutput()
	if err != nil {
		t.Fatalf("certificate verification failed for %s:\n%s", cert, out)
	}
}

func assertEKU(t *testing.T, cert, eku string) {
	t.Helper()
	out, err := exec.Command("openssl", "x509", "-in", cert, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 failed: %v", err)
	}
	if !strings.Contains(string(out), eku) {
		t.Fatalf("EKU %q not found in %s", eku, cert)
	}
}

func TestStandaloneCA(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if !fileExists(filepath.Join(caDir, "ca_cert.pem")) {
		t.Fatal("ca_cert.pem not created")
	}
	if !fileExists(filepath.Join(caDir, "ca_bundle.pem")) {
		t.Fatal("ca_bundle.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if err := makeCert("test", []string{"test.example.com", "127.0.0.1"}, caDir, "", "server", 365, nil, nil); err != nil {
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

	if err := makeCA(caDir, "Test Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA root: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(caDir, "ca_cert.pem"))

	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingCert := filepath.Join(caDir, "issuing_ca", "ca_cert.pem")
	if !fileExists(issuingCert) {
		t.Fatal("issuing_ca/ca_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), issuingCert)

	if err := makeCert("test", []string{"test.example.com", "127.0.0.1"}, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing_ca", "test_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("issuing_ca/test_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	assertEKU(t, certPath, "TLS Web Server Authentication")
	assertEKU(t, certPath, "TLS Web Client Authentication")

	if err := makePFX(certPath, filepath.Join(caDir, "issuing_ca"), "s3cr3t"); err != nil {
		t.Fatalf("makePFX: %v", err)
	}
	pfxPath := filepath.Join(caDir, "issuing_ca", "test.pfx")
	if !fileExists(pfxPath) {
		t.Fatal("issuing_ca/test.pfx not created")
	}
	out, err := exec.Command("openssl", "pkcs12", "-in", pfxPath, "-noout", "-info",
		"-password", "pass:s3cr3t").CombinedOutput()
	if err != nil {
		t.Fatalf("PFX verification failed:\n%s", out)
	}
}

func TestUserCert(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}

	if err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing_ca"), "", "user", 365, nil, nil); err != nil {
		t.Fatalf("makeCert user: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing_ca", "Alice Example_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("Alice Example_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	assertEKU(t, certPath, "TLS Web Client Authentication")
	assertEKU(t, certPath, "E-mail Protection")
	assertEKU(t, certPath, "Code Signing")
}

func TestCertDirOverride(t *testing.T) {
	caDir := t.TempDir()
	certDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCert("test", []string{"test.example.com"}, caDir, certDir, "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(certDir, "test_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("test_cert.pem not created in certDir override")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
}

func TestServerSANs(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCert("web.example.com", []string{"web", "www.example.com", "192.0.2.1", "2001:db8::1", "1.3.6.1.4.1.99999.1"},
		caDir, "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "web_cert.pem")
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if cert.Subject.CommonName != "web.example.com" || !slices.Equal(cert.DNSNames, []string{"web.example.com", "web", "www.example.com"}) {
		t.Fatalf("CN %q, DNS names %v", cert.Subject.CommonName, cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 || cert.IPAddresses[0].String() != "192.0.2.1" || cert.IPAddresses[1].String() != "2001:db8::1" {
		t.Fatalf("IP addresses %v", cert.IPAddresses)
	}
	out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text:\n%s", out)
	}
	if !strings.Contains(string(out), "Registered ID:1.3.6.1.4.1.99999.1") {
		t.Fatalf("registeredID SAN missing:\n%s", out)
	}
	var b bytes.Buffer
	if err := showCert(&b, certPath); err != nil {
		t.Fatalf("showCert: %v", err)
	}
	if !strings.Contains(b.String(), "1.3.6.1.4.1.99999.1") {
		t.Fatalf("info lacks the registeredID SAN:\n%s", b.String())
	}

	for _, c := range []struct {
		cn   string
		sans []string
	}{
		{"192.0.2.1", nil},
		{"1.3.6.1.4.1.99999.1", nil},
		{"Web Server", nil},
		{"host.example.com", []string{"admin@example.com"}},
		{"host.example.com", []string{"fe80::1%en0"}},
		{"host.example.com", []string{"under_score.example.com"}},
	} {
		if err := makeCert(c.cn, c.sans, caDir, "", "server", 365, nil, nil); err == nil {
			t.Fatalf("expected an error for CN %q and SANs %v", c.cn, c.sans)
		}
	}
}

func TestUserSubjects(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, c := range []struct {
		args    []string
		file    string
		subject string
		emails  []string
		oid     string
	}{
		{[]string{"Alice Example", "alice@example.com", "a.example@example.org", "1.3.6.1.4.1.99999.2"}, "Alice Example",
			"/CN=Alice Example/emailAddress=alice@example.com", []string{"alice@example.com", "a.example@example.org"}, "1.3.6.1.4.1.99999.2"},
		{[]string{"bob@example.com", "Bob"}, "Bob", "/CN=Bob/emailAddress=bob@example.com", []string{"bob@example.com"}, ""},
		{[]string{"carol@example.com"}, "carol", "/emailAddress=carol@example.com", []string{"carol@example.com"}, ""},
		{[]string{"Dave"}, "Dave", "/CN=Dave", nil, ""},
	} {
		if err := makeCert(c.args[0], c.args[1:], caDir, "", "user", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %v: %v", c.args, err)
		}
		certPath := filepath.Join(caDir, c.file+"_cert.pem")
		verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
		cert, err := loadCert(certPath)
		if err != nil {
			t.Fatalf("loadCert %s: %v", certPath, err)
		}
		if got := nameString(cert.Subject); got != c.subject {
			t.Fatalf("subject of %v is %q, want %q", c.args, got, c.subject)
		}
		if !slices.Equal(cert.EmailAddresses, c.emails) {
			t.Fatalf("email SANs of %v are %v, want %v", c.args, cert.EmailAddresses, c.emails)
		}
		if c.oid != "" {
			out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-text").CombinedOutput()
			if err != nil {
				t.Fatalf("openssl x509 -text:\n%s", out)
			}
			if !strings.Contains(string(out), "Registered ID:"+c.oid) {
				t.Fatalf("registeredID SAN of %v missing:\n%s", c.args, out)
			}
		}
	}

	for _, args := range [][]string{
		{"Eve", "Eve Example"},
		{"eve@example.com", "eve2@example.com"},
		{"Eve", "1.3.6.1.4.1.99999.3"},
		{"Eve", "eve@example.com", "Eve Example"},
		{"Eve", "eve@example.com", "eve.example.com"},
		{"Eve", "eve@example.com", "192.0.2.1"},
	} {
		if err := makeCert(args[0], args[1:], caDir, "", "user", 365, nil, nil); err == nil {
			t.Fatalf("expected an error for %v", args)
		}
	}
}

func TestInvalidIPSAN(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCert("test", []string{"999.1.1.1"}, caDir, "", "server", 365, nil, nil); err == nil {
		t.Fatal("expected error for invalid IPv4 SAN")
	}
}

func TestRootExists(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
}

func TestPublishURLs(t *testing.T) {
	caDir := t.TempDir()
	base := "http://pki.example.com"

	if err := makeCA(caDir, "Test CA", 3650, "", base); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CAPublishBaseURL != base {
		t.Fatalf("%s holds base URL %q, want %q", configFile, cfg.CAPublishBaseURL, base)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("test", nil, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}

	issuing, err := loadCert(filepath.Join(caDir, "issuing_ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(issuing.IssuingCertificateURL, []string{base + "/ca_cert.crt"}) ||
		!slices.Equal(issuing.CRLDistributionPoints, []string{base + "/crl.pem"}) {
		t.Fatalf("issuing CA URLs: AIA %v CDP %v", issuing.IssuingCertificateURL, issuing.CRLDistributionPoints)
	}

	leaf, err := loadCert(filepath.Join(caDir, "issuing_ca", "test_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(leaf.IssuingCertificateURL, []string{base + "/issuing_ca/ca_cert.crt"}) ||
		!slices.Equal(leaf.CRLDistributionPoints, []string{base + "/issuing_ca/crl.pem"}) {
		t.Fatalf("leaf URLs: AIA %v CDP %v", leaf.IssuingCertificateURL, leaf.CRLDistributionPoints)
	}
}

func TestIndex(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("test", nil, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	if fileExists(filepath.Join(caDir, configFile)) {
		t.Fatalf("%s written without settings", configFile)
	}

	for _, c := range []struct{ dir, cert, subject string }{
		{caDir, filepath.Join(caDir, "issuing_ca", "ca_cert.pem"), "/CN=Issuing CA"},
		{filepath.Join(caDir, "issuing_ca"), filepath.Join(caDir, "issuing_ca", "test_cert.pem"), "/CN=test"},
	} {
		out, err := exec.Command("openssl", "x509", "-in", c.cert, "-noout", "-serial").Output()
		if err != nil {
			t.Fatalf("openssl x509 -serial: %v", err)
		}
		opensslSerial := strings.TrimPrefix(strings.TrimSpace(string(out)), "serial=")
		cert, err := loadCert(c.cert)
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		want := []indexEntry{{"V", cert.NotAfter.UTC().Format(utcTimeFormat), "", opensslSerial, "unknown", c.subject}}
		entries, err := readIndex(c.dir)
		if err != nil {
			t.Fatalf("readIndex: %v", err)
		}
		if !slices.Equal(entries, want) {
			t.Fatalf("index of %s is %+v, want %+v", c.dir, entries, want)
		}
	}
}

func TestOpenSSLCA(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := makeCert(name, nil, caDir, "", "server", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	alice, err := loadCert(filepath.Join(caDir, "alice_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if err := revokeCert(filepath.Join(caDir, "alice_cert.pem"), caDir); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}

	cnf := filepath.Join(t.TempDir(), "openssl.cnf")
	if err := os.WriteFile(cnf, []byte("[ca]\ndefault_ca = test\n\n[test]\n"+
		"database = "+filepath.Join(caDir, indexFile)+"\n"+
		"crlnumber = "+filepath.Join(caDir, crlNumberFile)+"\n"+
		"certificate = "+filepath.Join(caDir, "ca_cert.pem")+"\n"+
		"private_key = "+filepath.Join(caDir, "ca_key.pem")+"\n"+
		"default_md = sha256\ndefault_crl_days = 1\n"), 0o644); err != nil {
		t.Fatalf("write openssl.cnf: %v", err)
	}
	crlPath := filepath.Join(t.TempDir(), "crl.pem")
	if out, err := exec.Command("openssl", "ca", "-config", cnf, "-gencrl", "-out", crlPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -gencrl:\n%s", out)
	}
	b, err := os.ReadFile(crlPath)
	if err != nil {
		t.Fatalf("read CRL: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM block in the CRL of openssl ca")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(alice.SerialNumber) != 0 {
		t.Fatalf("CRL of openssl ca lists %+v, want only alice", crl.RevokedCertificateEntries)
	}
	if crl.Number.Int64() != 2 {
		t.Fatalf("CRL of openssl ca has number %d, want 2, after the first CRL of make-ca", crl.Number)
	}
}

func TestRevokeAndCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := makeCert(name, nil, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	alicePath := filepath.Join(caDir, "issuing_ca", "alice_cert.pem")
	alice, err := loadCert(alicePath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	bob, err := loadCert(filepath.Join(caDir, "issuing_ca", "bob_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}

	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing_ca")); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if err := revokeCert(alicePath, filepath.Join(caDir, "issuing_ca")); err != nil {
		t.Fatalf("revokeCert second run: %v", err)
	}

	crlPath := filepath.Join(caDir, "issuing_ca", "crl.pem")
	for want := int64(2); want <= 3; want++ {
		if err := makeCRL(filepath.Join(caDir, "issuing_ca"), 30); err != nil {
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
			crl.RevokedCertificateEntries[0].SerialNumber.Cmp(alice.SerialNumber) != 0 {
			t.Fatalf("CRL entries %+v, want only alice", crl.RevokedCertificateEntries)
		}
	}

	out, err := exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_bundle.pem"),
		"-CRLfile", crlPath, alicePath).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "revoked") {
		t.Fatalf("expected alice to be reported revoked:\n%s", out)
	}
	out, err = exec.Command("openssl", "verify", "-crl_check", "-CAfile", filepath.Join(caDir, "ca_bundle.pem"),
		"-CRLfile", crlPath, filepath.Join(caDir, "issuing_ca", "bob_cert.pem")).CombinedOutput()
	if err != nil {
		t.Fatalf("bob (serial %X) should verify:\n%s", bob.SerialNumber, out)
	}
}

func TestListAndInfo(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := makeCert(name, nil, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	if err := revokeCert(filepath.Join(caDir, "issuing_ca", "alice_cert.pem"), filepath.Join(caDir, "issuing_ca")); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if err := makeCRL(filepath.Join(caDir, "issuing_ca"), 30); err != nil {
		t.Fatalf("makeCRL: %v", err)
	}

	for _, c := range []struct {
		statuses  []string
		want, not []string
	}{
		{nil, []string{"/CN=alice", "/CN=bob"}, nil},
		{[]string{"revoked"}, []string{"revoked", "/CN=alice"}, []string{"/CN=bob"}},
		{[]string{"valid"}, []string{"valid", "/CN=bob"}, []string{"/CN=alice"}},
		{[]string{"expired"}, nil, []string{"/CN=alice", "/CN=bob"}},
	} {
		var out bytes.Buffer
		if err := listCerts(&out, filepath.Join(caDir, "issuing_ca"), c.statuses); err != nil {
			t.Fatalf("listCerts %v: %v", c.statuses, err)
		}
		for _, s := range c.want {
			if !strings.Contains(out.String(), s) {
				t.Fatalf("list %v lacks %q:\n%s", c.statuses, s, out.String())
			}
		}
		for _, s := range c.not {
			if strings.Contains(out.String(), s) {
				t.Fatalf("list %v holds %q:\n%s", c.statuses, s, out.String())
			}
		}
	}

	var out bytes.Buffer
	if err := showInfo(&out, filepath.Join(caDir, "issuing_ca")); err != nil {
		t.Fatalf("showInfo issuing: %v", err)
	}
	for _, s := range []string{"CN=Issuing CA", "yes, path length 0", "1 valid, 1 revoked, 0 expired", "CRL:", "number 2, 1 revoked", "Next CRL number:"} {
		if !strings.Contains(out.String(), s) {
			t.Fatalf("info of the issuing CA lacks %q:\n%s", s, out.String())
		}
	}
	out.Reset()
	if err := showInfo(&out, caDir); err != nil {
		t.Fatalf("showInfo root: %v", err)
	}
	for _, s := range []string{"root CA", "yes, path length 1", "1 valid, 0 revoked, 0 expired", "CRL:", "number 1, 0 revoked", "Issuing CAs:", "issuing_ca"} {
		if !strings.Contains(out.String(), s) {
			t.Fatalf("info of the root CA lacks %q:\n%s", s, out.String())
		}
	}
}

func TestShowCert(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "http://pki.example.com"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing_ca"), "", "user", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing_ca", "Alice Example_cert.pem")
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	derPath := filepath.Join(t.TempDir(), "alice.der")
	if err := os.WriteFile(derPath, cert.Raw, 0o644); err != nil {
		t.Fatalf("write DER: %v", err)
	}
	out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-fingerprint", "-sha256").Output()
	if err != nil {
		t.Fatalf("openssl x509 -fingerprint: %v", err)
	}
	_, fingerprint, _ := strings.Cut(strings.TrimSpace(string(out)), "=")

	for _, path := range []string{certPath, derPath} {
		var b bytes.Buffer
		if err := showCert(&b, path); err != nil {
			t.Fatalf("showCert %s: %v", path, err)
		}
		for _, s := range []string{"CN=Alice Example", "CN=Issuing CA", "valid", "RSA 4096 bits", "CA:", "no",
			"digitalSignature, contentCommitment", "clientAuth, emailProtection, codeSigning",
			"alice@example.com", "http://pki.example.com/issuing_ca/crl.pem", fingerprint} {
			if !strings.Contains(b.String(), s) {
				t.Fatalf("info of %s lacks %q:\n%s", path, s, b.String())
			}
		}
	}

	var b bytes.Buffer
	if err := showCert(&b, filepath.Join(caDir, "ca_bundle.pem")); err != nil {
		t.Fatalf("showCert bundle: %v", err)
	}
	for _, s := range []string{"1 of 2", "2 of 2", "CN=Test CA", "CN=Issuing CA"} {
		if !strings.Contains(b.String(), s) {
			t.Fatalf("info of the bundle lacks %q:\n%s", s, b.String())
		}
	}

	if err := showCert(&b, filepath.Join(caDir, "issuing_ca", "Alice Example_key.pem")); err == nil {
		t.Fatal("expected an error for a file without a certificate")
	}
}

func TestCADirRoles(t *testing.T) {
	caDir := t.TempDir()
	issuingDir := filepath.Join(caDir, "issuing_ca")

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	rootDir, name, err := locateCA(issuingDir)
	if err != nil || name != "issuing_ca" || filepath.Base(rootDir) != filepath.Base(caDir) {
		t.Fatalf("locateCA(%s) = %q, %q, %v", issuingDir, rootDir, name, err)
	}
	if _, name, err := locateCA(caDir); err != nil || name != "" {
		t.Fatalf("locateCA(%s) names an issuing CA %q, %v", caDir, name, err)
	}
	if err := makeCA(issuingDir, "Nested CA", 3650, "nested", ""); err == nil {
		t.Fatal("expected make-ca to refuse an issuing CA directory")
	}

	if err := revokeCert(filepath.Join(issuingDir, "ca_cert.pem"), caDir); err != nil {
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

func TestEKU(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCert("device01.example.com", nil, caDir, "", "server", 365,
		[]string{"clientAuth", "1.3.6.1.4.1.99999.10"}, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "device01_cert.pem")
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) ||
		len(cert.UnknownExtKeyUsage) != 1 || cert.UnknownExtKeyUsage[0].String() != "1.3.6.1.4.1.99999.10" {
		t.Fatalf("EKUs %v, unknown EKUs %v", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	out, err := exec.Command("openssl", "x509", "-in", certPath, "-noout", "-ext", "extendedKeyUsage").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -ext extendedKeyUsage:\n%s", out)
	}
	for _, s := range []string{"TLS Web Server Authentication", "TLS Web Client Authentication", "1.3.6.1.4.1.99999.10"} {
		if !strings.Contains(string(out), s) {
			t.Fatalf("extended key usage lacks %q:\n%s", s, out)
		}
	}

	if err := makeCert("Signer", nil, caDir, "", "user", 365, []string{"TIMESTAMPING", "codeSigning"}, nil); err != nil {
		t.Fatalf("makeCert user: %v", err)
	}
	signer, err := loadCert(filepath.Join(caDir, "Signer_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(signer.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping}) {
		t.Fatalf("EKUs of the signer %v", signer.ExtKeyUsage)
	}

	for _, eku := range []string{"deviceAuth", "3.1.2", "1.3.6.1.4.1.99999.x"} {
		if err := makeCert("bad.example.com", nil, caDir, "", "server", 365, []string{eku}, nil); err == nil {
			t.Fatalf("expected an error for EKU %q", eku)
		}
	}
}

func TestKeyUsageAndNone(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, c := range []struct {
		cn, certType string
		ekus, kus    []string
		keyUsage     x509.KeyUsage
		extKeyUsage  []x509.ExtKeyUsage
	}{
		{"bare.example.com", "none", nil, nil, 0, nil},
		{"agree.example.com", "none", []string{"clientAuth"}, []string{"digitalSignature", "KEYAGREEMENT"},
			x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"Mail User", "user", nil, []string{"keyEncipherment", "digitalSignature"},
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning}},
	} {
		if err := makeCert(c.cn, nil, caDir, "", c.certType, 365, c.ekus, c.kus); err != nil {
			t.Fatalf("makeCert %s: %v", c.cn, err)
		}
		name, _, _ := strings.Cut(c.cn, ".")
		certPath := filepath.Join(caDir, name+"_cert.pem")
		verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
		cert, err := loadCert(certPath)
		if err != nil {
			t.Fatalf("loadCert %s: %v", certPath, err)
		}
		if cert.KeyUsage != c.keyUsage || !slices.Equal(cert.ExtKeyUsage, c.extKeyUsage) {
			t.Fatalf("%s has key usage %b and EKUs %v, want %b and %v", c.cn, cert.KeyUsage, cert.ExtKeyUsage, c.keyUsage, c.extKeyUsage)
		}
	}

	bare, err := loadCert(filepath.Join(caDir, "bare_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	for _, ext := range bare.Extensions {
		if id := ext.Id.String(); id == "2.5.29.15" || id == "2.5.29.37" {
			t.Fatalf("a none certificate without --ku and --eku has the extension %s", id)
		}
	}
	out, err := exec.Command("openssl", "x509", "-in", filepath.Join(caDir, "agree_cert.pem"), "-noout", "-ext", "keyUsage").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Digital Signature, Key Agreement") {
		t.Fatalf("openssl x509 -ext keyUsage:\n%s", out)
	}

	for _, c := range []struct {
		certType string
		sans     []string
		kus      []string
	}{
		{"server", nil, []string{"keyCertSign"}},
		{"none", nil, []string{"signing"}},
		{"none", []string{"admin@example.com"}, nil},
		{"device", nil, nil},
	} {
		if err := makeCert("bad.example.com", c.sans, caDir, "", c.certType, 365, nil, c.kus); err == nil {
			t.Fatalf("expected an error for type %s, SANs %v and key usages %v", c.certType, c.sans, c.kus)
		}
	}
}

func TestConfigTypes(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte("types:\n"+
		"  device:\n    key_usage: [digitalSignature]\n    ext_key_usage: [clientAuth, 1.3.6.1.4.1.99999.10]\n"+
		"  person:\n    names: user\n    key_usage: [digitalSignature, keyEncipherment]\n    ext_key_usage: []\n"+
		"  user:\n    key_usage: [digitalSignature, contentCommitment, keyEncipherment]\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}

	for _, c := range []struct {
		certType string
		args     []string
		file     string
		keyUsage x509.KeyUsage
		ekus     []x509.ExtKeyUsage
		oids     int
	}{
		{"device", []string{"dev1.example.com"}, "dev1", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 1},
		{"person", []string{"Pat", "pat@example.com"}, "Pat", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil, 0},
		{"user", []string{"Una", "una@example.com"}, "Una",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning}, 0},
		{"server", []string{"web.example.com"}, "web", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 0},
	} {
		if err := makeCert(c.args[0], c.args[1:], caDir, "", c.certType, 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", c.certType, err)
		}
		cert, err := loadCert(filepath.Join(caDir, c.file+"_cert.pem"))
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		if cert.KeyUsage != c.keyUsage || !slices.Equal(cert.ExtKeyUsage, c.ekus) || len(cert.UnknownExtKeyUsage) != c.oids {
			t.Fatalf("%s: key usage %b, EKUs %v, other EKUs %v", c.certType, cert.KeyUsage, cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
		}
	}
	if err := makeCert("x.example.com", nil, caDir, "", "printer", 365, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "device, none, person, server, user") {
		t.Fatalf("expected an unknown type error naming the types, got %v", err)
	}

	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if err := cfg.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	saved, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig after save: %v", err)
	}
	if p := saved.Types["person"].ExtKeyUsage; p == nil || len(*p) != 0 {
		t.Fatalf("the empty ext_key_usage of person did not survive a save: %v", p)
	}
	if saved.Types["user"].ExtKeyUsage != nil {
		t.Fatal("the ext_key_usage left out of user was written by a save")
	}

	for _, types := range []string{
		"types:\n  bad-name:\n    key_usage: [digitalSignature]\n",
		"types:\n  device:\n    names: robot\n",
		"types:\n  device:\n    key_usage: [keyCertSign]\n",
		"types:\n  device:\n    ext_key_usage: [deviceAuth]\n",
	} {
		if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(types), 0o644); err != nil {
			t.Fatalf("write %s: %v", configFile, err)
		}
		if err := makeCert("y.example.com", nil, caDir, "", "server", 365, nil, nil); err == nil {
			t.Fatalf("expected an error for\n%s", types)
		}
	}
}

func TestWriteOpenSSLConf(t *testing.T) {
	caDir := t.TempDir()
	issuingDir := filepath.Join(caDir, "issuing_ca")

	if err := makeCA(caDir, "Test CA", 3650, "", "http://pki.example.com"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg.Days.Cert = 90
	ekus := []string{"clientAuth", "ipsecUser", "1.3.6.1.4.1.99999.10"}
	cfg.Types = map[string]typeConfig{"device": {ExtKeyUsage: &ekus}}
	if err := cfg.save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	rootConf, err := writeOpenSSLConf(caDir)
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
	conf, err := writeOpenSSLConf(issuingDir)
	if err != nil {
		t.Fatalf("writeOpenSSLConf issuing: %v", err)
	}
	b, err = os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read %s: %v", conf, err)
	}
	for _, s := range []string{"default_days     = 90", "[ ext_device ]", "[ ext_none ]", "[ ext_server ]", "[ ext_user ]",
		"extendedKeyUsage       = clientAuth, 1.3.6.1.5.5.7.3.7, 1.3.6.1.4.1.99999.10",
		"crlDistributionPoints  = URI:http://pki.example.com/issuing_ca/crl.pem"} {
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
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(cert.DNSNames, []string{"dev1.example.com"}) ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageIPSECUser}) ||
		len(cert.UnknownExtKeyUsage) != 1 || !slices.Equal(cert.CRLDistributionPoints, []string{"http://pki.example.com/issuing_ca/crl.pem"}) {
		t.Fatalf("certificate of openssl ca: DNS %v, EKUs %v %v, CDP %v", cert.DNSNames, cert.ExtKeyUsage, cert.UnknownExtKeyUsage, cert.CRLDistributionPoints)
	}

	var list bytes.Buffer
	if err := listCerts(&list, issuingDir, nil); err != nil {
		t.Fatalf("listCerts: %v", err)
	}
	if !strings.Contains(list.String(), serialHex(cert.SerialNumber)) {
		t.Fatalf("the certificate of openssl ca is not listed:\n%s", list.String())
	}
	if err := revokeCert(certPath, issuingDir); err != nil {
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

func TestServe(t *testing.T) {
	caDir := t.TempDir()
	server := httptest.NewServer(newServeMux(caDir))
	defer server.Close()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := makeCA(caDir, "Test CA", 3650, "", server.URL); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("web.example.com", nil, filepath.Join(caDir, "issuing_ca"), "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}

	get := func(method, path string) (int, string, []byte) {
		req, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", path, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp.StatusCode, resp.Header.Get("Content-Type"), body
	}

	leaf, err := loadCert(filepath.Join(caDir, "issuing_ca", "web_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	issuing, err := loadCert(filepath.Join(caDir, "issuing_ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	aia := strings.TrimPrefix(leaf.IssuingCertificateURL[0], server.URL)
	if status, typ, body := get("GET", aia); status != http.StatusOK || typ != "application/pkix-cert" || !bytes.Equal(body, issuing.Raw) {
		t.Fatalf("GET %s: %d %s, the DER of the issuing CA: %v", aia, status, typ, bytes.Equal(body, issuing.Raw))
	}
	cdp := strings.TrimPrefix(leaf.CRLDistributionPoints[0], server.URL)
	if status, _, _ := get("GET", cdp); status != http.StatusOK {
		t.Fatalf("GET %s, the first CRL of make-ca: %d, want 200", cdp, status)
	}
	if err := makeCA(caDir, "Short CA", 10, "short_ca", ""); err != nil {
		t.Fatalf("makeCA short: %v", err)
	}
	status, typ, page := get("GET", "/")
	if status != http.StatusOK || typ != "text/html; charset=utf-8" {
		t.Fatalf("GET /: %d %s", status, typ)
	}
	fingerprint := sha256.Sum256(issuing.Raw)
	for _, s := range []string{"<title>Test CA - simple-ca</title>", `font-semibold">Test CA</h1>`, "served by simple-ca",
		"/CN=Issuing CA", "issuing CA issuing_ca",
		"issuing CA short_ca", "<dd>/CN=Test CA</dd>", serialHex(issuing.SerialNumber),
		`<span class="whitespace-nowrap">` + colonHex(fingerprint[:8]) + `:</span><span class="whitespace-nowrap">` +
			colonHex(fingerprint[8:16]) + `:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[16:24]) +
			`:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[24:]) + `</span>`,
		"RSA 4096 bits", issuing.NotBefore.UTC().Format(displayTimeFormat), "3650 days left",
		`bg-amber-100 text-amber-800">10 days left`, `href="/ca_cert.crt"`, `href="/issuing_ca/ca_cert.pem"`,
		"<dd>number 1, 0 revoked, next update ", `href="/issuing_ca/crl.crl"`, `<script src="` + tailwindPath + `">`} {
		if !strings.Contains(string(page), s) {
			t.Fatalf("the index page lacks %q:\n%s", s, page)
		}
	}
	if strings.Contains(string(page), "https://") {
		t.Fatalf("the index page loads a resource from another site:\n%s", page)
	}
	bundleAt := strings.Index(string(page), `href="/ca_bundle.pem"`)
	if bundleAt < 0 || bundleAt > strings.Index(string(page), "<section") {
		t.Fatalf("the index page does not offer the CA bundle above the CAs:\n%s", page)
	}
	status, typ, script := get("GET", tailwindPath)
	if status != http.StatusOK || typ != "text/javascript; charset=utf-8" || !bytes.Equal(script, tailwindJS) ||
		!bytes.Contains(script, []byte(`"4.3.3"`)) {
		t.Fatalf("GET %s: %d %s, %d bytes", tailwindPath, status, typ, len(script))
	}
	if status, _, _ := get("GET", "/assets/"); status != http.StatusNotFound {
		t.Fatalf("GET /assets/: %d, want 404", status)
	}
	if err := makeCRL(filepath.Join(caDir, "issuing_ca"), 30); err != nil {
		t.Fatalf("makeCRL: %v", err)
	}
	if _, _, page := get("GET", "/"); !strings.Contains(string(page), "<dd>number 2, 0 revoked, next update ") {
		t.Fatalf("the index page lacks the second CRL of the issuing CA:\n%s", page)
	}
	status, typ, body := get("GET", cdp)
	if status != http.StatusOK || typ != "application/x-pem-file" {
		t.Fatalf("GET %s: %d %s", cdp, status, typ)
	}
	if block, _ := pem.Decode(body); block == nil || block.Type != "X509 CRL" {
		t.Fatalf("GET %s is not a PEM CRL:\n%s", cdp, body)
	}
	status, typ, body = get("GET", "/issuing_ca/crl.crl")
	if status != http.StatusOK || typ != "application/pkix-crl" {
		t.Fatalf("GET /issuing_ca/crl.crl: %d %s", status, typ)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil || crl.CheckSignatureFrom(issuing) != nil {
		t.Fatalf("the DER CRL does not parse or is not signed by the issuing CA: %v", err)
	}

	bundle, err := os.ReadFile(filepath.Join(caDir, "ca_bundle.pem"))
	if err != nil {
		t.Fatalf("read ca_bundle.pem: %v", err)
	}
	if status, _, body := get("GET", "/ca_bundle.pem"); status != http.StatusOK || !bytes.Equal(body, bundle) {
		t.Fatalf("GET /ca_bundle.pem: %d", status)
	}
	status, typ, body = get("GET", "/ca_bundle.p7b")
	if status != http.StatusOK || typ != "application/x-pkcs7-certificates" {
		t.Fatalf("GET /ca_bundle.p7b: %d %s", status, typ)
	}
	p7bPath := filepath.Join(t.TempDir(), "ca_bundle.p7b")
	if err := os.WriteFile(p7bPath, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", p7bPath, err)
	}
	out, err := exec.Command("openssl", "pkcs7", "-inform", "DER", "-in", p7bPath, "-print_certs").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl pkcs7: %v\n%s", err, out)
	}
	var p7bCerts, bundleCerts [][]byte
	for rest := out; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		p7bCerts = append(p7bCerts, block.Bytes)
	}
	for rest := bundle; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		bundleCerts = append(bundleCerts, block.Bytes)
	}
	if len(bundleCerts) < 2 || !slices.EqualFunc(p7bCerts, bundleCerts, bytes.Equal) {
		t.Fatalf("ca_bundle.p7b holds %d certificates, want the %d of ca_bundle.pem", len(p7bCerts), len(bundleCerts))
	}
	if status, _, _ := get("HEAD", "/ca_cert.pem"); status != http.StatusOK {
		t.Fatalf("HEAD /ca_cert.pem: %d", status)
	}

	for _, c := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/ca_key.pem", http.StatusNotFound},
		{"GET", "/issuing_ca/ca_key.pem", http.StatusNotFound},
		{"GET", "/issuing_ca/web_cert.pem", http.StatusNotFound},
		{"GET", "/missing/ca_cert.crt", http.StatusNotFound},
		{"GET", "/issuing_ca/../ca_key.pem", http.StatusNotFound},
		{"GET", "/crl.pem", http.StatusOK},
		{"POST", "/ca_cert.crt", http.StatusMethodNotAllowed},
	} {
		if status, _, _ := get(c.method, c.path); status != c.status {
			t.Fatalf("%s %s: %d, want %d", c.method, c.path, status, c.status)
		}
	}
}

func TestInitialCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte("days:\n  crl: 7\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, dir := range []string{caDir, filepath.Join(caDir, "issuing_ca")} {
		ca, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(dir, "crl.pem"))
		if err != nil {
			t.Fatalf("make-ca wrote no CRL in %s: %v", dir, err)
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
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, crlNumberFile)); err != nil || strings.TrimSpace(string(b)) != "02" {
		t.Fatalf("make-ca of an existing CA changed its CRL number: %q, %v", b, err)
	}
}

func TestSign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing_ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing_ca")
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
		if err := signCSR(csrPath, issuingDir, "", "server", 30, nil, nil, false, strings.NewReader(answer)); err == nil {
			t.Fatalf("signCSR answered %q succeeded, want an error", answer)
		}
		if fileExists(certPath) {
			t.Fatalf("signCSR answered %q wrote %s", answer, certPath)
		}
		if entries, err := readIndex(issuingDir); err != nil || len(entries) != 0 {
			t.Fatalf("signCSR answered %q recorded %+v, %v", answer, entries, err)
		}
	}
	if err := signCSR(csrPath, issuingDir, "", "server", 30, []string{"codeSigning"}, nil, false, strings.NewReader("Yes\n")); err != nil {
		t.Fatalf("signCSR: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := loadCert(certPath)
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
	if cert.IsCA || cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
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

	if err := signCSR(csrPath, issuingDir, "", "server", 30, nil, nil, true, nil); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("signing again: %v, want an error for the existing certificate", err)
	}
	if err := signCSR(certPath, issuingDir, t.TempDir(), "server", 30, nil, nil, true, nil); err == nil {
		t.Fatal("signing a certificate file succeeded, want an error")
	}
	forceDir := t.TempDir()
	if err := signCSR(csrPath, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err != nil {
		t.Fatalf("signCSR with force: %v", err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(forceDir, "web_cert.pem"))
}

func TestEntryStatus(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		entry indexEntry
		want  string
	}{
		{indexEntry{status: "V", expires: "261030120001Z"}, "valid"},
		{indexEntry{status: "V", expires: "261030120000Z"}, "expired"},
		{indexEntry{status: "V", expires: "20501030120000Z"}, "valid"},
		{indexEntry{status: "E", expires: "271030120000Z"}, "expired"},
		{indexEntry{status: "R", expires: "271030120000Z", revoked: "261029120000Z"}, "revoked"},
	} {
		got, err := entryStatus(c.entry, now)
		if err != nil {
			t.Fatalf("entryStatus %+v: %v", c.entry, err)
		}
		if got != c.want {
			t.Fatalf("entryStatus %+v = %q, want %q", c.entry, got, c.want)
		}
	}
}
