package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/skoszewski/serve-markdown/v3/render"
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

	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingCert := filepath.Join(caDir, "issuing-ca", "ca_cert.pem")
	if !fileExists(issuingCert) {
		t.Fatal("issuing-ca/ca_cert.pem not created")
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), issuingCert)

	if err := makeCert("test", []string{"test.example.com", "127.0.0.1"}, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
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

func TestUserCert(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}

	if err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing-ca"), "", "user", 365, nil, nil); err != nil {
		t.Fatalf("makeCert user: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing-ca", "Alice_Example_cert.pem")
	if !fileExists(certPath) {
		t.Fatal("Alice_Example_cert.pem not created")
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
		{[]string{"Alice Example", "alice@example.com", "a.example@example.org", "1.3.6.1.4.1.99999.2"}, "Alice_Example",
			"/CN=Alice Example/emailAddress=alice@example.com", []string{"alice@example.com", "a.example@example.org"}, "1.3.6.1.4.1.99999.2"},
		{[]string{"bob@example.com", "Bob"}, "Bob", "/CN=Bob/emailAddress=bob@example.com", []string{"bob@example.com"}, ""},
		{[]string{"carol@example.com"}, "carol", "/emailAddress=carol@example.com", []string{"carol@example.com"}, ""},
		{[]string{"Dave"}, "Dave", "/CN=Dave", nil, ""},
		{[]string{"../Frank Example", "frank@example.com"}, "Frank_Example",
			"/CN=../Frank Example/emailAddress=frank@example.com", []string{"frank@example.com"}, ""},
		{[]string{"g.example@example.com"}, "g_example", "/emailAddress=g.example@example.com", []string{"g.example@example.com"}, ""},
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
		{"..."},
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
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
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

func TestIndex(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	if fileExists(filepath.Join(caDir, configFile)) {
		t.Fatalf("%s written without settings", configFile)
	}

	for _, c := range []struct{ dir, cert, subject string }{
		{caDir, filepath.Join(caDir, "issuing-ca", "ca_cert.pem"), "/CN=Issuing CA"},
		{filepath.Join(caDir, "issuing-ca"), filepath.Join(caDir, "issuing-ca", "test_cert.pem"), "/CN=test"},
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
	bob, err := loadCert(filepath.Join(caDir, "bob_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if err := revokeCert(filepath.Join(caDir, "alice_cert.pem"), caDir, "keyCompromise"); err != nil {
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
	if out, err := exec.Command("openssl", "ca", "-config", cnf, "-revoke", filepath.Join(caDir, "bob_cert.pem"),
		"-crl_reason", "CACompromise").CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -revoke:\n%s", out)
	}

	// Both CRLs, of openssl ca and of crl create, list alice and bob with their reasons.
	opensslCRL := filepath.Join(t.TempDir(), "crl.pem")
	if out, err := exec.Command("openssl", "ca", "-config", cnf, "-gencrl", "-out", opensslCRL).CombinedOutput(); err != nil {
		t.Fatalf("openssl ca -gencrl:\n%s", out)
	}
	if err := makeCRL(caDir, 30); err != nil {
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
			reasons[serialHex(e.SerialNumber)] = e.ReasonCode
		}
		if len(reasons) != 2 || reasons[serialHex(alice.SerialNumber)] != 1 || reasons[serialHex(bob.SerialNumber)] != 2 {
			t.Fatalf("%s lists the reason codes %v, want alice keyCompromise (1) and bob CACompromise (2)", crlPath, reasons)
		}
		if want := int64(2 + i); crl.Number.Int64() != want {
			t.Fatalf("%s has number %d, want %d", crlPath, crl.Number, want)
		}
	}
}

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
		if err := makeCert(name, nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
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

func TestListAndInfo(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := makeCert(name, nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", name, err)
		}
	}
	if err := revokeCert(filepath.Join(caDir, "issuing-ca", "alice_cert.pem"), filepath.Join(caDir, "issuing-ca"), ""); err != nil {
		t.Fatalf("revokeCert: %v", err)
	}
	if err := makeCRL(filepath.Join(caDir, "issuing-ca"), 30); err != nil {
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
		if err := listCerts(&out, filepath.Join(caDir, "issuing-ca"), c.statuses); err != nil {
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
	if err := showInfo(&out, filepath.Join(caDir, "issuing-ca")); err != nil {
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
	for _, s := range []string{"root CA", "yes, path length 1", "1 valid, 0 revoked, 0 expired", "CRL:", "number 1, 0 revoked", "Issuing CAs:", "issuing-ca"} {
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
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing-ca"), "", "user", 365, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	certPath := filepath.Join(caDir, "issuing-ca", "Alice_Example_cert.pem")
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
			"alice@example.com", "http://pki.example.com/issuing-ca/crl.pem", fingerprint} {
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

	if err := showCert(&b, filepath.Join(caDir, "issuing-ca", "Alice_Example_key.pem")); err == nil {
		t.Fatal("expected an error for a file without a certificate")
	}
}

func TestCADirRoles(t *testing.T) {
	caDir := t.TempDir()
	issuingDir := filepath.Join(caDir, "issuing-ca")

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	rootDir, name, err := locateCA(issuingDir)
	if err != nil || name != "issuing-ca" || filepath.Base(rootDir) != filepath.Base(caDir) {
		t.Fatalf("locateCA(%s) = %q, %q, %v", issuingDir, rootDir, name, err)
	}
	if _, name, err := locateCA(caDir); err != nil || name != "" {
		t.Fatalf("locateCA(%s) names an issuing CA %q, %v", caDir, name, err)
	}
	if err := makeCA(issuingDir, "Nested CA", 3650, "nested", ""); err == nil {
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
		name, _, _ := strings.Cut(strings.ReplaceAll(c.cn, " ", "_"), ".")
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
	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"types": {`+
		`"device": {"key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]}, `+
		`"person": {"names": "user", "key_usage": ["digitalSignature", "keyEncipherment"], "ext_key_usage": []}, `+
		`"user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}}}`), 0o644); err != nil {
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
		`{"types": {"Bad_Name": {"key_usage": ["digitalSignature"]}}}`,
		`{"types": {"device": {"names": "robot"}}}`,
		`{"types": {"device": {"key_usage": ["keyCertSign"]}}}`,
		`{"types": {"device": {"ext_key_usage": ["deviceAuth"]}}}`,
		`{"types": {"device": {"key_usages": ["digitalSignature"]}}}`,
		"types:\n  device:\n    key_usage: [digitalSignature]\n",
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
	issuingDir := filepath.Join(caDir, "issuing-ca")

	if err := makeCA(caDir, "Test CA", 3650, "", "http://pki.example.com"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
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
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(cert.DNSNames, []string{"dev1.example.com"}) ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageIPSECUser}) ||
		len(cert.UnknownExtKeyUsage) != 1 || !slices.Equal(cert.CRLDistributionPoints, []string{"http://pki.example.com/issuing-ca/crl.pem"}) {
		t.Fatalf("certificate of openssl ca: DNS %v, EKUs %v %v, CDP %v", cert.DNSNames, cert.ExtKeyUsage, cert.UnknownExtKeyUsage, cert.CRLDistributionPoints)
	}

	var list bytes.Buffer
	if err := listCerts(&list, issuingDir, nil); err != nil {
		t.Fatalf("listCerts: %v", err)
	}
	if !strings.Contains(list.String(), serialHex(cert.SerialNumber)) {
		t.Fatalf("the certificate of openssl ca is not listed:\n%s", list.String())
	}
	if err := revokeCert(certPath, issuingDir, ""); err != nil {
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
	server := httptest.NewServer(newServeMux(caDir, nil, false))
	defer server.Close()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	if err := makeCA(caDir, "Test CA", 3650, "", server.URL); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("web.example.com", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil); err != nil {
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

	leaf, err := loadCert(filepath.Join(caDir, "issuing-ca", "web_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	issuing, err := loadCert(filepath.Join(caDir, "issuing-ca", "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	aia := strings.TrimPrefix(leaf.IssuingCertificateURL[0], server.URL)
	if status, typ, body := get("GET", aia); status != http.StatusOK || typ != "application/pkix-cert" || !bytes.Equal(body, issuing.Raw) {
		t.Fatalf("GET %s: %d %s, the DER of the issuing CA: %v", aia, status, typ, bytes.Equal(body, issuing.Raw))
	}
	cdp := strings.TrimPrefix(leaf.CRLDistributionPoints[0], server.URL)
	if status, _, _ := get("GET", cdp); status != http.StatusOK {
		t.Fatalf("GET %s, the first CRL of ca create: %d, want 200", cdp, status)
	}
	if err := makeCA(caDir, "Short CA", 10, "short-ca", ""); err != nil {
		t.Fatalf("makeCA short: %v", err)
	}
	status, typ, page := get("GET", "/")
	if status != http.StatusOK || typ != "text/html; charset=utf-8" {
		t.Fatalf("GET /: %d %s", status, typ)
	}
	fingerprint := sha256.Sum256(issuing.Raw)
	for _, s := range []string{"<title>Test CA - simple-ca</title>", `font-semibold">Test CA</h1>`, "served by simple-ca",
		"<dd>/CN=Issuing CA</dd>", `underline-offset-4">Issuing CA</span>`, `<dt class="text-muted">CN</dt>`,
		`font-semibold">Issuing CA</h2>`, `text-subtle-ink">Root CA</span>`, `text-subtle-ink">Subordinate CA</span>`,
		"<dd>/CN=Test CA</dd>", serialHex(issuing.SerialNumber),
		`<span class="whitespace-nowrap">` + colonHex(fingerprint[:8]) + `:</span><span class="whitespace-nowrap">` +
			colonHex(fingerprint[8:16]) + `:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[16:24]) +
			`:</span><span class="whitespace-nowrap">` + colonHex(fingerprint[24:]) + `</span>`,
		"RSA 4096 bits", issuing.NotBefore.UTC().Format(displayTimeFormat), "3650 days left",
		`bg-warn text-warn-ink">10 days left`, `href="/ca_cert.crt"`, `href="/issuing-ca/ca_cert.pem"`,
		"<dd>number 1, 0 revoked, next update ", `href="/issuing-ca/crl.crl"`, `<script src="` + tailwindPath + `">`,
		`<button type="button" data-info="info-1"`, `<dialog id="info-1"`, `<script src="/assets/webui/index.js">`} {
		if !strings.Contains(string(page), s) {
			t.Fatalf("the index page lacks %q:\n%s", s, page)
		}
	}
	if strings.Contains(string(page), "https://") {
		t.Fatalf("the index page loads a resource from another site:\n%s", page)
	}
	if !strings.Contains(string(page), `<tr id="issuing-ca">`) {
		t.Fatalf("the index page has no row with the ID issuing-ca:\n%s", page)
	}

	// /CA and /CA/ of an issuing CA redirect to its section of the index page.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, c := range []struct {
		method, path, location string
		want                   int
	}{
		{"GET", "/issuing-ca", "/#issuing-ca", http.StatusFound},
		{"GET", "/issuing-ca/", "/#issuing-ca", http.StatusFound},
		{"HEAD", "/issuing-ca", "/#issuing-ca", http.StatusFound},
		{"GET", "/nosuch", "", http.StatusNotFound},
		{"GET", "/nosuch/", "", http.StatusNotFound},
	} {
		req, err := http.NewRequest(c.method, server.URL+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want || resp.Header.Get("Location") != c.location {
			t.Fatalf("%s %s: %d to %q, want %d to %q", c.method, c.path, resp.StatusCode, resp.Header.Get("Location"), c.want, c.location)
		}
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
	if err := makeCRL(filepath.Join(caDir, "issuing-ca"), 30); err != nil {
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
	status, typ, body = get("GET", "/issuing-ca/crl.crl")
	if status != http.StatusOK || typ != "application/pkix-crl" {
		t.Fatalf("GET /issuing-ca/crl.crl: %d %s", status, typ)
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
		{"GET", "/issuing-ca/ca_key.pem", http.StatusNotFound},
		{"GET", "/issuing-ca/web_cert.pem", http.StatusNotFound},
		{"GET", "/missing/ca_cert.crt", http.StatusNotFound},
		{"GET", "/issuing-ca/../ca_key.pem", http.StatusNotFound},
		{"GET", "/crl.pem", http.StatusOK},
		{"POST", "/ca_cert.crt", http.StatusMethodNotAllowed},
		{"GET", "/acme/directory", http.StatusNotFound},
		{"GET", "/issuing-ca/acme/directory", http.StatusNotFound},
	} {
		if status, _, _ := get(c.method, c.path); status != c.status {
			t.Fatalf("%s %s: %d, want %d", c.method, c.path, status, c.status)
		}
	}
}

func TestACME(t *testing.T) {
	if _, err := exec.LookPath("lego"); err != nil {
		t.Skip("lego is not installed")
	}
	caDir := t.TempDir()
	tlsDir := t.TempDir()
	legoDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"days": {"cert": 400}, "acme": {"domains": ["localhost"]}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Servers CA", 3650, "servers", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCert("localhost", nil, caDir, tlsDir, "server", 30, nil, nil); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: newServeMux(caDir, nil, false), ErrorLog: log.New(io.Discard, "", 0)}
	go server.ServeTLS(listener, filepath.Join(tlsDir, "localhost_cert.pem"), filepath.Join(tlsDir, "localhost_key.pem"))
	defer server.Close()

	// The http-01 challenges are validated on a free port, where lego answers them.
	free, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpPort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	defer func(port int) { acmeHTTPPort = port }(acmeHTTPPort)
	acmeHTTPPort = httpPort

	directory := fmt.Sprintf("https://localhost:%d/servers/acme/directory", listener.Addr().(*net.TCPAddr).Port)
	lego := func(args ...string) (string, error) {
		cmd := exec.Command("lego", args...)
		cmd.Env = append(os.Environ(), "LEGO_CA_CERTIFICATES="+filepath.Join(caDir, "ca_cert.pem"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	common := []string{"--server", directory, "--path", legoDir, "--email", "test@example.com"}

	out, err := lego(append([]string{"run", "--accept-tos", "--domains", "localhost", "--http",
		"--http.address", fmt.Sprintf(":%d", httpPort)}, common...)...)
	if err != nil {
		t.Fatalf("lego run: %v\n%s", err, out)
	}
	var certPath string
	filepath.WalkDir(legoDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(path) == "localhost.crt" {
			certPath = path
		}
		return nil
	})
	if certPath == "" {
		t.Fatalf("lego wrote no localhost.crt to %s:\n%s", legoDir, out)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if cert.Subject.CommonName != "localhost" || !slices.Equal(cert.DNSNames, []string{"localhost"}) ||
		cert.Issuer.CommonName != "Servers CA" {
		t.Fatalf("certificate of %v %v by %v, want localhost by Servers CA", cert.Subject, cert.DNSNames, cert.Issuer)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("extended key usage %v, want that of the server type", cert.ExtKeyUsage)
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; days != 90 {
		t.Fatalf("the ACME certificate is valid for %v days, want the ACME default, 90, not days.cert", days)
	}
	entries, err := readIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].serial != serialHex(cert.SerialNumber) {
		t.Fatalf("index.txt of the issuing CA: %+v, %v, want the ACME certificate", entries, err)
	}
	if !fileExists(filepath.Join(caDir, "servers", acmeStateFile)) {
		t.Fatalf("no %s in the issuing CA directory", acmeStateFile)
	}

	out, err = lego(append([]string{"run", "--accept-tos", "--domains", "www.example.org", "--http",
		"--http.address", fmt.Sprintf(":%d", httpPort)}, common...)...)
	if err == nil || !strings.Contains(out, "rejectedIdentifier") {
		t.Fatalf("lego run for a name outside acme.domains: %v, want rejectedIdentifier:\n%s", err, out)
	}

	out, err = lego(append([]string{"certificates", "revoke", "--cert.name", "localhost", "--reason", "4"}, common...)...)
	if err != nil {
		t.Fatalf("lego certificates revoke: %v\n%s", err, out)
	}
	entries, err = readIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].status != "R" || !strings.HasSuffix(entries[0].revoked, ",superseded") {
		t.Fatalf("index.txt after lego revoked: %+v, %v, want revoked, superseded", entries, err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(t, caDir)}}}
	origin := strings.TrimSuffix(directory, "/servers/acme/directory")
	resp, err := client.Get(origin + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), directory) || !strings.Contains(string(page), origin+"/acme/directory") {
		t.Fatalf("the index page lacks the ACME directories:\n%s", page)
	}
	resp, err = client.Get(origin + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"newOrder":"`+origin+`/acme/new-order"`) {
		t.Fatalf("GET /acme/directory of the root CA: %d\n%s", resp.StatusCode, body)
	}
}

func rootPool(t *testing.T, caDir string) *x509.CertPool {
	t.Helper()
	root, err := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}

func TestServeAddress(t *testing.T) {
	if err := run([]string{"serve", "--address", ""}); !errors.Is(err, errUsage) {
		t.Fatalf("serve --address \"\": %v, want a usage error", err)
	}
}

func TestCommands(t *testing.T) {
	caDir := t.TempDir()
	if err := run([]string{"ca", "create", "--ca-dir", caDir, "Test CA"}); err != nil {
		t.Fatalf("ca create: %v", err)
	}
	caCert := filepath.Join(caDir, "ca_cert.pem")
	for _, c := range []struct {
		args []string
		want error
	}{
		{nil, errUsage},
		{[]string{"-h"}, nil},
		{[]string{"ca"}, errUsage},
		{[]string{"cert"}, errUsage},
		{[]string{"crl"}, errUsage},
		{[]string{"token"}, errUsage},
		{[]string{"cert", "-h"}, nil},
		{[]string{"token", "--help"}, nil},
		{[]string{"nosuch"}, errUsage},
		{[]string{"cert", "nosuch"}, errUsage},
		{[]string{"make-ca", "--ca-dir", caDir, "Old"}, errUsage},
		{[]string{"list-tokens"}, errUsage},
		{[]string{"cert", "create", "-h"}, flag.ErrHelp},
		{[]string{"cert", "show"}, errUsage},
		{[]string{"cert", "show", caCert}, nil},
		{[]string{"ca", "show", "--ca-dir", caDir}, nil},
		{[]string{"cert", "list", "--ca-dir", caDir}, nil},
		{[]string{"token", "list", "--ca-dir", caDir}, nil},
		{[]string{"crl", "create", "--ca-dir", caDir}, nil},
	} {
		if err := run(c.args); !errors.Is(err, c.want) {
			t.Fatalf("run %q: %v, want %v", c.args, err, c.want)
		}
	}
}

func TestInitialCRL(t *testing.T) {
	caDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"days": {"crl": 7}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
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
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA second run: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, crlNumberFile)); err != nil || strings.TrimSpace(string(b)) != "02" {
		t.Fatalf("ca create of an existing CA changed its CRL number: %q, %v", b, err)
	}
}

func TestSign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
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

	for _, c := range []struct{ file, cert string }{{"my web.v2.csr", "my_web_v2_cert.pem"}, {"db", "db_cert.pem"}} {
		renamed := filepath.Join(csrDir, c.file)
		if err := os.Link(csrPath, renamed); err != nil {
			t.Fatalf("link %s: %v", renamed, err)
		}
		if err := signCSR(renamed, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err != nil {
			t.Fatalf("signCSR %s: %v", c.file, err)
		}
		verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), filepath.Join(forceDir, c.cert))
	}
	empty := filepath.Join(csrDir, "+.csr")
	if err := os.Link(csrPath, empty); err != nil {
		t.Fatalf("link %s: %v", empty, err)
	}
	if err := signCSR(empty, issuingDir, forceDir, "server", 30, nil, nil, true, nil); err == nil {
		t.Fatal("signing +.csr succeeded, want an error for the empty file name")
	}
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

func TestTokens(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	token, err := makeToken(caDir, "deploy", time.Hour, []string{"server", "user"}, []string{"Example.COM."}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token %q is not a JWT", token)
	}
	info, err := os.Stat(filepath.Join(caDir, tokensFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s: %v, mode %v, want 0600", tokensFile, err, info.Mode().Perm())
	}
	db, err := loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	tok := db.Tokens["deploy"]
	if tok == nil || !slices.Equal(tok.Domains, []string{"example.com"}) || !slices.Equal(tok.Types, []string{"server", "user"}) ||
		tok.Expires.Sub(tok.Issued) != time.Hour {
		t.Fatalf("token entry %+v, want the domains, types and validity given", tok)
	}

	for _, c := range []struct {
		name    string
		types   []string
		domains []string
	}{
		{"deploy", []string{"server"}, []string{"example.com"}},
		{"bad name", []string{"server"}, []string{"example.com"}},
		{"other", []string{"nosuch"}, []string{"example.com"}},
		{"other", []string{"server"}, nil},
		{"other", []string{"server"}, []string{"192.0.2.1"}},
	} {
		if _, err := makeToken(caDir, c.name, time.Hour, c.types, c.domains, nil, nil); err == nil {
			t.Fatalf("makeToken %q %v %v succeeded, want an error", c.name, c.types, c.domains)
		}
	}

	// --ip takes addresses, kept as prefixes, prefixes, kept masked, and *.
	for _, ips := range [][]string{{"300.1.2.3"}, {"10.0.0.0/33"}, {"fe80::1%en0"}, {"example.com"}} {
		if _, err := makeToken(caDir, "ips", time.Hour, []string{"server"}, nil, ips, nil); err == nil {
			t.Fatalf("makeToken --ip %v succeeded, want an error", ips)
		}
		if _, err := makeToken(caDir, "ips", time.Hour, []string{"server"}, []string{"*"}, nil, ips); err == nil {
			t.Fatalf("makeToken --host %v succeeded, want an error", ips)
		}
	}
	if _, err := makeToken(caDir, "ips", time.Hour, []string{"server"}, []string{"*"}, nil, []string{"*"}); err == nil {
		t.Fatal("makeToken --host * succeeded, want an error")
	}
	if _, err := makeToken(caDir, "ips", time.Hour, []string{"server"}, []string{"*"},
		[]string{"192.0.2.10", "10.1.2.3/8", "2001:db8::/32", "*"}, nil); err != nil {
		t.Fatalf("makeToken with * and IP addresses: %v", err)
	}
	db, err = loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if ips := db.Tokens["ips"]; !slices.Equal(ips.IPs, []string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::/32", "*"}) ||
		!slices.Equal(ips.Domains, []string{"*"}) {
		t.Fatalf("token entry %+v, want the IP prefixes masked and the domain *", ips)
	}
	if err := revokeToken(caDir, "ips"); err != nil {
		t.Fatalf("revokeToken ips: %v", err)
	}

	var out bytes.Buffer
	if err := listTokens(&out, caDir); err != nil {
		t.Fatalf("listTokens: %v", err)
	}
	if !strings.Contains(out.String(), "deploy") || strings.Contains(out.String(), "(expired)") ||
		strings.Contains(out.String(), "STATUS") {
		t.Fatalf("token list output:\n%s\nwant the valid token deploy without a status", out.String())
	}
	if shown := showPrefixes([]string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::1/128", "2001:db8::/32", "*"}); !slices.Equal(shown,
		[]string{"192.0.2.10", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32", "*"}) {
		t.Fatalf("showPrefixes = %v, want single addresses without their prefix length", shown)
	}
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	if err := revokeToken(caDir, "deploy"); err == nil {
		t.Fatal("revoking twice succeeded, want an error")
	}
	if err := revokeToken(caDir, "nosuch"); err == nil {
		t.Fatal("revoking an unknown token succeeded, want an error")
	}
	// A revoked token is kept without its JWT ID, expired when it was revoked, holding its name
	// until it is purged.
	out.Reset()
	if err := listTokens(&out, caDir); err != nil || !strings.Contains(out.String(), "deploy  revoked  ") {
		t.Fatalf("token list output:\n%s\n%v, want the revoked token marked revoked, without a time", out.String(), err)
	}
	if db, err := loadTokens(caDir); err != nil || db.Tokens["deploy"] == nil || db.Tokens["deploy"].ID != "" ||
		time.Now().Before(db.Tokens["deploy"].Expires) || time.Since(db.Tokens["deploy"].Expires) > time.Minute {
		t.Fatalf("tokens after revoking: %v, want deploy kept without its JWT ID, expired when revoked", err)
	}
	if _, err := makeToken(caDir, "deploy", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken with the name of a revoked token succeeded, want an error")
	}
	if err := purgeToken(caDir, "deploy"); err != nil {
		t.Fatalf("purgeToken of the revoked token: %v", err)
	}
	if _, err := makeToken(caDir, "deploy", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("makeToken with the name of a purged token: %v", err)
	}
	if err := purgeToken(caDir, "deploy"); err == nil || !strings.Contains(err.Error(), "revoke it first") {
		t.Fatalf("purgeToken of a token still accepted: %v, want an error", err)
	}

	// A revoked token, without its expiry, is renewed for the default validity of token create.
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	if _, err := renewToken(caDir, "deploy", 0); err != nil {
		t.Fatalf("renewToken of the revoked token: %v", err)
	}
	if db, err := loadTokens(caDir); err != nil || db.Tokens["deploy"].revoked() ||
		db.Tokens["deploy"].Expires.Sub(db.Tokens["deploy"].Issued) != time.Hour {
		t.Fatalf("renewed revoked token %+v, %v, want it valid for an hour, not revoked", db.Tokens["deploy"], err)
	}
	if _, err := makeToken(caDir, "short", time.Millisecond, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken valid for 1ms succeeded, want an error")
	}

	// purgeTokens removes the expired and revoked tokens alone.
	oldJWT, err := makeToken(caDir, "old", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken old: %v", err)
	}
	expire := func() string {
		t.Helper()
		db, err := loadTokens(caDir)
		if err != nil {
			t.Fatalf("loadTokens: %v", err)
		}
		db.Tokens["old"].Expires = time.Now().Add(-time.Minute)
		if err := db.save(caDir); err != nil {
			t.Fatalf("save: %v", err)
		}
		return db.Tokens["old"].ID
	}
	oldID := expire()
	out.Reset()
	if err := listTokens(&out, caDir); err != nil || !strings.Contains(out.String(), " UTC (expired)") {
		t.Fatalf("token list output:\n%s\n%v, want the expired token marked", out.String(), err)
	}

	// An expired token is kept for as long as it is to be kept, and renewed with a new JWT ID, valid
	// for as long as it was before and allowing what it allowed.
	if n, err := purgeTokens(caDir, time.Hour); err != nil || n != 0 {
		t.Fatalf("purgeTokens keeping an hour: %d, %v, want the token expired a minute ago kept", n, err)
	}
	renewed, err := renewToken(caDir, "old", 0)
	if err != nil {
		t.Fatalf("renewToken: %v", err)
	}
	db, err = loadTokens(caDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if tok := db.Tokens["old"]; renewed == oldJWT || tok.ID == oldID || !time.Now().Before(tok.Expires) ||
		tok.Expires.Sub(tok.Issued) != time.Hour || !slices.Equal(tok.Domains, []string{"example.com"}) {
		t.Fatalf("renewed token %+v, want a new JWT and ID, valid for an hour from now, for example.com", tok)
	}
	if _, err := renewToken(caDir, "nowhere", 0); err == nil {
		t.Fatal("renewToken of a token that is not there succeeded")
	}
	expire()
	if n, err := purgeTokens(caDir, 0); err != nil || n != 2 {
		t.Fatalf("purgeTokens: %d, %v, want the expired token and the revoked ips removed", n, err)
	}
	if db, err := loadTokens(caDir); err != nil || len(db.Tokens) != 1 || db.Tokens["deploy"] == nil {
		t.Fatalf("tokens after purging: %v, want deploy alone", err)
	}
	if n, err := purgeTokens(t.TempDir(), 0); err != nil || n != 0 {
		t.Fatalf("purgeTokens without tokens-db.json: %d, %v, want 0", n, err)
	}

	// A held lock makes the commands wait and then fail, and its release lets them run.
	lockPath := filepath.Join(caDir, tokensFile+".lock")
	if fileExists(lockPath) {
		t.Fatalf("%s left after the commands", lockPath)
	}
	unlock, err := lockTokens(caDir)
	if err != nil {
		t.Fatalf("lockTokens: %v", err)
	}
	wait := tokensLockWait
	tokensLockWait = 200 * time.Millisecond
	t.Cleanup(func() { tokensLockWait = wait })
	if err := revokeToken(caDir, "deploy"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("locked by process %d", os.Getpid())) {
		t.Fatalf("revokeToken while locked: %v, want a lock error naming this process", err)
	}
	unlock()
	if err := revokeToken(caDir, "deploy"); err != nil {
		t.Fatalf("revokeToken after unlocking: %v", err)
	}
}

func TestAPISign(t *testing.T) {
	caDir := t.TempDir()
	csrDir := t.TempDir()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if err := makeCA(caDir, "Plain CA", 3650, "plain-ca", ""); err != nil {
		t.Fatalf("makeCA plain: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	token, err := makeToken(issuingDir, "deploy", time.Hour, []string{"server", "user"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	rootToken, err := makeToken(caDir, "root", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken root: %v", err)
	}
	serverOnly, err := makeToken(issuingDir, "server-only", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken server-only: %v", err)
	}
	expired, err := makeToken(issuingDir, "expired", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken expired: %v", err)
	}
	revoked, err := makeToken(issuingDir, "revoked", time.Hour, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken revoked: %v", err)
	}
	if err := revokeToken(issuingDir, "revoked"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	if _, err := renewToken(issuingDir, "revoked", 0); err != nil {
		t.Fatalf("renewToken of the revoked token: %v", err)
	}
	db, err := loadTokens(issuingDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	db.Tokens["expired"].Expires = time.Now().Add(-time.Hour)
	if err := db.save(issuingDir); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, claims, _ := strings.Cut(token, ".")
	claims, _, _ = strings.Cut(claims, ".")
	algNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + claims + "."

	csr := func(name string, args ...string) string {
		path := filepath.Join(csrDir, name+".csr")
		out, err := exec.Command("openssl", append([]string{"req", "-new", "-newkey", "ec", "-pkeyopt",
			"ec_paramgen_curve:P-256", "-nodes", "-keyout", filepath.Join(csrDir, name+"_key.pem"), "-out", path}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl req: %v\n%s", err, out)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}
	web := csr("web", "-subj", "/CN=web.example.com", "-addext", "subjectAltName=DNS:web.example.com,DNS:*.web.example.com")
	alice := csr("alice", "-subj", "/CN=Alice Example/emailAddress=alice@example.com")
	outside := csr("outside", "-subj", "/CN=web.example.org")
	withIP := csr("ip", "-subj", "/CN=web.example.com", "-addext", "subjectAltName=IP:192.0.2.1")
	withO := csr("org", "-subj", "/O=Example/CN=web.example.com")

	server := httptest.NewServer(newServeMux(caDir, nil, false))
	defer server.Close()
	post := func(path, token, contentType, body string) (int, map[string]string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]string
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	request := func(csr, certType string) string {
		b, _ := json.Marshal(map[string]string{"csr": csr, "type": certType})
		return string(b)
	}

	status, resp := post("/issuing-ca/api/sign", token, "application/json", request(web, ""))
	if status != http.StatusOK {
		t.Fatalf("signing web: %d %v", status, resp)
	}
	certPath := filepath.Join(csrDir, "web_cert.pem")
	if err := os.WriteFile(certPath, []byte(resp["certificate"]), 0o644); err != nil {
		t.Fatal(err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if !slices.Equal(cert.DNSNames, []string{"web.example.com", "*.web.example.com"}) || resp["serial"] != serialHex(cert.SerialNumber) {
		t.Fatalf("DNS names %v, serial %s, want those of the request and the certificate", cert.DNSNames, resp["serial"])
	}
	if strings.Count(resp["chain"], "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("chain:\n%s\nwant the certificate and the issuing CA", resp["chain"])
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 1 || entries[0].serial != resp["serial"] {
		t.Fatalf("index.txt %+v, %v, want the issued certificate", entries, err)
	}
	if db, err := loadTokens(issuingDir); err != nil || !slices.Equal(db.Tokens["deploy"].Certs, []string{resp["serial"]}) {
		t.Fatalf("certs of the token: %v, want the issued certificate", err)
	}

	status, resp = post("/issuing-ca/api/sign", token, "application/json", request(alice, "user"))
	if status != http.StatusOK {
		t.Fatalf("signing alice: %d %v", status, resp)
	}
	status, resp = post("/api/sign", rootToken, "application/json", request(web, ""))
	if status != http.StatusOK || strings.Count(resp["chain"], "BEGIN CERTIFICATE") != 1 {
		t.Fatalf("signing with the root CA: %d %v, want the certificate alone in the chain", status, resp)
	}

	for _, c := range []struct {
		name, path, token, contentType, body string
		want                                 int
	}{
		{"no token", "/issuing-ca/api/sign", "", "application/json", request(web, ""), http.StatusUnauthorized},
		{"other CA token", "/issuing-ca/api/sign", rootToken, "application/json", request(web, ""), http.StatusUnauthorized},
		{"expired token", "/issuing-ca/api/sign", expired, "application/json", request(web, ""), http.StatusUnauthorized},
		{"revoked token", "/issuing-ca/api/sign", revoked, "application/json", request(web, ""), http.StatusUnauthorized},
		{"alg none", "/issuing-ca/api/sign", algNone, "application/json", request(web, ""), http.StatusUnauthorized},
		{"garbage token", "/issuing-ca/api/sign", "abc", "application/json", request(web, ""), http.StatusUnauthorized},
		{"name outside", "/issuing-ca/api/sign", token, "application/json", request(outside, ""), http.StatusForbidden},
		{"IP SAN", "/issuing-ca/api/sign", token, "application/json", request(withIP, ""), http.StatusForbidden},
		{"O attribute", "/issuing-ca/api/sign", token, "application/json", request(withO, ""), http.StatusForbidden},
		{"email in server", "/issuing-ca/api/sign", token, "application/json", request(alice, "server"), http.StatusForbidden},
		{"DNS in user", "/issuing-ca/api/sign", token, "application/json", request(web, "user"), http.StatusForbidden},
		{"type not allowed", "/issuing-ca/api/sign", serverOnly, "application/json", request(alice, "user"), http.StatusForbidden},
		{"bad csr", "/issuing-ca/api/sign", token, "application/json", request("nonsense", ""), http.StatusBadRequest},
		{"unknown field", "/issuing-ca/api/sign", token, "application/json", `{"csr":"x","days":5}`, http.StatusBadRequest},
		{"content type", "/issuing-ca/api/sign", token, "text/plain", request(web, ""), http.StatusUnsupportedMediaType},
		{"no tokens", "/plain-ca/api/sign", token, "application/json", request(web, ""), http.StatusNotFound},
		{"no CA", "/nosuch/api/sign", token, "application/json", request(web, ""), http.StatusNotFound},
	} {
		if status, resp := post(c.path, c.token, c.contentType, c.body); status != c.want {
			t.Fatalf("%s: status %d %v, want %d", c.name, status, resp, c.want)
		}
	}
	if _, resp := post("/issuing-ca/api/sign", serverOnly, "application/json", request(alice, "user")); resp["error"] !=
		"the token does not allow the type 'user'; choose a type it allows, server, or the default, its first type" {
		t.Errorf("type not allowed: %v, want the types the token allows", resp)
	}
	if entries, err := readIndex(issuingDir); err != nil || len(entries) != 2 {
		t.Fatalf("index.txt %+v, %v, want the two certificates issued", entries, err)
	}

	form, err := http.Get(server.URL + "/issuing-ca/sign")
	if err != nil {
		t.Fatal(err)
	}
	formPage, _ := io.ReadAll(form.Body)
	form.Body.Close()
	if form.StatusCode != http.StatusOK || !strings.Contains(string(formPage), `action="/issuing-ca/sign"`) ||
		!strings.Contains(string(formPage), `type="password"`) ||
		!strings.Contains(string(formPage), `<option value="">Default: the token's first type</option>`) ||
		!strings.Contains(string(formPage), `<option value="server">server: TLS server and TLS client</option>`) ||
		!strings.Contains(string(formPage), `<option value="none">none: no key usages</option>`) {
		t.Fatalf("GET /issuing-ca/sign: %d\n%s\nwant the form, its types described", form.StatusCode, formPage)
	}
	signed, err := http.PostForm(server.URL+"/issuing-ca/sign", url.Values{"csr": {web}, "token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	download, _ := io.ReadAll(signed.Body)
	signed.Body.Close()
	if signed.StatusCode != http.StatusOK || signed.Header.Get("Content-Disposition") != "attachment; filename=web_cert.pem" {
		t.Fatalf("POST /issuing-ca/sign: %d %q, want web_cert.pem as a download", signed.StatusCode, signed.Header.Get("Content-Disposition"))
	}
	if err := os.WriteFile(certPath, download, 0o644); err != nil {
		t.Fatal(err)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	refused, err := http.PostForm(server.URL+"/issuing-ca/sign", url.Values{"csr": {outside}, "token": {revoked}, "type": {"user"}})
	if err != nil {
		t.Fatal(err)
	}
	refusedPage, _ := io.ReadAll(refused.Body)
	refused.Body.Close()
	if refused.StatusCode != http.StatusUnauthorized || !strings.Contains(string(refusedPage), "unknown token") ||
		!strings.Contains(string(refusedPage), "<option value=\"user\" selected>") {
		t.Fatalf("POST with a revoked token: %d\n%s\nwant the form with the error and the type kept", refused.StatusCode, refusedPage)
	}
	noForm, err := http.Get(server.URL + "/plain-ca/sign")
	if err != nil {
		t.Fatal(err)
	}
	noFormPage, _ := io.ReadAll(noForm.Body)
	noForm.Body.Close()
	if noForm.StatusCode != http.StatusOK || !strings.Contains(string(noFormPage), "has no tokens yet") ||
		strings.Contains(string(noFormPage), "<form") {
		t.Fatalf("GET /plain-ca/sign: %d\n%s\nwant the page saying the CA has no tokens", noForm.StatusCode, noFormPage)
	}
	noTokens, err := http.PostForm(server.URL+"/plain-ca/sign", url.Values{"csr": {web}, "token": {token}})
	if err != nil {
		t.Fatal(err)
	}
	noTokens.Body.Close()
	if noTokens.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /plain-ca/sign: %d, want 403", noTokens.StatusCode)
	}
	if noCA, err := http.Get(server.URL + "/nosuch/sign"); err != nil || noCA.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nosuch/sign: %v %v, want 404", noCA.StatusCode, err)
	}

	resp2, err := http.Get(server.URL + "/api/sign")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/sign: %d, want 405", resp2.StatusCode)
	}
	page, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(body), server.URL+"/issuing-ca/api/sign") || strings.Contains(string(body), "/plain-ca/api/sign") {
		t.Fatalf("index page does not show the signing API of the CAs with tokens alone")
	}

	// A domain * allows any name, and --ip prefixes or * allow IP addresses, of the SANs and the CN.
	anyName, err := makeToken(issuingDir, "any-name", time.Hour, []string{"server"}, []string{"*"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken any-name: %v", err)
	}
	ipRange, err := makeToken(issuingDir, "ip-range", time.Hour, []string{"server"}, nil, []string{"10.0.0.0/8", "2001:db8::/32"}, nil)
	if err != nil {
		t.Fatalf("makeToken ip-range: %v", err)
	}
	lab, err := makeToken(issuingDir, "lab", time.Hour, []string{"server"}, []string{"*"}, []string{"*"}, nil)
	if err != nil {
		t.Fatalf("makeToken lab: %v", err)
	}
	ipOnly := csr("ip-only", "-subj", "/CN=10.1.2.3", "-addext", "subjectAltName=IP:10.1.2.3,IP:2001:db8::5")
	ipOutside := csr("ip-outside", "-subj", "/CN=10.1.2.3", "-addext", "subjectAltName=IP:192.0.2.9")
	for _, c := range []struct {
		name, token, csr string
		want             int
	}{
		{"any name, another domain", anyName, outside, http.StatusOK},
		{"any name, an IP SAN", anyName, withIP, http.StatusForbidden},
		{"IP range, IP CN and SANs", ipRange, ipOnly, http.StatusOK},
		{"IP range, an IP outside", ipRange, ipOutside, http.StatusForbidden},
		{"IP range, a DNS name", ipRange, web, http.StatusForbidden},
		{"lab, DNS and IP", lab, withIP, http.StatusOK},
	} {
		status, resp := post("/issuing-ca/api/sign", c.token, "application/json", request(c.csr, ""))
		if status != c.want {
			t.Fatalf("%s: status %d %v, want %d", c.name, status, resp, c.want)
		}
		if c.csr == ipOnly && status == http.StatusOK {
			block, _ := pem.Decode([]byte(resp["certificate"]))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil || len(cert.IPAddresses) != 2 || cert.IPAddresses[0].String() != "10.1.2.3" ||
				cert.IPAddresses[1].String() != "2001:db8::5" {
				t.Fatalf("IP SANs of the certificate: %v, %v, want those of the request", cert.IPAddresses, err)
			}
		}
	}

	// token create --localhost allows localhost and 127.0.0.1; --host and --network limit the
	// clients, which are 127.0.0.1 for the test server.
	for _, args := range [][]string{
		{"--localhost", "--host", "127.0.0.1", "localhost-here"},
		{"--localhost", "--network", "192.0.2.0/24, 198.51.100.0/24", "localhost-elsewhere"},
	} {
		if err := run(append([]string{"token", "create", "--ca-dir", issuingDir}, args...)); err != nil {
			t.Fatalf("token create %v: %v", args, err)
		}
	}
	db, err = loadTokens(issuingDir)
	if err != nil {
		t.Fatalf("loadTokens: %v", err)
	}
	if tok := db.Tokens["localhost-elsewhere"]; !slices.Equal(tok.Domains, []string{"localhost"}) ||
		!slices.Equal(tok.IPs, []string{"127.0.0.1/32"}) ||
		!slices.Equal(tok.Clients, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Fatalf("token entry %+v, want localhost, 127.0.0.1 and the two client prefixes", tok)
	}
	local := csr("localhost", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	for _, c := range []struct {
		name    string
		clients []string
		want    int
	}{
		{"here", []string{"127.0.0.1"}, http.StatusOK},
		{"elsewhere", []string{"192.0.2.0/24"}, http.StatusForbidden},
	} {
		token, err := makeToken(issuingDir, c.name, time.Hour, []string{"server"}, []string{"localhost"},
			[]string{"127.0.0.1"}, c.clients)
		if err != nil {
			t.Fatalf("makeToken %s: %v", c.name, err)
		}
		status, resp := post("/issuing-ca/api/sign", token, "application/json", request(local, ""))
		if status != c.want || (c.want == http.StatusForbidden && resp["error"] != "the token is not allowed from 127.0.0.1") {
			t.Fatalf("localhost certificate with clients %v: %d %v, want %d", c.clients, status, resp, c.want)
		}
	}

	// Behind a trusted proxy, the client is the one its X-Forwarded-For names; the header of a
	// peer that is not trusted is not read.
	proxied, err := makeToken(issuingDir, "proxied", time.Hour, []string{"server"}, []string{"localhost"},
		[]string{"127.0.0.1"}, []string{"192.0.2.50"})
	if err != nil {
		t.Fatalf("makeToken proxied: %v", err)
	}
	behindProxy := httptest.NewServer(newServeMux(caDir, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, false))
	defer behindProxy.Close()
	for _, c := range []struct {
		url, forwarded string
		want           int
	}{
		{behindProxy.URL, "192.0.2.50", http.StatusOK},
		{behindProxy.URL, "", http.StatusForbidden},
		{behindProxy.URL, "192.0.2.51", http.StatusForbidden},
		{server.URL, "192.0.2.50", http.StatusForbidden},
	} {
		req, err := http.NewRequest(http.MethodPost, c.url+"/issuing-ca/api/sign", strings.NewReader(request(local, "")))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+proxied)
		if c.forwarded != "" {
			req.Header.Set("X-Forwarded-For", c.forwarded)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("X-Forwarded-For %q to %s: %d, want %d", c.forwarded, c.url, resp.StatusCode, c.want)
		}
	}
}

func TestClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, c := range []struct {
		peer    string
		headers []string
		want    string
	}{
		{"192.0.2.1:5000", []string{"203.0.113.7"}, "192.0.2.1"},
		{"10.0.0.1:5000", nil, "10.0.0.1"},
		{"10.0.0.1:5000", []string{"203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"198.51.100.9, 203.0.113.7, 10.0.0.2"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"198.51.100.9", "203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"10.0.0.5, 10.0.0.2"}, "10.0.0.5"},
		{"10.0.0.1:5000", []string{"nonsense, 203.0.113.7"}, "203.0.113.7"},
		{"10.0.0.1:5000", []string{"203.0.113.7, nonsense"}, "10.0.0.1"},
		{"[::ffff:10.0.0.1]:5000", []string{"2001:db8::7"}, "2001:db8::7"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/sign", nil)
		r.RemoteAddr = c.peer
		for _, h := range c.headers {
			r.Header.Add("X-Forwarded-For", h)
		}
		if got := clientAddr(r, trusted).String(); got != c.want {
			t.Fatalf("clientAddr from %s with %q = %s, want %s", c.peer, c.headers, got, c.want)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/sign", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := clientAddr(r, nil).String(); got != "10.0.0.1" {
		t.Fatalf("clientAddr without trusted proxies = %s, want the peer 10.0.0.1", got)
	}
}

func TestTokenDefaults(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	write := func(tokens string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"tokens": `+tokens+`}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(name string) *apiToken {
		t.Helper()
		db, err := loadTokens(caDir)
		if err != nil || db.Tokens[name] == nil {
			t.Fatalf("token %s: %v", name, err)
		}
		return db.Tokens[name]
	}
	write(`{"valid": "8h", "types": ["server"], "domains": ["*"], "ips": ["10.0.0.0/8"], "localhost": true,
		"hosts": ["192.168.1.4"], "networks": ["172.16.0.0/12"]}`)

	// Without options, every setting is the default of simple-ca.json.
	if err := run([]string{"token", "create", "--ca-dir", caDir, "defaults"}); err != nil {
		t.Fatalf("token create with the defaults: %v", err)
	}
	tok := entry("defaults")
	if tok.Expires.Sub(tok.Issued) != 8*time.Hour || !slices.Equal(tok.Domains, []string{"*", "localhost"}) ||
		!slices.Equal(tok.IPs, []string{"10.0.0.0/8", "127.0.0.1/32"}) ||
		!slices.Equal(tok.Clients, []string{"192.168.1.4/32", "172.16.0.0/12"}) {
		t.Fatalf("token from the defaults %+v", tok)
	}

	// An option replaces its default; --network replaces hosts and networks together.
	if err := run([]string{"token", "create", "--ca-dir", caDir, "--valid", "30m", "--domain", "example.com",
		"--network", "10.1.0.0/16", "--localhost=false", "options"}); err != nil {
		t.Fatalf("token create with options: %v", err)
	}
	tok = entry("options")
	if tok.Expires.Sub(tok.Issued) != 30*time.Minute || !slices.Equal(tok.Domains, []string{"example.com"}) ||
		!slices.Equal(tok.IPs, []string{"10.0.0.0/8"}) || !slices.Equal(tok.Clients, []string{"10.1.0.0/16"}) {
		t.Fatalf("token with options %+v", tok)
	}

	write(`{"valid": "8 hours", "domains": ["example.com"]}`)
	if err := run([]string{"token", "create", "--ca-dir", caDir, "bad"}); err == nil || !strings.Contains(err.Error(), "tokens.valid") {
		t.Fatalf("token create with tokens.valid \"8 hours\": %v, want an error naming tokens.valid", err)
	}
	if err := run([]string{"token", "create", "--ca-dir", caDir, "--valid", "1h", "good"}); err != nil {
		t.Fatalf("token create with --valid over a bad tokens.valid: %v", err)
	}
}

func TestKebabCaseNames(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"Servers", "lab_servers", "lab--servers", "-lab", "lab-", "lab.servers"} {
		if err := makeCA(caDir, "Bad CA", 3650, name, ""); err == nil || !strings.Contains(err.Error(), "kebab-case") {
			t.Fatalf("makeCA --issuing-ca %q: %v, want a kebab-case error", name, err)
		}
		if _, err := makeToken(caDir, name, time.Hour, []string{"server"}, []string{"example.com"}, nil, nil); err == nil ||
			!strings.Contains(err.Error(), "kebab-case") {
			t.Fatalf("makeToken %q: %v, want a kebab-case error", name, err)
		}
	}
	if err := makeCA(caDir, "Lab Servers CA", 3650, "lab-servers2", ""); err != nil {
		t.Fatalf("makeCA --issuing-ca lab-servers2: %v", err)
	}
	issuingDir := filepath.Join(caDir, "lab-servers2")

	// A kebab-case type works with cert create and with openssl ca through openssl.cnf.
	if err := os.WriteFile(filepath.Join(caDir, configFile),
		[]byte(`{"types": {"web-server": {"key_usage": ["digitalSignature"], "ext_key_usage": ["serverAuth"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := makeCert("web.example.com", nil, issuingDir, "", "web-server", 30, nil, nil); err != nil {
		t.Fatalf("makeCert --type web-server: %v", err)
	}
	conf, err := writeOpenSSLConf(issuingDir)
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

func TestHelpPage(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"help", "docs"} {
		if err := makeCA(caDir, "Pages CA", 3650, name, ""); err == nil || !strings.Contains(err.Error(), "taken") {
			t.Fatalf("makeCA --issuing-ca %s: %v, want it refused", name, err)
		}
	}

	get := func(server *httptest.Server, path string) (int, string) {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return resp.StatusCode, string(body)
	}

	// Without the page's browser files there is no help, and nothing links to it.
	saved := helpSite
	t.Cleanup(func() { helpSite = saved })
	helpSite = nil
	without := httptest.NewServer(newServeMux(caDir, nil, false))
	defer without.Close()
	if status, _ := get(without, "/help/"); status != http.StatusNotFound {
		t.Errorf("/help/ without the assets: status %d, want 404", status)
	}
	for _, path := range []string{"/", "/sign"} {
		if _, body := get(without, path); strings.Contains(body, helpPath) {
			t.Errorf("%s links to %s without the assets", path, helpPath)
		}
	}

	// With them, the help is a page at /help/, linked from the index page and the form.
	pages, err := fs.Sub(helpPages, "help")
	if err != nil {
		t.Fatal(err)
	}
	helpSite = render.New(pages, render.Options{Prefix: helpPath, Search: render.IndexSearch{"index.md"},
		Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	with := httptest.NewServer(newServeMux(caDir, nil, false))
	defer with.Close()
	if status, page := get(with, "/help/"); status != http.StatusOK || !strings.Contains(page, `src="/help/_/assets/page.js"`) {
		t.Errorf("/help/: status %d, want the page shell:\n%s", status, page)
	}
	if status, body := get(with, "/help/_/content?path=%2Fhelp%2F"); status != http.StatusOK ||
		!strings.Contains(body, `"title":"Requesting a certificate"`) || !strings.Contains(body, "## With request-cert") ||
		!strings.Contains(body, "### Send the request") {
		t.Errorf("/help/ content: status %d, want the help:\n%s", status, body)
	}
	for _, path := range []string{"/", "/sign"} {
		if _, body := get(with, path); !strings.Contains(body, `href="/help/"`) {
			t.Errorf("%s does not link to /help/", path)
		}
	}
	// The routes of the CAs stand beside the help.
	if status, _ := get(with, "/ca_cert.pem"); status != http.StatusOK {
		t.Errorf("/ca_cert.pem beside /help/: status %d, want 200", status)
	}
	// The guides are served, and linked from the index page, with serve --docs alone.
	if status, _ := get(with, "/docs/"); status != http.StatusNotFound {
		t.Errorf("/docs/ without --docs: status %d, want 404", status)
	}
	if _, body := get(with, "/"); strings.Contains(body, `href="/docs/"`) {
		t.Error("the index page links to /docs/ without --docs")
	}
	guides, err := fs.Sub(docsPages, "docs")
	if err != nil {
		t.Fatal(err)
	}
	savedDocs := docsSite
	t.Cleanup(func() { docsSite = savedDocs })
	docsSite = render.New(guides, render.Options{Prefix: docsPath, Search: render.IndexSearch{"usage.md"},
		Menu: docsMenu, List: render.DefaultList, Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	withDocs := httptest.NewServer(newServeMux(caDir, nil, true))
	defer withDocs.Close()
	status, page := get(withDocs, "/docs/")
	if status != http.StatusOK || !strings.Contains(page, `<a href="/docs/usage.md" class="current">Usage</a>`) ||
		!strings.Contains(page, `<a href="/docs/signing-api.md">Signing API</a>`) {
		t.Errorf("/docs/: status %d, want the page shell with the menu of the guides:\n%s", status, page)
	}
	for _, name := range []string{"usage.md", "serve.md", "acme.md", "signing-api.md", "development.md"} {
		if status, body := get(withDocs, "/docs/_/content?path=%2Fdocs%2F"+name); status != http.StatusOK ||
			strings.Contains(body, `"error":"`) {
			t.Errorf("/docs/%s: status %d, want the guide:\n%s", name, status, body)
		}
	}
	if _, body := get(withDocs, "/"); !strings.Contains(body, `href="/docs/"`) {
		t.Error("the index page does not link to /docs/ with --docs")
	}
}

func TestTokenWebUI(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	server := httptest.NewServer((&webuiServer{rootDir: caDir, key: "the-key"}).mux())
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}

	// The page and its scripts are served to anyone; the API takes the key alone, for as long as
	// it runs.
	resp, err := http.Get(server.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %v, %v, want the page", resp, err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, script := range []string{"/assets/webui/webui.js", "/assets/webui/tokens.js"} {
		if !strings.Contains(string(page), `<script src="`+script+`">`) {
			t.Errorf("the page does not load %s", script)
		}
		resp, err := http.Get(server.URL + script)
		if err != nil || resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/javascript") {
			t.Errorf("GET %s: %v, %v, want the script", script, resp, err)
			continue
		}
		resp.Body.Close()
	}
	for _, path := range []string{"/assets/webui/", "/assets/webui/missing.js"} {
		if resp, err := http.Get(server.URL + path); err != nil || resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %v, %v, want 404", path, resp, err)
		}
	}
	for _, key := range []string{"", "wrong"} {
		if status, answer := call(key, "GET", "/api/cas", nil); status != http.StatusUnauthorized || answer["error"] == nil {
			t.Errorf("GET /api/cas with the key %q: %d %v, want 401 with an error", key, status, answer)
		}
	}
	for range 2 {
		status, answer := call("the-key", "GET", "/api/cas", nil)
		cas, _ := answer["cas"].([]any)
		if status != http.StatusOK || answer["title"] != "Test CA" || len(cas) != 2 ||
			cas[1].(map[string]any)["label"] != "issuing CA issuing-ca: Issuing CA" || cas[1].(map[string]any)["name"] != "Issuing CA" ||
			fmt.Sprint(cas[1].(map[string]any)["subject_attributes"]) != "[[CN Issuing CA]]" {
			t.Fatalf("GET /api/cas: %d %v, want the root and the issuing CA, with their names and subject attributes", status, answer)
		}
	}

	// A token is created, listed, renewed with a new JWT ID, revoked, kept, and purged.
	if status, answer := call("the-key", "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "Bad_Name",
		"valid": "1h", "domains": []string{"example.com"}}); status != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(answer["error"]), "kebab-case") {
		t.Errorf("create with a bad name: %d %v, want 400 with the error", status, answer)
	}
	status, answer := call("the-key", "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "web-deploy",
		"valid": "8h", "domains": []string{"example.com"}, "clients": []string{"192.168.1.0/24"}, "types": []string{"server"}})
	if status != http.StatusCreated || !strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Fatalf("create: %d %v, want 201 with the token", status, answer)
	}
	status, answer = call("the-key", "GET", "/api/tokens?ca=issuing-ca", nil)
	tokens, _ := answer["tokens"].([]any)
	if status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["name"] != "web-deploy" ||
		fmt.Sprint(tokens[0].(map[string]any)["clients"]) != "[192.168.1.0/24]" {
		t.Fatalf("GET /api/tokens: %d %v, want web-deploy from 192.168.1.0/24", status, answer)
	}
	created, _ := loadTokens(filepath.Join(caDir, "issuing-ca"))
	if status, answer := call("the-key", "POST", "/api/tokens/renew", map[string]any{"ca": "issuing-ca", "name": "web-deploy"}); status != http.StatusOK ||
		!strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Errorf("renew: %d %v, want the renewed token", status, answer)
	}
	if db, _ := loadTokens(filepath.Join(caDir, "issuing-ca")); db.Tokens["web-deploy"].ID == created.Tokens["web-deploy"].ID {
		t.Error("the renewed token has no new JWT ID")
	}
	if status, _ := call("the-key", "POST", "/api/tokens/revoke", map[string]any{"ca": "../x", "name": "web-deploy"}); status != http.StatusNotFound {
		t.Errorf("revoke of a CA outside the root: %d, want 404", status)
	}
	if status, _ := call("the-key", "POST", "/api/tokens/revoke", map[string]any{"ca": "issuing-ca", "name": "web-deploy"}); status != http.StatusOK {
		t.Errorf("revoke: %d, want 200", status)
	}
	status, answer = call("the-key", "GET", "/api/tokens?ca=issuing-ca", nil)
	if tokens, _ := answer["tokens"].([]any); status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["revoked"] != true {
		t.Errorf("GET /api/tokens after revoking: %d %v, want web-deploy kept, revoked", status, answer)
	}
	if status, answer := call("the-key", "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca"}); status != http.StatusOK ||
		answer["removed"] != float64(1) {
		t.Errorf("purge: %d %v, want 1 removed", status, answer)
	}
	if status, _ := call("the-key", "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca", "bogus": true}); status != http.StatusBadRequest {
		t.Errorf("purge with an unknown field: %d, want 400", status)
	}
}

func TestCertWebUI(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 3650, "issuing-ca", ""); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	issuingDir := filepath.Join(caDir, "issuing-ca")
	server := httptest.NewServer((&webuiServer{rootDir: caDir, key: "the-key", certs: true}).mux())
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}

	// The page loads the shared script and its own.
	resp, err := http.Get(server.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %v, %v, want the page", resp, err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, script := range []string{"/assets/webui/webui.js", "/assets/webui/certs.js"} {
		if !strings.Contains(string(page), `<script src="`+script+`">`) {
			t.Errorf("the page does not load %s", script)
		}
	}

	// The API takes the key alone; the CAs come with the name rules, the reasons and the days.
	if status, _ := call("wrong", "GET", "/api/certs?ca=issuing-ca", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/certs with a wrong key: %d, want 401", status)
	}
	status, answer := call("the-key", "GET", "/api/cas", nil)
	if names, _ := answer["names"].(map[string]any); status != http.StatusOK || names["user"] != "user" ||
		fmt.Sprint(answer["defaults"]) != "map[crl_days:30 days:365]" {
		t.Fatalf("GET /api/cas: %d %v, want the name rules and the days", status, answer)
	}
	if status, _ := call("the-key", "POST", "/api/tokens", map[string]any{"ca": ""}); status != http.StatusNotFound {
		t.Errorf("a token request of cert webui: %d, want 404", status)
	}

	// A certificate is created into the CA directory, once; a second create of the name is refused.
	body := map[string]any{"ca": "issuing-ca", "type": "server", "subject": "web.example.com", "sans": []string{"192.0.2.10"}, "days": 30}
	if status, answer := call("the-key", "POST", "/api/certs", body); status != http.StatusCreated {
		t.Fatalf("create: %d %v, want 201", status, answer)
	}
	if !fileExists(filepath.Join(issuingDir, "web_cert.pem")) || !fileExists(filepath.Join(issuingDir, "web_key.pem")) {
		t.Fatal("create wrote no certificate and key to the CA directory")
	}
	if status, _ := call("the-key", "POST", "/api/certs", body); status != http.StatusConflict {
		t.Errorf("create of an existing name: %d, want 409", status)
	}
	if status, answer := call("the-key", "POST", "/api/certs", map[string]any{"ca": "issuing-ca", "type": "server",
		"subject": "not a host", "days": 30}); status != http.StatusBadRequest || answer["error"] == nil {
		t.Errorf("create with a bad CN: %d %v, want 400 with the error", status, answer)
	}

	// A request is signed into the CA directory under the name given, cleaned.
	csrPath := filepath.Join(t.TempDir(), "api.csr")
	if out, err := exec.Command("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", os.DevNull, "-subj", "/CN=api.example.com", "-out", csrPath).CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	csr, _ := os.ReadFile(csrPath)
	status, answer = call("the-key", "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "api server", "csr": string(csr), "days": 30})
	if status != http.StatusCreated || answer["file"] != "api_server_cert.pem" || !fileExists(filepath.Join(issuingDir, "api_server_cert.pem")) {
		t.Fatalf("sign: %d %v, want api_server_cert.pem in the CA directory", status, answer)
	}
	if status, _ := call("the-key", "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "../x", "csr": string(csr), "days": 30}); status != http.StatusBadRequest {
		t.Errorf("sign with a name holding a directory: %d, want 400", status)
	}

	// The certificates are listed; one is revoked for a reason, and the CRL lists it.
	status, answer = call("the-key", "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ := answer["certs"].([]any)
	if status != http.StatusOK || len(certs) != 2 || certs[0].(map[string]any)["status"] != "valid" {
		t.Fatalf("GET /api/certs: %d %v, want the two certificates, valid", status, answer)
	}
	serial := certs[0].(map[string]any)["serial"]

	// A certificate is shown from its file, as cert show writes it; the root CA shows its issuing CAs.
	status, answer = call("the-key", "GET", "/api/certs/show?ca=issuing-ca&serial="+serial.(string), nil)
	fields, _ := answer["fields"].([]any)
	if status != http.StatusOK || answer["file"] != "web_cert.pem" ||
		!slices.ContainsFunc(fields, func(f any) bool { return fmt.Sprint(f) == "[IP address 192.0.2.10]" }) {
		t.Errorf("GET /api/certs/show: %d %v, want web_cert.pem with its IP address", status, answer)
	}
	if status, answer := call("the-key", "GET", "/api/certs/show?ca=issuing-ca&serial=00", nil); status != http.StatusNotFound || answer["error"] == nil {
		t.Errorf("GET /api/certs/show of an unknown serial: %d %v, want 404 with an error", status, answer)
	}
	_, answer = call("the-key", "GET", "/api/certs?ca=", nil)
	rootCerts, _ := answer["certs"].([]any)
	if len(rootCerts) != 1 {
		t.Fatalf("GET /api/certs of the root CA: %v, want the issuing CA", answer)
	}
	if status, answer := call("the-key", "GET", "/api/certs/show?ca=&serial="+rootCerts[0].(map[string]any)["serial"].(string), nil); status != http.StatusOK || answer["file"] != "issuing-ca/ca_cert.pem" {
		t.Errorf("GET /api/certs/show of the issuing CA: %d %v, want issuing-ca/ca_cert.pem", status, answer)
	}

	if status, _ := call("the-key", "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "nonsense"}); status != http.StatusBadRequest {
		t.Errorf("revoke with an unknown reason: %d, want 400", status)
	}
	if status, answer := call("the-key", "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "superseded"}); status != http.StatusOK {
		t.Fatalf("revoke: %d %v, want 200", status, answer)
	}
	if status, _ := call("the-key", "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial}); status != http.StatusBadRequest {
		t.Errorf("revoke twice: %d, want 400", status)
	}
	if status, answer := call("the-key", "POST", "/api/crl", map[string]any{"ca": "issuing-ca", "days": 7}); status != http.StatusOK {
		t.Fatalf("crl: %d %v, want 200", status, answer)
	}
	status, answer = call("the-key", "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ = answer["certs"].([]any)
	crl, _ := answer["crl"].(map[string]any)
	if status != http.StatusOK || certs[0].(map[string]any)["status"] != "revoked" || certs[0].(map[string]any)["reason"] != "superseded" ||
		crl["number"] != "2" {
		t.Errorf("GET /api/certs after revoking: %d %v, want the certificate revoked, superseded, and CRL number 2", status, answer)
	}
}
