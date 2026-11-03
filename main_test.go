package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/skoszewski/serve-markdown/v3/render"
)

// TestMain runs the tests without holding back refused clients; TestAuthGuard holds them back.
func TestMain(m *testing.M) {
	authFreeFailures = 1 << 30
	os.Exit(m.Run())
}

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
	server := httptest.NewServer(newServeMux(caDir, false, false))
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
		"<dd>/CN=Issuing CA</dd>", `<span data-subject="[[&#34;CN&#34;,&#34;Issuing CA&#34;]]">Issuing CA</span>`,
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
	if bundleAt < 0 || bundleAt > strings.Index(string(page), "<main") {
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
	server := &http.Server{Handler: newServeMux(caDir, false, false), ErrorLog: log.New(io.Discard, "", 0)}
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
	token, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server", "user"}, []string{"Example.COM."}, nil, nil)
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
		if _, err := makeToken(caDir, c.name, time.Hour, nil, c.types, c.domains, nil, nil); err == nil {
			t.Fatalf("makeToken %q %v %v succeeded, want an error", c.name, c.types, c.domains)
		}
	}

	// --ip takes addresses, kept as prefixes, prefixes, kept masked, and *.
	for _, ips := range [][]string{{"300.1.2.3"}, {"10.0.0.0/33"}, {"fe80::1%en0"}, {"example.com"}} {
		if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, nil, ips, nil); err == nil {
			t.Fatalf("makeToken --ip %v succeeded, want an error", ips)
		}
		if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"}, nil, ips); err == nil {
			t.Fatalf("makeToken --host %v succeeded, want an error", ips)
		}
	}
	if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"}, nil, []string{"*"}); err == nil {
		t.Fatal("makeToken --host * succeeded, want an error")
	}
	if _, err := makeToken(caDir, "scoped", time.Hour, []string{"admin"}, nil, nil, nil, nil); err == nil {
		t.Fatal("makeToken with an unknown scope succeeded, want an error")
	}
	if _, err := makeToken(caDir, "scoped", time.Hour, []string{"tokens"}, nil, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken with --domain without the scope sign succeeded, want an error")
	}
	for _, c := range []struct{ scopes, types []string }{
		{[]string{"*", "tokens"}, nil}, {nil, []string{"*", "server"}}, {[]string{"*"}, nil},
	} {
		if _, err := makeToken(caDir, "all", time.Hour, c.scopes, c.types, nil, nil, nil); err == nil {
			t.Fatalf("makeToken --scope %v --type %v succeeded, want an error", c.scopes, c.types)
		}
	}
	if _, err := makeToken(caDir, "all", time.Hour, []string{"*"}, []string{"*"}, []string{"example.com"}, nil, nil); err != nil {
		t.Fatalf("makeToken --scope * --type *: %v", err)
	}
	if db, err := loadTokens(caDir); err != nil || !db.Tokens["all"].hasScope("certs") || !allows(db.Tokens["all"].Types, "user") {
		t.Fatalf("the token all: %+v, %v, want every scope and every type", db.Tokens["all"], err)
	}
	if _, err := makeToken(caDir, "ips", time.Hour, nil, []string{"server"}, []string{"*"},
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
	if _, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken with the name of a revoked token succeeded, want an error")
	}
	if err := purgeToken(caDir, "deploy"); err != nil {
		t.Fatalf("purgeToken of the revoked token: %v", err)
	}
	if _, err := makeToken(caDir, "deploy", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err != nil {
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
	if _, err := makeToken(caDir, "short", time.Millisecond, nil, []string{"server"}, []string{"example.com"}, nil, nil); err == nil {
		t.Fatal("makeToken valid for 1ms succeeded, want an error")
	}

	// purgeTokens removes the expired and revoked tokens alone.
	oldJWT, err := makeToken(caDir, "old", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken old: %v", err)
	}
	expire := func() string {
		t.Helper()
		db, err := loadTokens(caDir)
		if err != nil {
			t.Fatalf("loadTokens: %v", err)
		}
		expired := time.Now().Add(-time.Minute)
		db.Tokens["old"].Issued, db.Tokens["old"].Expires = expired.Add(-time.Hour), expired
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
	if db, err := loadTokens(caDir); err != nil || !slices.Equal(slices.Sorted(maps.Keys(db.Tokens)), []string{"all", "deploy"}) {
		t.Fatalf("tokens after purging: %v, %v, want all and deploy, the tokens still accepted", slices.Sorted(maps.Keys(db.Tokens)), err)
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
	token, err := makeToken(issuingDir, "deploy", time.Hour, nil, []string{"server", "user"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	rootToken, err := makeToken(caDir, "root", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken root: %v", err)
	}
	serverOnly, err := makeToken(issuingDir, "server-only", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken server-only: %v", err)
	}
	expired, err := makeToken(issuingDir, "expired", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken expired: %v", err)
	}
	revoked, err := makeToken(issuingDir, "revoked", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken revoked: %v", err)
	}
	if err := revokeToken(issuingDir, "revoked"); err != nil {
		t.Fatalf("revokeToken: %v", err)
	}
	webuiOnly, err := makeToken(issuingDir, "webui-only", time.Hour, []string{"tokens", "certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken webui-only: %v", err)
	}
	anyType, err := makeToken(issuingDir, "any-type", time.Hour, nil, []string{"*"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken any-type: %v", err)
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

	server := httptest.NewServer(newServeMux(caDir, false, false))
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
		{"no scope sign", "/issuing-ca/api/sign", webuiOnly, "application/json", request(web, ""), http.StatusForbidden},
		{"type * passes", "/issuing-ca/api/sign", anyType, "application/json", request(web, "nonexistent"), http.StatusBadRequest},
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
	anyName, err := makeToken(issuingDir, "any-name", time.Hour, nil, []string{"server"}, []string{"*"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken any-name: %v", err)
	}
	ipRange, err := makeToken(issuingDir, "ip-range", time.Hour, nil, []string{"server"}, nil, []string{"10.0.0.0/8", "2001:db8::/32"}, nil)
	if err != nil {
		t.Fatalf("makeToken ip-range: %v", err)
	}
	lab, err := makeToken(issuingDir, "lab", time.Hour, nil, []string{"server"}, []string{"*"}, []string{"*"}, nil)
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
		token, err := makeToken(issuingDir, c.name, time.Hour, nil, []string{"server"}, []string{"localhost"},
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
	proxied, err := makeToken(issuingDir, "proxied", time.Hour, nil, []string{"server"}, []string{"localhost"},
		[]string{"127.0.0.1"}, []string{"192.0.2.50"})
	if err != nil {
		t.Fatalf("makeToken proxied: %v", err)
	}
	t.Cleanup(func() { trustedProxies = nil })
	for _, c := range []struct {
		trusted   bool
		forwarded string
		want      int
	}{
		{true, "192.0.2.50", http.StatusOK},
		{true, "", http.StatusForbidden},
		{true, "192.0.2.51", http.StatusForbidden},
		{false, "192.0.2.50", http.StatusForbidden},
	} {
		trustedProxies = nil
		if c.trusted {
			trustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/issuing-ca/api/sign", strings.NewReader(request(local, "")))
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
			t.Fatalf("X-Forwarded-For %q, proxy trusted %t: %d, want %d", c.forwarded, c.trusted, resp.StatusCode, c.want)
		}
	}
}

func TestClientAddr(t *testing.T) {
	trustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	t.Cleanup(func() { trustedProxies = nil })
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
		if got := clientAddr(r).String(); got != c.want {
			t.Fatalf("clientAddr from %s with %q = %s, want %s", c.peer, c.headers, got, c.want)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/sign", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	trustedProxies = nil
	if got := clientAddr(r).String(); got != "10.0.0.1" {
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
		if _, err := makeToken(caDir, name, time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil); err == nil ||
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
	for _, name := range []string{"help", "docs", "tokens", "certificates"} {
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
	without := httptest.NewServer(newServeMux(caDir, false, false))
	defer without.Close()
	if status, _ := get(without, "/help/"); status != http.StatusNotFound {
		t.Errorf("/help/ without the assets: status %d, want 404", status)
	}
	for _, path := range []string{"/", "/sign"} {
		if _, body := get(without, path); strings.Contains(body, helpPath) {
			t.Errorf("%s links to %s without the assets", path, helpPath)
		}
	}

	// The token and certificate pages are served, and linked from the index page, with webui alone.
	for _, path := range []string{tokensPath, certsPath} {
		if status, _ := get(without, path); status != http.StatusNotFound {
			t.Errorf("%s without webui: status %d, want 404", path, status)
		}
		if _, body := get(without, "/"); strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("the index page links to %s without webui", path)
		}
	}
	withWebUI := httptest.NewServer(newServeMux(caDir, false, true))
	defer withWebUI.Close()
	for _, path := range []string{tokensPath, certsPath} {
		if status, body := get(withWebUI, path); status != http.StatusOK || !strings.Contains(body, `href="/">All CAs</a>`) {
			t.Errorf("%s with webui: status %d, want the page linking to the index page", path, status)
		}
		if _, body := get(withWebUI, "/"); !strings.Contains(body, `href="`+path+`"`) {
			t.Errorf("the index page does not link to %s with webui", path)
		}
	}

	// With them, the help is a page at /help/, linked from the index page and the form.
	pages, err := fs.Sub(helpPages, "help")
	if err != nil {
		t.Fatal(err)
	}
	helpSite = render.New(pages, render.Options{Prefix: helpPath, Search: render.IndexSearch{"index.md"},
		Assets: fstest.MapFS{"page.js": {Data: []byte("// page")}}})
	with := httptest.NewServer(newServeMux(caDir, false, false))
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
	withDocs := httptest.NewServer(newServeMux(caDir, true, false))
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
	key, err := makeToken(caDir, "admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	prefix := "/tokens"
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+prefix+path, reader)
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

	// The page and its scripts are served to anyone; the API takes a token with the scope tokens
	// alone.
	resp, err := http.Get(server.URL + prefix + "/")
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
			t.Errorf("GET /api/cas with the token %q: %d %v, want 401 with an error", key, status, answer)
		}
	}
	signOnly, err := makeToken(caDir, "sign-only", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if status, answer := call(signOnly, "GET", "/api/cas", nil); status != http.StatusForbidden ||
		!strings.Contains(fmt.Sprint(answer["error"]), "scope tokens") {
		t.Errorf("GET /api/cas with a token without the scope tokens: %d %v, want 403 naming the scope", status, answer)
	}
	for range 2 {
		status, answer := call(key, "GET", "/api/cas", nil)
		cas, _ := answer["cas"].([]any)
		if status != http.StatusOK || answer["title"] != "Test CA" || len(cas) != 2 ||
			cas[1].(map[string]any)["id"] != "issuing-ca" || fmt.Sprint(cas[1].(map[string]any)["subject"]) != "[[CN Issuing CA]]" ||
			cas[1].(map[string]any)["label"] != nil || cas[1].(map[string]any)["role"] != nil {
			t.Fatalf("GET /api/cas: %d %v, want the root and the issuing CA, with their IDs and subject attributes alone", status, answer)
		}
	}

	// A token is created, listed, renewed with a new JWT ID, revoked, kept, and purged.
	if status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "Bad_Name",
		"valid": "1h", "domains": []string{"example.com"}}); status != http.StatusBadRequest ||
		!strings.Contains(fmt.Sprint(answer["error"]), "kebab-case") {
		t.Errorf("create with a bad name: %d %v, want 400 with the error", status, answer)
	}
	status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "web-deploy",
		"valid": "8h", "domains": []string{"example.com"}, "clients": []string{"192.168.1.0/24"}, "types": []string{"server"}})
	if status != http.StatusCreated || !strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Fatalf("create: %d %v, want 201 with the token", status, answer)
	}
	status, answer = call(key, "GET", "/api/tokens?ca=issuing-ca", nil)
	tokens, _ := answer["tokens"].([]any)
	if status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["name"] != "web-deploy" ||
		fmt.Sprint(tokens[0].(map[string]any)["clients"]) != "[192.168.1.0/24]" {
		t.Fatalf("GET /api/tokens: %d %v, want web-deploy from 192.168.1.0/24", status, answer)
	}
	created, _ := loadTokens(filepath.Join(caDir, "issuing-ca"))
	if status, answer := call(key, "POST", "/api/tokens/renew", map[string]any{"ca": "issuing-ca", "name": "web-deploy"}); status != http.StatusOK ||
		!strings.HasPrefix(fmt.Sprint(answer["token"]), "eyJ") {
		t.Errorf("renew: %d %v, want the renewed token", status, answer)
	}
	if db, _ := loadTokens(filepath.Join(caDir, "issuing-ca")); db.Tokens["web-deploy"].ID == created.Tokens["web-deploy"].ID {
		t.Error("the renewed token has no new JWT ID")
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "../x", "name": "web-deploy"}); status != http.StatusNotFound {
		t.Errorf("revoke of a CA outside the root: %d, want 404", status)
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "issuing-ca", "name": "web-deploy"}); status != http.StatusOK {
		t.Errorf("revoke: %d, want 200", status)
	}
	status, answer = call(key, "GET", "/api/tokens?ca=issuing-ca", nil)
	if tokens, _ := answer["tokens"].([]any); status != http.StatusOK || len(tokens) != 1 || tokens[0].(map[string]any)["revoked"] != true {
		t.Errorf("GET /api/tokens after revoking: %d %v, want web-deploy kept, revoked", status, answer)
	}
	if status, answer := call(key, "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca"}); status != http.StatusOK ||
		answer["removed"] != float64(1) {
		t.Errorf("purge: %d %v, want 1 removed", status, answer)
	}
	if status, _ := call(key, "POST", "/api/tokens/purge", map[string]any{"ca": "issuing-ca", "bogus": true}); status != http.StatusBadRequest {
		t.Errorf("purge with an unknown field: %d, want 400", status)
	}

	// A token grants sign and its own scopes, and manages the tokens whose scopes it grants.
	if status, _ := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "operator",
		"valid": "1h", "scopes": []string{"certs"}}); status != http.StatusForbidden {
		t.Errorf("creating a token with a scope the token lacks: %d, want 403", status)
	}
	if status, answer := call(key, "POST", "/api/tokens", map[string]any{"ca": "issuing-ca", "name": "helper",
		"valid": "1h", "scopes": []string{"tokens"}}); status != http.StatusCreated {
		t.Errorf("creating a token with the scope tokens: %d %v, want 201", status, answer)
	}
	if _, err := makeToken(filepath.Join(caDir, "issuing-ca"), "operator", time.Hour, []string{"certs"}, nil, nil, nil, nil); err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	if status, _ := call(key, "POST", "/api/tokens/revoke", map[string]any{"ca": "issuing-ca", "name": "operator"}); status != http.StatusForbidden {
		t.Errorf("revoking a token with a scope the token lacks: %d, want 403", status)
	}

	// An issuing CA token opens that CA alone.
	issuingKey, err := makeToken(filepath.Join(caDir, "issuing-ca"), "issuing-admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	status, answer = call(issuingKey, "GET", "/api/cas", nil)
	if cas, _ := answer["cas"].([]any); status != http.StatusOK || len(cas) != 1 || cas[0].(map[string]any)["id"] != "issuing-ca" ||
		answer["user"] != "issuing-admin" || answer["user_ca"] != "issuing-ca" {
		t.Errorf("GET /api/cas with an issuing CA token: %d %v, want the issuing CA alone", status, answer)
	}
	if status, _ := call(issuingKey, "GET", "/api/tokens?ca=", nil); status != http.StatusNotFound {
		t.Errorf("GET /api/tokens of the root CA with an issuing CA token: %d, want 404", status)
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
	key, err := makeToken(caDir, "operator", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	tokensOnly, err := makeToken(caDir, "tokens-only", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	server := httptest.NewServer(newServeMux(caDir, false, true))
	prefix := "/certificates"
	defer server.Close()
	call := func(key, method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			reader = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, server.URL+prefix+path, reader)
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
	resp, err := http.Get(server.URL + prefix + "/")
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

	// The API takes a token with the scope certs alone; the CAs come with the name rules, the
	// reasons and the days.
	if status, _ := call("wrong", "GET", "/api/certs?ca=issuing-ca", nil); status != http.StatusUnauthorized {
		t.Errorf("GET /api/certs with a wrong token: %d, want 401", status)
	}
	if status, _ := call(tokensOnly, "GET", "/api/cas", nil); status != http.StatusForbidden {
		t.Errorf("GET /api/cas with a token without the scope certs: %d, want 403", status)
	}
	status, answer := call(key, "GET", "/api/cas", nil)
	if names, _ := answer["names"].(map[string]any); status != http.StatusOK || names["user"] != "user" ||
		fmt.Sprint(answer["defaults"]) != "map[crl_days:30 days:365]" {
		t.Fatalf("GET /api/cas: %d %v, want the name rules and the days", status, answer)
	}
	if status, _ := call(key, "POST", "/api/tokens", map[string]any{"ca": ""}); status != http.StatusNotFound {
		t.Errorf("a token request of the certificate page: %d, want 404", status)
	}

	// A certificate is created into the CA directory, once; a second create of the name is refused.
	body := map[string]any{"ca": "issuing-ca", "type": "server", "subject": "web.example.com", "sans": []string{"192.0.2.10"}, "days": 30}
	if status, answer := call(key, "POST", "/api/certs", body); status != http.StatusCreated {
		t.Fatalf("create: %d %v, want 201", status, answer)
	}
	if !fileExists(filepath.Join(issuingDir, "web_cert.pem")) || !fileExists(filepath.Join(issuingDir, "web_key.pem")) {
		t.Fatal("create wrote no certificate and key to the CA directory")
	}
	if status, _ := call(key, "POST", "/api/certs", body); status != http.StatusConflict {
		t.Errorf("create of an existing name: %d, want 409", status)
	}
	if status, answer := call(key, "POST", "/api/certs", map[string]any{"ca": "issuing-ca", "type": "server",
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
	status, answer = call(key, "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "api server", "csr": string(csr), "days": 30})
	if status != http.StatusCreated || answer["file"] != "api_server_cert.pem" || !fileExists(filepath.Join(issuingDir, "api_server_cert.pem")) {
		t.Fatalf("sign: %d %v, want api_server_cert.pem in the CA directory", status, answer)
	}
	if status, _ := call(key, "POST", "/api/certs/sign", map[string]any{"ca": "issuing-ca", "type": "server",
		"name": "../x", "csr": string(csr), "days": 30}); status != http.StatusBadRequest {
		t.Errorf("sign with a name holding a directory: %d, want 400", status)
	}

	// The certificates are listed; one is revoked for a reason, and the CRL lists it.
	status, answer = call(key, "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ := answer["certs"].([]any)
	if status != http.StatusOK || len(certs) != 2 || certs[0].(map[string]any)["status"] != "valid" {
		t.Fatalf("GET /api/certs: %d %v, want the two certificates, valid", status, answer)
	}
	serial := certs[0].(map[string]any)["serial"]

	// A certificate is shown from its file, as cert show writes it; the root CA shows its issuing CAs.
	status, answer = call(key, "GET", "/api/certs/show?ca=issuing-ca&serial="+serial.(string), nil)
	shown, _ := answer["certificate"].(map[string]any)
	if status != http.StatusOK || answer["file"] != "web_cert.pem" || fmt.Sprint(shown["ip_addresses"]) != "[192.0.2.10]" ||
		fmt.Sprint(shown["key"]) != "map[algorithm:RSA bits:4096]" || shown["validity"] != "valid" ||
		fmt.Sprint(shown["subject"]) != "[[CN web.example.com]]" ||
		!regexp.MustCompile(`^[0-9A-F]{64}$`).MatchString(fmt.Sprint(shown["sha256_fingerprint"])) {
		t.Errorf("GET /api/certs/show: %d %v, want web_cert.pem with its IP address", status, answer)
	}
	if status, answer := call(key, "GET", "/api/certs/show?ca=issuing-ca&serial=00", nil); status != http.StatusNotFound || answer["error"] == nil {
		t.Errorf("GET /api/certs/show of an unknown serial: %d %v, want 404 with an error", status, answer)
	}
	_, answer = call(key, "GET", "/api/certs?ca=", nil)
	rootCerts, _ := answer["certs"].([]any)
	if len(rootCerts) != 1 {
		t.Fatalf("GET /api/certs of the root CA: %v, want the issuing CA", answer)
	}
	if status, answer := call(key, "GET", "/api/certs/show?ca=&serial="+rootCerts[0].(map[string]any)["serial"].(string), nil); status != http.StatusOK || answer["file"] != "issuing-ca/ca_cert.pem" {
		t.Errorf("GET /api/certs/show of the issuing CA: %d %v, want issuing-ca/ca_cert.pem", status, answer)
	}

	if status, _ := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "nonsense"}); status != http.StatusBadRequest {
		t.Errorf("revoke with an unknown reason: %d, want 400", status)
	}
	if status, answer := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial, "reason": "superseded"}); status != http.StatusOK {
		t.Fatalf("revoke: %d %v, want 200", status, answer)
	}
	if status, _ := call(key, "POST", "/api/certs/revoke", map[string]any{"ca": "issuing-ca", "serial": serial}); status != http.StatusBadRequest {
		t.Errorf("revoke twice: %d, want 400", status)
	}
	if status, answer := call(key, "POST", "/api/crl", map[string]any{"ca": "issuing-ca", "days": 7}); status != http.StatusOK {
		t.Fatalf("crl: %d %v, want 200", status, answer)
	}
	status, answer = call(key, "GET", "/api/certs?ca=issuing-ca", nil)
	certs, _ = answer["certs"].([]any)
	crl, _ := answer["crl"].(map[string]any)
	if status != http.StatusOK || certs[0].(map[string]any)["status"] != "revoked" || certs[0].(map[string]any)["reason"] != "superseded" ||
		crl["number"] != "2" {
		t.Errorf("GET /api/certs after revoking: %d %v, want the certificate revoked, superseded, and CRL number 2", status, answer)
	}
}

func TestSetupCode(t *testing.T) {
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

	// A token with a setup code is pending: it has no JWT, refuses renewal, and lists its code.
	if _, err := addToken(issuingDir, "bad", time.Hour, nil, nil, []string{"example.com"}, nil, nil, 0, []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("addToken with --otc-network without --otc succeeded, want an error")
	}
	code, err := addToken(issuingDir, "remote", 8*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	if ok, _ := regexp.MatchString(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$`, code); !ok {
		t.Fatalf("setup code %q, want four groups of four base32 characters", code)
	}
	db, err := loadTokens(issuingDir)
	if err != nil || !db.Tokens["remote"].pending() || db.Tokens["remote"].revoked() || db.Tokens["remote"].ID != "" ||
		db.Tokens["remote"].Setup.Code != setupCodeHash(code) {
		t.Fatalf("the pending token: %+v, %v, want a setup code and no JWT ID", db.Tokens["remote"], err)
	}
	if _, err := renewToken(issuingDir, "remote", 0); err == nil {
		t.Fatal("renewToken of a pending token succeeded, want an error")
	}
	var b strings.Builder
	if err := listTokens(&b, issuingDir); err != nil || !strings.Contains(b.String(), "setup until ") {
		t.Fatalf("listTokens: %v\n%s, want the setup code of remote", err, b.String())
	}

	// The code is exchanged once, in any letter case and without dashes, for a JWT that signs.
	server := httptest.NewServer(newServeMux(caDir, false, false))
	defer server.Close()
	exchange := func(code string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Post(server.URL+"/api/token-setup", "application/json", strings.NewReader(`{"code": "`+code+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	status, answer := exchange(strings.ToLower(strings.ReplaceAll(code, "-", "")))
	if status != http.StatusOK || answer["ca"] != "issuing-ca" || answer["name"] != "remote" ||
		fmt.Sprint(answer["scopes"]) != "[sign]" {
		t.Fatalf("exchange: %d %v, want the token remote of issuing-ca, with the scope sign", status, answer)
	}
	caCert, err := loadCert(filepath.Join(issuingDir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	db, _ = loadTokens(issuingDir)
	if name, tok, err := checkToken(db, caCert, fmt.Sprint(answer["token"])); err != nil || name != "remote" || tok.pending() ||
		tok.Expires.Sub(tok.Issued) != 8*time.Hour {
		t.Fatalf("the exchanged token: %s %+v %v, want remote, valid for 8h from the exchange", name, tok, err)
	}
	if status, _ := exchange(code); status != http.StatusUnauthorized {
		t.Errorf("exchanging a used code: %d, want 401", status)
	}
	if status, _ := exchange("AAAA-BBBB-CCCC-DDDD"); status != http.StatusUnauthorized {
		t.Errorf("exchanging an unknown code: %d, want 401", status)
	}

	// A code is refused from a client outside its networks and once it has expired, and a pending
	// token is no JWT of the signing API.
	far, err := addToken(caDir, "far", time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("addToken --otc-network: %v", err)
	}
	if status, _ := exchange(far); status != http.StatusForbidden {
		t.Errorf("exchanging from outside --otc-network: %d, want 403", status)
	}
	late, err := addToken(caDir, "late", time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Second, nil)
	if err != nil {
		t.Fatalf("addToken --otc-valid 1s: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if status, answer := exchange(late); status != http.StatusUnauthorized || answer["error"] != "the setup code has expired" {
		t.Errorf("exchanging an expired code: %d %v, want 401, expired", status, answer)
	}
	if n, err := purgeTokens(caDir, 0); err != nil || n != 1 {
		t.Errorf("purgeTokens: %d, %v, want the expired setup code removed", n, err)
	}
	db, _ = loadTokens(caDir)
	if _, _, err := lookupToken(db, &jwtClaims{Subject: "far"}); err == nil {
		t.Error("lookupToken of a pending token with an empty JWT ID succeeded, want an error")
	}

	// A token renewed with a setup code waits for it again: its JWT is refused at once, and the
	// code gives it a new one.
	if _, err := reissueToken(issuingDir, "remote", 0, 0, []string{"10.0.0.0/8"}); err == nil {
		t.Error("reissueToken with --otc-network without --otc succeeded, want an error")
	}
	renewed, err := reissueToken(issuingDir, "remote", 0, time.Hour, nil)
	if err != nil {
		t.Fatalf("reissueToken --otc: %v", err)
	}
	db, _ = loadTokens(issuingDir)
	if _, _, err := checkToken(db, caCert, fmt.Sprint(answer["token"])); err == nil || !db.Tokens["remote"].pending() {
		t.Error("the JWT of a token renewed with a setup code is accepted, want it refused")
	}
	if status, again := exchange(renewed); status != http.StatusOK || again["name"] != "remote" || again["token"] == answer["token"] {
		t.Errorf("exchanging the code of a renewed token: %d %v, want a new JWT of remote", status, again)
	}

	// The signing form takes a setup code for one certificate: a refused request leaves the code,
	// a signed one revokes its token; /api/sign takes no code.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrFor := func(name string) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}
	once, err := addToken(issuingDir, "once", time.Hour, nil, []string{"server"}, []string{"example.com"}, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	client := netip.MustParseAddr("127.0.0.1")
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", false); err == nil {
		t.Error("signWithToken of a setup code without setupCodes succeeded, want an error")
	}
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.org"), "", true); err == nil {
		t.Error("signWithToken of a setup code for a name the token does not allow succeeded, want an error")
	}
	cert, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", true)
	if err != nil {
		t.Fatalf("signWithToken of a setup code: %v", err)
	}
	db, _ = loadTokens(issuingDir)
	if tok := db.Tokens["once"]; !tok.revoked() || !slices.Equal(tok.Certs, []string{serialHex(cert.SerialNumber)}) {
		t.Errorf("the token of the setup code: %+v, want it revoked, with the certificate", tok)
	}
	if _, _, _, err := signWithToken(issuingDir, once, client, csrFor("web.example.com"), "", true); err == nil {
		t.Error("signWithToken of a used setup code succeeded, want an error")
	}

	// The setup code page exchanges a code once.
	page, err := addToken(caDir, "page", time.Hour, []string{"tokens"}, nil, nil, nil, nil, time.Hour, nil)
	if err != nil {
		t.Fatalf("addToken --otc: %v", err)
	}
	for _, c := range []struct {
		want int
		text string
	}{{http.StatusOK, "Your token <strong>page</strong>"}, {http.StatusUnauthorized, "unknown or used setup code"}} {
		resp, err := http.PostForm(server.URL+"/token-setup", url.Values{"code": {page}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want || !strings.Contains(string(body), c.text) {
			t.Errorf("POST /token-setup: %d, want %d with %q", resp.StatusCode, c.want, c.text)
		}
	}

	// A token is described with its limits from tokens-db.json, and a JWT read without its CA
	// with what it holds alone.
	pendingCode, err := addToken(caDir, "pending", 8*time.Hour, nil, nil, []string{"example.com"}, nil, nil, time.Hour,
		[]string{"10.0.0.0/8"})
	if err != nil || pendingCode == "" {
		t.Fatalf("addToken --otc: %v", err)
	}
	db, _ = loadTokens(caDir)
	described := fmt.Sprint(describeToken("pending", db.Tokens["pending"], true))
	for _, s := range []string{"[Status waits for its setup code", "[Domains example.com]", "[Code usable from 10.0.0.0/8]",
		"[Valid after the exchange 8h]"} {
		if !strings.Contains(described, s) {
			t.Errorf("describeToken of a pending token: %s, want %q", described, s)
		}
	}
	jwt, err := makeToken(caDir, "held", time.Hour, []string{"certs"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("makeToken: %v", err)
	}
	c, err := verifyJWT(nil, jwt)
	if err != nil || c.Subject != "held" || c.Scope != "certs" {
		t.Fatalf("verifyJWT without a CA: %+v, %v, want the claims of held", c, err)
	}
	if described := fmt.Sprint(describeToken(c.Subject, &apiToken{Scopes: strings.Fields(c.Scope)}, false)); strings.Contains(described, "Used from") {
		t.Errorf("describeToken without limits: %s, want no limits", described)
	}
}

func TestTokenAccessAcrossCAs(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	cas := []string{"", "servers", "clients", "devices"}
	for _, id := range cas[1:] {
		if err := makeCA(rootDir, "CA "+id, 3650, id, ""); err != nil {
			t.Fatalf("makeCA %s: %v", id, err)
		}
	}
	label := func(id string) string {
		if id == "" {
			return "root"
		}
		return id
	}
	path := func(id string) string {
		if id == "" {
			return ""
		}
		return "/" + id
	}
	caCerts := map[string]*x509.Certificate{}
	for _, id := range cas {
		cert, err := loadCert(filepath.Join(rootDir, id, "ca_cert.pem"))
		if err != nil {
			t.Fatal(err)
		}
		caCerts[id] = cert
	}

	// Every CA has tokens of the same four names, so a name of one CA never opens another.
	names := []string{"signer", "keeper", "operator", "master"}
	scopesOf := map[string][]string{"signer": {"sign"}, "keeper": {"tokens"}, "operator": {"certs"}, "master": {"*"}}
	has := func(name, scope string) bool { return allows(scopesOf[name], scope) }
	jwts := map[string]map[string]string{}
	for _, id := range cas {
		jwts[id] = map[string]string{}
		for _, name := range names {
			var types, domains []string
			if has(name, "sign") {
				types, domains = []string{"server"}, []string{"example.com"}
			}
			jwt, err := makeToken(filepath.Join(rootDir, id), name, time.Hour, scopesOf[name], types, domains, nil, nil)
			if err != nil {
				t.Fatalf("makeToken %s of %s: %v", name, label(id), err)
			}
			jwts[id][name] = jwt
		}
	}

	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	do := func(method, target, token, contentType, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+target, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	call := func(token, method, target string, body any) (int, map[string]any) {
		t.Helper()
		b := ""
		if body != nil {
			j, _ := json.Marshal(body)
			b = string(j)
		}
		return do(method, target, token, "application/json", b)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	signBody := map[string]string{"csr": csr}
	apiSignStatus := func(token, target string) int {
		t.Helper()
		status, answer := call(token, "POST", path(target)+"/api/sign", signBody)
		if status == http.StatusOK {
			block, _ := pem.Decode(fmt.Append(nil, answer["certificate"]))
			if block == nil {
				t.Errorf("POST %s/api/sign: no certificate in %v", path(target), answer)
				return status
			}
			if cert, err := x509.ParseCertificate(block.Bytes); err != nil || cert.CheckSignatureFrom(caCerts[target]) != nil {
				t.Errorf("POST %s/api/sign: a certificate not signed by the CA %s: %v", path(target), label(target), err)
			}
		}
		return status
	}
	formSignStatus := func(token, target string) int {
		t.Helper()
		resp, err := http.PostForm(server.URL+path(target)+"/sign", url.Values{"token": {token}, "csr": {csr}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") != "application/x-pem-file" {
			t.Errorf("POST %s/sign: %s, want a certificate", path(target), resp.Header.Get("Content-Type"))
		}
		return resp.StatusCode
	}

	// The signing API and the signing form of a CA take a token of that CA with the scope sign
	// alone; a token of another CA is unknown to them, whatever its name.
	for _, owner := range cas {
		for _, name := range names {
			for _, target := range cas {
				want := http.StatusUnauthorized
				if owner == target {
					want = http.StatusForbidden
					if has(name, "sign") {
						want = http.StatusOK
					}
				}
				if status := apiSignStatus(jwts[owner][name], target); status != want {
					t.Errorf("POST %s/api/sign with %s of %s: %d, want %d", path(target), name, label(owner), status, want)
				}
				if status := formSignStatus(jwts[owner][name], target); status != want {
					t.Errorf("POST %s/sign with %s of %s: %d, want %d", path(target), name, label(owner), status, want)
				}
			}
		}
	}

	// The token and certificate pages take a token of any CA with their scope: a root CA token
	// opens every CA, and an issuing CA token its own CA alone.
	for _, page := range []struct{ prefix, scope, list string }{{"/tokens", "tokens", "/api/tokens"}, {"/certificates", "certs", "/api/certs"}} {
		for _, owner := range cas {
			for _, name := range names {
				token, who := jwts[owner][name], name+" of "+label(owner)
				status, answer := call(token, "GET", page.prefix+"/api/cas", nil)
				if !has(name, page.scope) {
					if status != http.StatusForbidden || !strings.Contains(fmt.Sprint(answer["error"]), "scope "+page.scope) {
						t.Errorf("GET %s/api/cas with %s: %d %v, want 403 naming the scope", page.prefix, who, status, answer)
					}
				} else {
					var ids []string
					list, _ := answer["cas"].([]any)
					for _, ca := range list {
						ids = append(ids, fmt.Sprint(ca.(map[string]any)["id"]))
					}
					want := []string{owner}
					if owner == "" {
						want = []string{"", "clients", "devices", "servers"}
					}
					if status != http.StatusOK || !slices.Equal(ids, want) || answer["user"] != name || answer["user_ca"] != owner {
						t.Errorf("GET %s/api/cas with %s: %d %v, want the CAs %q", page.prefix, who, status, answer, want)
					}
				}
				for _, target := range cas {
					want := http.StatusForbidden
					if has(name, page.scope) {
						want = http.StatusNotFound
						if owner == "" || owner == target {
							want = http.StatusOK
						}
					}
					if status, answer := call(token, "GET", page.prefix+page.list+"?ca="+target, nil); status != want {
						t.Errorf("GET %s%s?ca=%s with %s: %d %v, want %d", page.prefix, page.list, target, who, status, answer, want)
					}

					// A change of a CA is refused alike; a token made on the token page is signed by the
					// key of its CA, whichever CA the token of the request belongs to.
					wantChange := want
					if page.scope == "tokens" {
						made := "made-" + name + "-of-" + label(owner) + "-in-" + label(target)
						if want == http.StatusOK {
							wantChange = http.StatusCreated
						}
						status, answer := call(token, "POST", "/tokens/api/tokens",
							map[string]any{"ca": target, "name": made, "valid": "1h", "domains": []string{"example.com"}})
						if status != wantChange {
							t.Errorf("creating %s in %s with %s: %d %v, want %d", made, label(target), who, status, answer, wantChange)
							continue
						}
						if status == http.StatusCreated {
							for _, id := range cas {
								if _, err := verifyJWT(caCerts[id], fmt.Sprint(answer["token"])); (err == nil) != (id == target) {
									t.Errorf("the token %s verifies with the CA %s: %v, want it signed by %s alone", made, label(id), err == nil, label(target))
								}
							}
						}
					} else if status, answer := call(token, "POST", "/certificates/api/crl", map[string]any{"ca": target, "days": 7}); status != wantChange {
						t.Errorf("POST /certificates/api/crl of %s with %s: %d %v, want %d", label(target), who, status, answer, wantChange)
					}
				}
			}
		}
	}

	// A root CA token manages the tokens of an issuing CA; an issuing CA token those of no other
	// CA. A revoked token of one CA leaves the token of the same name of another CA working.
	if status, answer := call(jwts["servers"]["keeper"], "POST", "/tokens/api/tokens/revoke",
		map[string]any{"ca": "clients", "name": "signer"}); status != http.StatusNotFound {
		t.Errorf("revoking signer of clients with keeper of servers: %d %v, want 404", status, answer)
	}
	if status, answer := call(jwts["servers"]["keeper"], "POST", "/tokens/api/tokens/purge", map[string]any{"ca": ""}); status != http.StatusNotFound {
		t.Errorf("purging the tokens of the root CA with keeper of servers: %d %v, want 404", status, answer)
	}
	if status, answer := call(jwts[""]["keeper"], "POST", "/tokens/api/tokens/renew",
		map[string]any{"ca": "servers", "name": "master"}); status != http.StatusForbidden {
		t.Errorf("renewing master of servers with keeper of root: %d %v, want 403, a scope keeper lacks", status, answer)
	}
	if status, answer := call(jwts[""]["keeper"], "POST", "/tokens/api/tokens/revoke",
		map[string]any{"ca": "servers", "name": "signer"}); status != http.StatusOK {
		t.Fatalf("revoking signer of servers with keeper of root: %d %v, want 200", status, answer)
	}
	if status := apiSignStatus(jwts["servers"]["signer"], "servers"); status != http.StatusUnauthorized {
		t.Errorf("POST /servers/api/sign with the revoked signer of servers: %d, want 401", status)
	}
	for _, id := range []string{"", "clients", "devices"} {
		if status := apiSignStatus(jwts[id]["signer"], id); status != http.StatusOK {
			t.Errorf("POST %s/api/sign with signer of %s after revoking signer of servers: %d, want 200", path(id), label(id), status)
		}
	}
	if status, answer := call(jwts[""]["master"], "POST", "/tokens/api/tokens/renew",
		map[string]any{"ca": "devices", "name": "keeper"}); status != http.StatusOK {
		t.Fatalf("renewing keeper of devices with master of root: %d %v, want 200", status, answer)
	} else {
		if status, _ := call(jwts["devices"]["keeper"], "GET", "/tokens/api/cas", nil); status != http.StatusUnauthorized {
			t.Errorf("GET /tokens/api/cas with the JWT of keeper of devices before its renewal: %d, want 401", status)
		}
		if status, answer := call(fmt.Sprint(answer["token"]), "GET", "/tokens/api/cas", nil); status != http.StatusOK || answer["user_ca"] != "devices" {
			t.Errorf("GET /tokens/api/cas with the renewed keeper of devices: %d %v, want devices", status, answer)
		}
	}

	// A setup code is exchanged for a token of its own CA, and the signing form of a CA takes the
	// codes of that CA alone; the signing API and the pages take no code.
	codes := map[string]string{}
	for _, id := range cas[1:] {
		code, err := addToken(filepath.Join(rootDir, id), "remote", time.Hour, nil, []string{"server"}, []string{"example.com"},
			nil, nil, time.Hour, nil)
		if err != nil {
			t.Fatalf("addToken --otc in %s: %v", id, err)
		}
		codes[id] = code
	}
	status, answer := call("", "POST", "/api/token-setup", map[string]string{"code": codes["servers"]})
	if status != http.StatusOK || answer["ca"] != "servers" || answer["name"] != "remote" {
		t.Fatalf("exchanging the code of servers: %d %v, want remote of servers", status, answer)
	}
	for _, target := range cas {
		want := http.StatusUnauthorized
		if target == "servers" {
			want = http.StatusOK
		}
		if status := apiSignStatus(fmt.Sprint(answer["token"]), target); status != want {
			t.Errorf("POST %s/api/sign with remote of servers from its code: %d, want %d", path(target), status, want)
		}
	}
	for _, target := range []string{"", "servers", "devices"} {
		if status := formSignStatus(codes["clients"], target); status != http.StatusUnauthorized {
			t.Errorf("POST %s/sign with the code of clients: %d, want 401", path(target), status)
		}
	}
	if status := apiSignStatus(codes["clients"], "clients"); status != http.StatusUnauthorized {
		t.Errorf("POST /clients/api/sign with the code of clients: %d, want 401", status)
	}
	for _, prefix := range []string{"/tokens", "/certificates"} {
		if status, _ := call(codes["clients"], "GET", prefix+"/api/cas", nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s/api/cas with the code of clients: %d, want 401", prefix, status)
		}
	}
	if status := formSignStatus(codes["clients"], "clients"); status != http.StatusOK {
		t.Errorf("POST /clients/sign with the code of clients: %d, want 200", status)
	}
	if status, answer := call("", "POST", "/api/token-setup", map[string]string{"code": codes["clients"]}); status != http.StatusUnauthorized {
		t.Errorf("exchanging the code of clients used on its signing form: %d %v, want 401", status, answer)
	}

	// A token used from a client it does not allow is refused by every path.
	far, err := makeToken(filepath.Join(rootDir, "devices"), "far", time.Hour, []string{"*"}, []string{"server"},
		[]string{"example.com"}, nil, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("makeToken --network: %v", err)
	}
	if status := apiSignStatus(far, "devices"); status != http.StatusForbidden {
		t.Errorf("POST /devices/api/sign from outside the networks of the token: %d, want 403", status)
	}
	if status := formSignStatus(far, "devices"); status != http.StatusForbidden {
		t.Errorf("POST /devices/sign from outside the networks of the token: %d, want 403", status)
	}
	for _, prefix := range []string{"/tokens", "/certificates"} {
		if status, _ := call(far, "GET", prefix+"/api/cas", nil); status != http.StatusForbidden {
			t.Errorf("GET %s/api/cas from outside the networks of the token: %d, want 403", prefix, status)
		}
	}

	// A JWT with a changed payload or header, or without a signature, is invalid everywhere.
	parts := strings.Split(jwts["clients"]["signer"], ".")
	var claims map[string]any
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["scope"] = "*"
	widened, _ := json.Marshal(claims)
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	for what, forged := range map[string]string{
		"a widened scope":    parts[0] + "." + base64.RawURLEncoding.EncodeToString(widened) + "." + parts[2],
		"the algorithm none": none + "." + parts[1] + ".",
		"no signature":       parts[0] + "." + parts[1] + ".",
	} {
		if status := apiSignStatus(forged, "clients"); status != http.StatusUnauthorized {
			t.Errorf("POST /clients/api/sign with %s: %d, want 401", what, status)
		}
		for _, prefix := range []string{"/tokens", "/certificates"} {
			if status, _ := call(forged, "GET", prefix+"/api/cas", nil); status != http.StatusUnauthorized {
				t.Errorf("GET %s/api/cas with %s: %d, want 401", prefix, what, status)
			}
		}
	}

	// An entry copied from the tokens of one CA into those of another does not make its JWT a
	// token of the other CA: the JWT is still checked with the key of the CA.
	serversDB, err := loadTokens(filepath.Join(rootDir, "servers"))
	if err != nil {
		t.Fatal(err)
	}
	clientsDB, err := loadTokens(filepath.Join(rootDir, "clients"))
	if err != nil {
		t.Fatal(err)
	}
	clientsDB.Tokens["master"] = serversDB.Tokens["master"]
	if err := clientsDB.save(filepath.Join(rootDir, "clients")); err != nil {
		t.Fatal(err)
	}
	if status := apiSignStatus(jwts["servers"]["master"], "clients"); status != http.StatusUnauthorized {
		t.Errorf("POST /clients/api/sign with master of servers copied into clients: %d, want 401", status)
	}
	if status, answer := call(jwts["servers"]["master"], "GET", "/tokens/api/tokens?ca=clients", nil); status != http.StatusNotFound {
		t.Errorf("GET /tokens/api/tokens?ca=clients with master of servers copied into clients: %d %v, want 404", status, answer)
	}

	// A CA outside the root CA directory, or one that does not exist, is not found.
	for _, target := range []string{"/nowhere/api/sign", "/.servers/api/sign"} {
		if status, _ := call(jwts[""]["master"], "POST", target, signBody); status != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", target, status)
		}
	}
	for _, ca := range []string{"..", "../servers", "servers/../clients", "Servers", "nowhere"} {
		for _, target := range []string{"/tokens/api/tokens", "/certificates/api/certs"} {
			if status, _ := call(jwts[""]["master"], "GET", target+"?ca="+url.QueryEscape(ca), nil); status != http.StatusNotFound {
				t.Errorf("GET %s?ca=%s with master of root: %d, want 404", target, ca, status)
			}
		}
	}
}

func TestOIDC(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(rootDir, "Clients CA", 3650, "clients", ""); err != nil {
		t.Fatalf("makeCA clients: %v", err)
	}

	// A test provider, counting the JWKS fetches.
	b64 := base64.RawURLEncoding.EncodeToString
	newKey := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	jwk := func(kid string, k *rsa.PrivateKey) map[string]string {
		return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": "AQAB"}
	}
	key1, key2, stranger := newKey(), newKey(), newKey()
	var mu sync.Mutex
	keys, fetches := []map[string]string{jwk("k1", key1)}, 0
	var idp *httptest.Server
	idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/authorize",
				"token_endpoint": idp.URL + "/token", "jwks_uri": idp.URL + "/jwks"})
		case "/jwks":
			mu.Lock()
			fetches++
			json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			mu.Unlock()
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	// idToken returns a valid ID token with claims overridden, signed by key as kid.
	idToken := func(kid string, key *rsa.PrivateKey, claims map[string]any) string {
		t.Helper()
		now := time.Now().Unix()
		c := map[string]any{"iss": idp.URL, "aud": "simple-ca", "sub": "subject-" + fmt.Sprint(claims["preferred_username"]),
			"iat": now, "exp": now + 300, "nonce": randomID()}
		maps.Copy(c, claims)
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
		payload, _ := json.Marshal(c)
		signed := b64(header) + "." + b64(payload)
		digest := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signed + "." + b64(sig)
	}
	user := func(name string, more map[string]any) map[string]any {
		c := map[string]any{"preferred_username": name}
		maps.Copy(c, more)
		return c
	}

	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	do := func(method, target, token string, body any) (int, map[string]any) {
		t.Helper()
		j, _ := json.Marshal(body)
		req, err := http.NewRequest(method, server.URL+target, bytes.NewReader(j))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer resp.Body.Close()
		var answer map[string]any
		json.NewDecoder(resp.Body).Decode(&answer)
		return resp.StatusCode, answer
	}
	signIn := func(raw string) (int, map[string]any) {
		t.Helper()
		return do("POST", "/api/oidc-token", "", map[string]string{"id_token": raw})
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Without oidc in simple-ca.json, the sign-in is off.
	if status, _ := do("GET", "/api/oidc", "", nil); status != http.StatusNotFound {
		t.Errorf("GET /api/oidc without oidc: %d, want 404", status)
	}
	if status, _ := signIn(idToken("k1", key1, user("alice@example.com", nil))); status != http.StatusNotFound {
		t.Errorf("POST /api/oidc-token without oidc: %d, want 404", status)
	}

	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	write(oidcUsersFile, `{
  "profiles": [
    {"name": "ca-admin", "token": {"valid": "8h", "scopes": ["tokens", "certs"]}},
    {"name": "web-signer", "ca": "clients", "token": {"scopes": ["sign"], "domains": ["example.com"]}},
    {"name": "viewer", "ca": "clients", "token": {"scopes": ["certs"], "networks": ["10.0.0.0/8"]}}
  ],
  "rules": [
    {"users": ["alice@example.com", "henry@example.com"], "profile": "ca-admin"},
    {"groups": ["web-team"], "profile": "web-signer"}
  ]
}`)
	cfg, err := loadConfig(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOIDC(rootDir, cfg); err != nil {
		t.Fatalf("checkOIDC: %v", err)
	}
	status, answer := do("GET", "/api/oidc", "", nil)
	if status != http.StatusOK || answer["label"] != "Entra ID" || answer["client_id"] != "simple-ca" ||
		answer["authorization_endpoint"] != idp.URL+"/authorize" || answer["token_endpoint"] != idp.URL+"/token" ||
		answer["redirect_path"] != "/oidc-callback" || fmt.Sprint(answer["scopes"]) != "[openid profile email]" {
		t.Errorf("GET /api/oidc: %d %v, want the settings of the Entra ID sign-in", status, answer)
	}

	// A user of a rule gets the token of its profile, and the ID token works once.
	alice := idToken("k1", key1, user("alice@example.com", nil))
	status, answer = signIn(alice)
	if status != http.StatusOK || answer["ca"] != "" || answer["name"] != "alice-example-com" ||
		fmt.Sprint(answer["scopes"]) != "[tokens certs]" {
		t.Fatalf("sign-in of alice: %d %v, want the token alice-example-com of the root CA", status, answer)
	}
	first := fmt.Sprint(answer["token"])
	status, answer = do("GET", "/tokens/api/cas", first, nil)
	if user, _ := answer["user_token"].(map[string]any); status != http.StatusOK || answer["user"] != "alice-example-com" ||
		fmt.Sprint(user["oidc"]) != fmt.Sprintf("map[issuer:%s subject:subject-alice@example.com user:alice@example.com]", idp.URL) {
		t.Errorf("GET /tokens/api/cas with the token of alice: %d %v, want alice-example-com of OIDC user alice", status, answer)
	}
	if status, _ := signIn(alice); status != http.StatusUnauthorized {
		t.Errorf("a used ID token: %d, want 401", status)
	}

	// An active token is reported, then replaced or reused.
	again := idToken("k1", key1, user("alice@example.com", nil))
	status, answer = signIn(again)
	if active, _ := answer["active"].(map[string]any); status != http.StatusConflict || active["name"] != "alice-example-com" ||
		active["ca"] != "" || active["expires"] == nil {
		t.Errorf("second sign-in of alice: %d %v, want 409 naming the active token", status, answer)
	}
	if status, _ := do("GET", "/tokens/api/cas", first, nil); status != http.StatusOK {
		t.Errorf("the token of the first sign-in after a sign-in not replacing it: %d, want 200", status)
	}
	signInWith := func(raw string, choice map[string]any) (int, map[string]any) {
		t.Helper()
		body := map[string]any{"id_token": raw}
		maps.Copy(body, choice)
		return do("POST", "/api/oidc-token", "", body)
	}
	if status, _ := signInWith(again, map[string]any{"reuse": true}); status != http.StatusBadRequest {
		t.Errorf("reusing the token without reuse_token: %d, want 400", status)
	}
	if status, _ := signInWith(again, map[string]any{"replace": true, "reuse": true}); status != http.StatusBadRequest {
		t.Errorf("replace and reuse together: %d, want 400", status)
	}
	status, answer = signInWith(again, map[string]any{"replace": true})
	if status != http.StatusOK {
		t.Fatalf("second sign-in of alice replacing the token: %d %v, want 200", status, answer)
	}
	second := fmt.Sprint(answer["token"])
	if status, _ := do("GET", "/tokens/api/cas", first, nil); status != http.StatusUnauthorized {
		t.Errorf("the replaced token of the first sign-in: %d, want 401", status)
	}
	if status, _ := signInWith(again, map[string]any{"replace": true}); status != http.StatusUnauthorized {
		t.Errorf("the ID token of the replacing sign-in again: %d, want 401", status)
	}
	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca", "reuse_token": true}}`)
	if status, answer := do("GET", "/api/oidc", "", nil); status != http.StatusOK || answer["reuse_token"] != true {
		t.Errorf("GET /api/oidc with reuse_token: %d %v, want reuse_token true", status, answer)
	}
	status, answer = signInWith(idToken("k1", key1, user("alice@example.com", nil)), map[string]any{"reuse": true})
	if status != http.StatusOK || answer["token"] != second {
		t.Errorf("third sign-in of alice reusing the token: %d %v, want the token of the second sign-in", status, answer)
	}
	if status, _ := do("GET", "/tokens/api/cas", second, nil); status != http.StatusOK {
		t.Errorf("the reused token: %d, want 200", status)
	}
	write(configFile, `{"oidc": {"provider": "entra", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)

	// A revoked token of the user is replaced without asking.
	if err := revokeToken(rootDir, "alice-example-com"); err != nil {
		t.Fatal(err)
	}
	if status, answer := signIn(idToken("k1", key1, user("alice@example.com", nil))); status != http.StatusOK {
		t.Errorf("sign-in of alice with the token revoked: %d %v, want 200", status, answer)
	}
	db, _ := loadTokens(rootDir)
	if tok := db.Tokens["alice-example-com"]; tok.OIDC == nil || tok.Expires.Sub(tok.Issued) != 8*time.Hour {
		t.Errorf("the token of alice: %+v, want the OIDC user, valid for 8h", tok)
	}
	if _, err := renewToken(rootDir, "alice-example-com", 0); err != nil {
		t.Fatal(err)
	}
	if db, _ := loadTokens(rootDir); db.Tokens["alice-example-com"].OIDC == nil {
		t.Error("the renewed token of alice lost its OIDC user")
	}

	// A group rule comes before the roles.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.example.com"}, DNSNames: []string{"web.example.com"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	signBody := map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	status, answer = signIn(idToken("k1", key1, user("bob@example.com", map[string]any{"groups": []string{"web-team"},
		"roles": []string{"ca-admin"}})))
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "bob-example-com" {
		t.Fatalf("sign-in of bob in web-team: %d %v, want the token of web-signer in clients", status, answer)
	}
	bob := fmt.Sprint(answer["token"])
	if status, answer := do("POST", "/clients/api/sign", bob, signBody); status != http.StatusOK {
		t.Errorf("POST /clients/api/sign with the token of bob: %d %v, want 200", status, answer)
	}
	if status, _ := do("POST", "/api/sign", bob, signBody); status != http.StatusUnauthorized {
		t.Errorf("POST /api/sign of the root CA with the token of bob: %d, want 401", status)
	}

	// Profiles by role, a disallowed client, and a user without a profile.
	status, answer = signIn(idToken("k1", key1, user("carol@example.com", map[string]any{"roles": []string{"viewer", "web-signer", "other"}})))
	if status != http.StatusOK || answer["ca"] != "clients" || fmt.Sprint(answer["scopes"]) != "[sign]" {
		t.Errorf("sign-in of carol with the roles viewer and web-signer: %d %v, want web-signer", status, answer)
	}
	if status, _ := signIn(idToken("k1", key1, user("dave@example.com", map[string]any{"roles": []string{"viewer"}}))); status != http.StatusForbidden {
		t.Errorf("sign-in of dave, viewer from outside its networks: %d, want 403", status)
	}
	if status, _ := signIn(idToken("k1", key1, user("erin@example.com", map[string]any{"roles": []string{"other"}}))); status != http.StatusForbidden {
		t.Errorf("sign-in of erin without a profile: %d, want 403", status)
	}
	if _, err := makeToken(rootDir, "henry-example-com", time.Hour, []string{"tokens"}, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if status, _ := signIn(idToken("k1", key1, user("henry@example.com", nil))); status != http.StatusConflict {
		t.Errorf("sign-in of henry, whose token name is taken: %d, want 409", status)
	}

	// Invalid ID tokens.
	now := time.Now().Unix()
	for name, raw := range map[string]string{
		"another key":    idToken("k1", stranger, user("alice@example.com", nil)),
		"an unknown key": idToken("k9", key1, user("alice@example.com", nil)),
		"another issuer": idToken("k1", key1, user("alice@example.com", map[string]any{"iss": "https://elsewhere.example.com"})),
		"another client": idToken("k1", key1, user("alice@example.com", map[string]any{"aud": []string{"other"}})),
		"another azp":    idToken("k1", key1, user("alice@example.com", map[string]any{"azp": "other"})),
		"expired":        idToken("k1", key1, user("alice@example.com", map[string]any{"exp": now - 1})),
		"future":         idToken("k1", key1, user("alice@example.com", map[string]any{"iat": now + 600})),
		"no nonce":       idToken("k1", key1, user("alice@example.com", map[string]any{"nonce": ""})),
		"not a JWT":      "not-a-jwt",
	} {
		if status, answer := signIn(raw); status != http.StatusUnauthorized {
			t.Errorf("an ID token of %s: %d %v, want 401", name, status, answer)
		}
	}

	// A new JWKS key is fetched after oidcKeysRefetch.
	mu.Lock()
	keys = append(keys, jwk("k2", key2))
	before := fetches
	mu.Unlock()
	client := newOIDCClient(rootDir)
	oc, _, _ := cfg.OIDC.resolved(cfg.path)
	if _, err := client.checkIDToken(oc, idToken("k1", key1, user("alice@example.com", nil))); err != nil {
		t.Fatalf("checkIDToken: %v", err)
	}
	client.keys = map[string]crypto.PublicKey{"k1": &key1.PublicKey}
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err == nil {
		t.Error("checkIDToken with a key of the JWKS not fetched again yet succeeded, want an error")
	}
	client.keysAt = time.Now().Add(-oidcKeysRefetch)
	if _, err := client.checkIDToken(oc, idToken("k2", key2, user("alice@example.com", nil))); err != nil {
		t.Errorf("checkIDToken with the new key k2: %v", err)
	}
	mu.Lock()
	if fetches != before+2 {
		t.Errorf("JWKS fetches: %d, want %d", fetches-before, 2)
	}
	mu.Unlock()

	// Keycloak realm and client roles.
	write(configFile, `{"oidc": {"provider": "keycloak", "issuer": "`+idp.URL+`", "client_id": "simple-ca"}}`)
	status, answer = signIn(idToken("k1", key1, user("frank", map[string]any{"realm_access": map[string]any{"roles": []string{"web-signer"}}})))
	if status != http.StatusOK || answer["ca"] != "clients" || answer["name"] != "frank" {
		t.Errorf("sign-in of frank with the realm role web-signer: %d %v, want web-signer", status, answer)
	}
	status, answer = signIn(idToken("k1", key1, user("grace", map[string]any{"resource_access": map[string]any{
		"simple-ca": map[string]any{"roles": []string{"ca-admin"}}, "other": map[string]any{"roles": []string{"web-signer"}}}})))
	if status != http.StatusOK || answer["ca"] != "" {
		t.Errorf("sign-in of grace with the client role ca-admin: %d %v, want ca-admin", status, answer)
	}

	// Invalid settings and profiles.
	for name, c := range map[string]string{
		"an unknown provider": `{"oidc": {"provider": "other", "issuer": "https://idp.example.com", "client_id": "x"}}`,
		"no client ID":        `{"oidc": {"issuer": "https://idp.example.com"}}`,
		"an issuer not a URL": `{"oidc": {"issuer": "idp.example.com", "client_id": "x"}}`,
	} {
		cfg := &config{path: configFile}
		if err := json.Unmarshal([]byte(c), cfg); err != nil {
			t.Fatal(err)
		}
		if err := checkOIDC(rootDir, cfg); err == nil {
			t.Errorf("checkOIDC with %s succeeded, want an error", name)
		}
	}
	for name, users := range map[string]string{
		"an unknown CA":       `{"profiles": [{"name": "a", "ca": "nowhere", "token": {"scopes": ["certs"]}}]}`,
		"a profile name":      `{"profiles": [{"name": "CA Admin", "token": {"scopes": ["certs"]}}]}`,
		"a profile twice":     `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}, {"name": "a", "token": {"scopes": ["certs"]}}]}`,
		"keep_expired":        `{"profiles": [{"name": "a", "token": {"scopes": ["certs"], "keep_expired": "1h"}}]}`,
		"sign without names":  `{"profiles": [{"name": "a", "token": {"scopes": ["sign"]}}]}`,
		"an unknown profile":  `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}], "rules": [{"users": ["x"], "profile": "b"}]}`,
		"a rule without whom": `{"profiles": [{"name": "a", "token": {"scopes": ["certs"]}}], "rules": [{"profile": "a"}]}`,
		"an unknown key":      `{"profiles": [], "groups": []}`,
	} {
		write(oidcUsersFile, users)
		if err := checkOIDC(rootDir, cfg); err == nil {
			t.Errorf("checkOIDC with %s in %s succeeded, want an error", name, oidcUsersFile)
		}
	}
}

func TestAuthGuard(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	free := authFreeFailures
	authFreeFailures = 2
	t.Cleanup(func() { authFreeFailures = free })

	// A client is counted by its address, an IPv6 client by its /64.
	for _, c := range [][2]string{{"192.0.2.10", "192.0.2.10/32"}, {"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"}} {
		if key := guardKey(netip.MustParseAddr(c[0])); key.String() != c[1] {
			t.Errorf("guardKey(%s) = %s, want %s", c[0], key, c[1])
		}
	}

	// The hold doubles with each refusal past the free ones, up to authMaxWait.
	g := newAuthGuard()
	client := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("2001:db8:1:2:bbbb::2")
	refusedErr := apiErr(http.StatusUnauthorized, "invalid token")
	for i, want := range []time.Duration{0, 0, time.Second, 2 * time.Second, 4 * time.Second} {
		g.record(client, refusedErr)
		if hold := time.Until(g.clients[guardKey(client)].until); hold > want || (want > 0 && hold < want-time.Second) {
			t.Errorf("refusal %d: hold %s, want %s", i+1, hold, want)
		}
	}
	for range 40 {
		g.record(client, refusedErr)
	}
	if hold := time.Until(g.clients[guardKey(client)].until); hold > authMaxWait {
		t.Errorf("hold %s after many refusals, want at most %s", hold, authMaxWait)
	}
	w := httptest.NewRecorder()
	if err := g.check(w, client); err == nil || w.Header().Get("Retry-After") == "" {
		t.Errorf("check of a held client: %v, Retry-After %q, want 429 and Retry-After", err, w.Header().Get("Retry-After"))
	}
	if err := g.check(httptest.NewRecorder(), other); err != nil {
		t.Errorf("check of another client: %v, want none", err)
	}
	g.record(client, apiErr(http.StatusForbidden, "the token does not have the scope tokens"))
	if g.clients[guardKey(client)] == nil {
		t.Error("an error other than 401 forgot the refusals, want them kept")
	}
	g.record(client, nil)
	if err := g.check(httptest.NewRecorder(), client); err != nil {
		t.Errorf("check after a success: %v, want none", err)
	}

	// The routes checking credentials share the guard, fresh of the refusals of the other tests.
	shared := guard
	guard = newAuthGuard()
	t.Cleanup(func() { guard = shared })
	rootDir := t.TempDir()
	if err := makeCA(rootDir, "Root CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	admin, err := makeToken(rootDir, "admin", time.Hour, []string{"tokens"}, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServeMux(rootDir, false, true))
	defer server.Close()
	call := func(method, path, token, body string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	forged := admin[:len(admin)-4] + "AAAA"
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized} {
		if resp := call("GET", "/tokens/api/cas", forged, ""); resp.StatusCode != want {
			t.Errorf("forged token %d: %d, want %d", i+1, resp.StatusCode, want)
		}
	}
	for _, c := range []struct{ name, method, path, token, body string }{
		{"the token page with its token", "GET", "/tokens/api/cas", admin, ""},
		{"the signing API", "POST", "/api/sign", forged, `{"csr": ""}`},
		{"a setup code", "POST", "/api/token-setup", "", `{"code": "AAAA-BBBB-CCCC-DDDD"}`},
	} {
		if resp := call(c.method, c.path, c.token, c.body); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Errorf("%s while held back: %d, Retry-After %q, want 429", c.name, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if resp := call("GET", "/tokens/api/cas", admin, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("the token page after the hold: %d, want 200", resp.StatusCode)
	}
	if resp := call("GET", "/tokens/api/cas", forged, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a forged token after a success: %d, want 401", resp.StatusCode)
	}
	if resp := call("GET", "/tokens/api/cas", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", resp.StatusCode)
	}
}

func TestThemeConfig(t *testing.T) {
	css, err := themeConfig{Light: map[string]string{"head": "#7c2d12", "action": "oklch(0.55 0.2 40)"},
		Dark: map[string]string{"head": " darkred "}}.css("simple-ca.json")
	if err != nil || string(css) != ":root { --action: oklch(0.55 0.2 40); --head: #7c2d12; }\n"+
		`:root[data-theme="dark"] { --head: darkred; }`+"\n" {
		t.Errorf("css: %q, %v, want the variables of both themes", css, err)
	}
	if css, err := (themeConfig{}).css("simple-ca.json"); err != nil || css != "" {
		t.Errorf("css without colours: %q, %v, want none", css, err)
	}
	for _, theme := range []themeConfig{
		{Light: map[string]string{"header": "#123456"}},
		{Dark: map[string]string{"head": "red; } body { display: none"}},
		{Dark: map[string]string{"head": "url(x)"}},
	} {
		if _, err := theme.css("simple-ca.json"); err == nil {
			t.Errorf("css of %+v succeeded, want an error", theme)
		}
	}

	// theme.json of a CA directory holds the colours of that CA alone, none without it.
	dir := t.TempDir()
	if theme, err := loadTheme(dir); err != nil || theme.Light != nil || theme.Dark != nil {
		t.Errorf("loadTheme without theme.json: %+v, %v, want none", theme, err)
	}
	if css := pageTheme(dir); css != "" {
		t.Errorf("pageTheme without theme.json: %q, want none", css)
	}
	for _, c := range []struct{ file, want string }{
		{`{"light": {"head": "#7f1d1d"}}`, ":root { --head: #7f1d1d; }\n"},
		{`{"theme": {"light": {"head": "#7f1d1d"}}}`, ""},
		{`{"light": {"head": "not a colour"}}`, ""},
	} {
		if err := os.WriteFile(filepath.Join(dir, themeFile), []byte(c.file), 0o644); err != nil {
			t.Fatal(err)
		}
		if theme, err := loadTheme(dir); (err == nil) != (c.want != "") || (err == nil && theme.Light["head"] != "#7f1d1d") {
			t.Errorf("loadTheme of %s: %+v, %v, want the colours or an error", c.file, theme, err)
		}
		if css := pageTheme(dir); string(css) != c.want {
			t.Errorf("pageTheme of %s: %q, want %q", c.file, css, c.want)
		}
	}
}
