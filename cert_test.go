package main

import (
	"bytes"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestUserCert(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}

	if _, err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing-ca"), "", "user", 365, nil, nil, ""); err != nil {
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

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if _, err := makeCert("test", []string{"test.example.com"}, caDir, certDir, "server", 365, nil, nil, ""); err != nil {
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

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if _, err := makeCert("web.example.com", []string{"web", "www.example.com", "192.0.2.1", "2001:db8::1", "1.3.6.1.4.1.99999.1"},
		caDir, "", "server", 365, nil, nil, ""); err != nil {
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
		if _, err := makeCert(c.cn, c.sans, caDir, "", "server", 365, nil, nil, ""); err == nil {
			t.Fatalf("expected an error for CN %q and SANs %v", c.cn, c.sans)
		}
	}
}

func TestUserSubjects(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
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
		if _, err := makeCert(c.args[0], c.args[1:], caDir, "", "user", 365, nil, nil, ""); err != nil {
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
		if _, err := makeCert(args[0], args[1:], caDir, "", "user", 365, nil, nil, ""); err == nil {
			t.Fatalf("expected an error for %v", args)
		}
	}
}

func TestInvalidIPSAN(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if _, err := makeCert("test", []string{"999.1.1.1"}, caDir, "", "server", 365, nil, nil, ""); err == nil {
		t.Fatal("expected error for invalid IPv4 SAN")
	}
}

func TestListAndInfo(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	for _, name := range []string{"alice", "bob"} {
		if _, err := makeCert(name, nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
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

	if err := makeCA(caDir, "Test CA", 3650, "", "http://pki.example.com", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := makeCert("Alice Example", []string{"alice@example.com"}, filepath.Join(caDir, "issuing-ca"), "", "user", 365, nil, nil, ""); err != nil {
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

func TestEKU(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if _, err := makeCert("device01.example.com", nil, caDir, "", "server", 365,
		[]string{"clientAuth", "1.3.6.1.4.1.99999.10"}, nil, ""); err != nil {
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

	if _, err := makeCert("Signer", nil, caDir, "", "user", 365, []string{"TIMESTAMPING", "codeSigning"}, nil, ""); err != nil {
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
		if _, err := makeCert("bad.example.com", nil, caDir, "", "server", 365, []string{eku}, nil, ""); err == nil {
			t.Fatalf("expected an error for EKU %q", eku)
		}
	}
}

func TestKeyUsageAndNone(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
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
		if _, err := makeCert(c.cn, nil, caDir, "", c.certType, 365, c.ekus, c.kus, ""); err != nil {
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
		if _, err := makeCert("bad.example.com", c.sans, caDir, "", c.certType, 365, nil, c.kus, ""); err == nil {
			t.Fatalf("expected an error for type %s, SANs %v and key usages %v", c.certType, c.sans, c.kus)
		}
	}
}
