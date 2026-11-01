package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCert returns a certificate for cn, a CA with ca, signed by parent and its key, or self-signed
// when parent is nil, and its key.
func testCert(t *testing.T, cn string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// writePEM writes certs to a PEM file in a temporary directory and returns its path.
func writePEM(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var b []byte
	for _, cert := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "ca_bundle.pem")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadCAs(t *testing.T) {
	root, rootKey := testCert(t, "Root CA", true, nil, nil)
	issuing, _ := testCert(t, "Issuing CA", true, root, rootKey)
	leaf, _ := testCert(t, "web.example.com", false, root, rootKey)
	other, otherKey := testCert(t, "Other Root CA", true, nil, nil)
	foreign, _ := testCert(t, "Foreign CA", true, other, otherKey)

	gotRoot, gotIssuing, err := loadCAs(writePEM(t, issuing, root))
	if err != nil || gotRoot.Subject.CommonName != "Root CA" || len(gotIssuing) != 1 || gotIssuing[0].Subject.CommonName != "Issuing CA" {
		t.Fatalf("loadCAs of the bundle: %v, %v, %v; want the root and its issuing CA", gotRoot, gotIssuing, err)
	}
	der := filepath.Join(t.TempDir(), "ca_cert.crt")
	if err := os.WriteFile(der, root.Raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if gotRoot, gotIssuing, err := loadCAs(der); err != nil || gotRoot.Subject.CommonName != "Root CA" || len(gotIssuing) != 0 {
		t.Errorf("loadCAs of the DER root: %v, %v, %v; want the root alone", gotRoot, gotIssuing, err)
	}
	for name, test := range map[string]struct {
		certs []*x509.Certificate
		want  string
	}{
		"a leaf":                 {[]*x509.Certificate{root, leaf}, "is not a CA certificate"},
		"two roots":              {[]*x509.Certificate{root, other}, "more than one root CA"},
		"no root":                {[]*x509.Certificate{issuing}, "no root CA"},
		"another root's CA":      {[]*x509.Certificate{root, foreign}, "is not signed by the root CA"},
		"a CA with another root": {[]*x509.Certificate{foreign, other, root}, "more than one root CA"},
	} {
		if _, _, err := loadCAs(writePEM(t, test.certs...)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("loadCAs of %s: %v, want an error saying %q", name, err, test.want)
		}
	}
}

func TestAddListRemove(t *testing.T) {
	dir := t.TempDir()
	savedLayouts, savedGOOS := layouts, goos
	layouts, goos = []layout{{filepath.Join(t.TempDir(), "missing"), []string{"false"}}, {dir, []string{"true"}}}, "linux"
	t.Cleanup(func() { layouts, goos = savedLayouts, savedGOOS })

	root, rootKey := testCert(t, "Root CA", true, nil, nil)
	issuing, _ := testCert(t, "Issuing CA", true, root, rootKey)
	caDir := filepath.Dir(writePEM(t, root, issuing))
	issuingDir := filepath.Join(caDir, "issuing-ca")
	if err := os.Mkdir(issuingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(issuingDir, "ca_cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuing.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"add", "--ca-dir", caDir}); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, cert := range []*x509.Certificate{root, issuing} {
		b, err := os.ReadFile(filepath.Join(dir, fileName(cert)))
		if block, _ := pem.Decode(b); err != nil || block == nil || string(block.Bytes) != string(cert.Raw) {
			t.Errorf("add wrote no PEM %s for %s: %v", fileName(cert), cert.Subject, err)
		}
	}
	t.Setenv("SIMPLE_CA_DIR", caDir)
	if err := run([]string{"add"}); err != nil {
		t.Errorf("add again from SIMPLE_CA_DIR: %v, want the CAs left as they are", err)
	}
	if err := run([]string{"list"}); err != nil {
		t.Errorf("list: %v", err)
	}
	if err := run([]string{"remove", "--machine", "--ca-dir", issuingDir}); err != nil {
		t.Fatalf("remove from the issuing CA's directory: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("remove left %v", left)
	}
	if err := run([]string{"add", "--ca-dir", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "ca_bundle.pem") {
		t.Errorf("add from a directory without ca_bundle.pem: %v, want an error naming it", err)
	}

	for _, args := range [][]string{{"add", "--user"}, {"add", caDir}, {"list", "extra"}, {"trust"}} {
		if err := run(args); err != errUsage {
			t.Errorf("run %v: %v, want the usage", args, err)
		}
	}
	goos = "darwin"
	if err := run([]string{"add", "--ca-dir", caDir}); err == nil || !strings.Contains(err.Error(), "Linux version") {
		t.Errorf("add on darwin: %v, want an error naming the Linux version", err)
	}
}
