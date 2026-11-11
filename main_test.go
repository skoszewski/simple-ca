package main

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
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

func TestKebabCaseNames(t *testing.T) {
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"Servers", "lab_servers", "lab--servers", "-lab", "lab-", "lab.servers"} {
		if err := makeCA(caDir, "Bad CA", 3650, name, "", "rsa"); err == nil || !strings.Contains(err.Error(), "kebab-case") {
			t.Fatalf("makeCA --issuing-ca %q: %v, want a kebab-case error", name, err)
		}
	}
	if err := makeCA(caDir, "Lab Servers CA", 0, "lab-servers2", "", "rsa"); err != nil {
		t.Fatalf("makeCA --issuing-ca lab-servers2: %v", err)
	}
	issuingDir := filepath.Join(caDir, "lab-servers2")

	// A kebab-case type works with cert create and with openssl ca through openssl.cnf.
	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile),
		[]byte(`{"types": {"web-server": {"key_usage": ["digitalSignature"], "ext_key_usage": ["serverAuth"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := makeCert("web.example.com", nil, issuingDir, "", "web-server", 30, nil, nil, ""); err != nil {
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
