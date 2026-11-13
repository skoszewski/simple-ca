package main

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
)

// TestMain runs the tests without holding back refused clients; TestAuthGuard holds them back.
// With SIMPLE_CA_TEST_MAIN=1 it runs main with the arguments of the test binary instead.
func TestMain(m *testing.M) {
	if os.Getenv("SIMPLE_CA_TEST_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	authFreeFailures = 1 << 30
	os.Exit(m.Run())
}

// verifyCert verifies the certificate cert against the CA bundle with openssl.
func verifyCert(t *testing.T, bundle, cert string) {
	t.Helper()
	out, err := exec.Command("openssl", "verify", "-CAfile", bundle, cert).CombinedOutput()
	if err != nil {
		t.Fatalf("certificate verification failed for %s:\n%s", cert, out)
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
		{nil, cli.ErrUsage},
		{[]string{"-h"}, nil},
		{[]string{"ca"}, cli.ErrUsage},
		{[]string{"cert"}, cli.ErrUsage},
		{[]string{"crl"}, cli.ErrUsage},
		{[]string{"token"}, cli.ErrUsage},
		{[]string{"cert", "-h"}, nil},
		{[]string{"token", "--help"}, nil},
		{[]string{"nosuch"}, cli.ErrUsage},
		{[]string{"cert", "nosuch"}, cli.ErrUsage},
		{[]string{"make-ca", "--ca-dir", caDir, "Old"}, cli.ErrUsage},
		{[]string{"list-tokens"}, cli.ErrUsage},
		{[]string{"cert", "create", "-h"}, flag.ErrHelp},
		{[]string{"cert", "show"}, cli.ErrUsage},
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
