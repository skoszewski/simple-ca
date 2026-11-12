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

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
)

// runCaptured runs the command line args and returns what it wrote to stdout and stderr.
func runCaptured(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	stdout, stderr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outC, errC := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(outR); outC <- string(b) }()
	go func() { b, _ := io.ReadAll(errR); errC <- string(b) }()
	os.Stdout, os.Stderr = outW, errW
	runErr := run(args)
	os.Stdout, os.Stderr = stdout, stderr
	outW.Close()
	errW.Close()
	return <-outC, <-errC, runErr
}

func TestUsage(t *testing.T) {
	out, _, err := runCaptured(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Usage: simple-ca-lite GROUP COMMAND [options] [ARGS]\n") {
		t.Errorf("usage does not name simple-ca-lite:\n%s", out)
	}
	for _, g := range []string{"ca", "cert", "crl", "key"} {
		if !strings.Contains(out, "\n  "+g+" ") {
			t.Errorf("usage does not list the group %s:\n%s", g, out)
		}
	}
	for _, g := range []string{"token", "audit", "serve", "context"} {
		if strings.Contains(out, "\n  "+g+" ") {
			t.Errorf("usage lists %s:\n%s", g, out)
		}
	}
	if strings.Contains(out, "simple-ca ") || strings.Contains(out, "simple-ca\n") {
		t.Errorf("usage names simple-ca:\n%s", out)
	}
}

func TestNoArguments(t *testing.T) {
	out, errOut, err := runCaptured(t)
	if !errors.Is(err, cli.ErrUsage) {
		t.Errorf("no arguments: %v, want the usage error", err)
	}
	if out != "" || !strings.HasPrefix(errOut, "Usage: simple-ca-lite ") {
		t.Errorf("no arguments: stdout %q, stderr %q, want the usage on stderr", out, errOut)
	}
}

func TestUnknownCommands(t *testing.T) {
	for _, args := range [][]string{{"token", "create", "x"}, {"serve"}, {"audit", "list"}, {"context"}} {
		_, errOut, err := runCaptured(t, args...)
		if !errors.Is(err, cli.ErrUsage) {
			t.Errorf("%v: %v, want the usage error", args, err)
		}
		if want := "simple-ca-lite: unknown command \"" + args[0] + "\"\n"; !strings.HasPrefix(errOut, want) {
			t.Errorf("%v: stderr %q, want it to start with %q", args, errOut, want)
		}
	}
}

func TestVersion(t *testing.T) {
	out, _, err := runCaptured(t, "--version")
	if err != nil {
		t.Fatal(err)
	}
	if want := "simple-ca-lite version " + version() + "\n"; out != want {
		t.Errorf("--version: %q, want %q", out, want)
	}
}

func TestCertificateFlow(t *testing.T) {
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", "")
	root := t.TempDir()
	servers := filepath.Join(root, "servers")
	steps := [][]string{
		{"ca", "create", "--ca-dir", root, "--key-type", "ec", "Lite Root CA"},
		{"ca", "create", "--ca-dir", root, "--issuing-ca", "servers", "Lite Servers CA"},
		{"cert", "create", "--ca-dir", servers, "web.example.com"},
	}
	for _, args := range steps {
		if _, errOut, err := runCaptured(t, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, errOut)
		}
	}
	for _, f := range []string{
		filepath.Join(root, "ca_cert.pem"),
		filepath.Join(servers, "ca_cert.pem"),
		filepath.Join(servers, "web_cert.pem"),
		filepath.Join(servers, "web_key.pem"),
	} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%v", err)
		}
	}

	// The issued certificate is a valid entry of the index of the issuing CA.
	index, err := os.ReadFile(filepath.Join(servers, "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(index)), "\n"); len(lines) != 1 ||
		!strings.HasPrefix(lines[0], "V\t") || !strings.HasSuffix(lines[0], "/CN=web.example.com") {
		t.Errorf("index.txt of servers: %q, want one valid entry of web.example.com", index)
	}

	out, errOut, err := runCaptured(t, "cert", "list", "--ca-dir", servers)
	if err != nil {
		t.Fatalf("cert list: %v\n%s", err, errOut)
	}
	if !strings.Contains(out, "valid") || !strings.Contains(out, "web.example.com") {
		t.Errorf("cert list: %q, want the valid certificate of web.example.com", out)
	}

	args := []string{"cert", "revoke", "--ca-dir", servers, "--reason", "superseded",
		filepath.Join(servers, "web_cert.pem")}
	if _, errOut, err := runCaptured(t, args...); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, errOut)
	}
	index, err = os.ReadFile(filepath.Join(servers, "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(index), "R\t") || !strings.Contains(string(index), ",superseded") {
		t.Errorf("index.txt of servers after cert revoke: %q, want a revoked entry", index)
	}

	out, errOut, err = runCaptured(t, "crl", "create", "--ca-dir", root, "--all")
	if err != nil {
		t.Fatalf("crl create --all: %v\n%s", err, errOut)
	}
	for _, d := range []string{root, servers} {
		if !strings.Contains(out, "CRL written to "+filepath.Join(d, "crl.pem")) {
			t.Errorf("crl create --all: %q, want the CRL of %s", out, d)
		}
		if b, err := os.ReadFile(filepath.Join(d, "crl.pem")); err != nil || !strings.Contains(string(b), "-----BEGIN X509 CRL-----") {
			t.Errorf("crl.pem of %s: %v, want a PEM CRL", d, err)
		}
	}
}
