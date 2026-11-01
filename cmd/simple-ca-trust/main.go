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

// Command simple-ca-trust adds the root CA and the issuing CAs of a simple-ca CA to the system
// trust store of Linux, removes them, and lists them.
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

// layout is the trust store of a Linux distribution: the directory of the trust anchors the
// administrator adds, and the command that rebuilds the trust store from it.
type layout struct {
	dir     string
	refresh []string
}

// layouts are the trust stores simple-ca-trust knows, the first one whose directory exists used.
var layouts = []layout{
	{"/usr/local/share/ca-certificates", []string{"update-ca-certificates"}},
	{"/etc/pki/ca-trust/source/anchors", []string{"update-ca-trust", "extract"}},
}

// goos is the operating system simple-ca-trust runs on.
var goos = runtime.GOOS

const usage = `Usage:
  simple-ca-trust add [--machine] [--ca-dir DIR | --file FILE]
  simple-ca-trust remove [--machine] [--ca-dir DIR | --file FILE]
  simple-ca-trust list [--machine]
  simple-ca-trust --version

Adds the root CA and the issuing CAs of the CA in --ca-dir, read from ca_bundle.pem of its root
CA, to the system trust store of Linux, removes them, or lists the CAs it added. --ca-dir is the
directory of the root CA or of one of its issuing CAs, or a directory holding a copy of
ca_bundle.pem; it defaults to SIMPLE_CA_DIR, else the working directory. --file names the root
CA certificate or a CA bundle, PEM or DER, instead. Linux has only the system store, --machine,
the default, and changing it needs root.
`

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return nil
	case "-version", "--version":
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		if version == "" {
			version = "dev"
		}
		fmt.Println("simple-ca-trust", version)
		return nil
	case "add", "remove", "list":
	default:
		fmt.Fprintf(os.Stderr, "simple-ca-trust: unknown command %q\n\n%s", args[0], usage)
		return errUsage
	}

	command := args[0]
	flags := flag.NewFlagSet("simple-ca-trust "+command, flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(flags.Output(), usage) }
	flags.Bool("machine", true, "change the system trust store, the only one of Linux")
	user := flags.Bool("user", false, "the store of the current user, which Linux does not have")
	caDir := flags.String("ca-dir", "", "directory of the root CA or of one of its issuing CAs")
	file := flags.String("file", "", "the root CA certificate or a CA bundle, instead of --ca-dir")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "simple-ca-trust %s: wrong number of arguments\n\n%s", command, usage)
		return errUsage
	}
	if *caDir != "" && *file != "" {
		fmt.Fprintf(os.Stderr, "simple-ca-trust %s: --ca-dir and --file cannot be given together\n\n%s", command, usage)
		return errUsage
	}
	if *user {
		fmt.Fprintln(os.Stderr, "simple-ca-trust: Linux has only the system trust store; --user is not available")
		return errUsage
	}
	if goos != "linux" {
		return errors.New("this is the Linux version of simple-ca-trust; Windows and macOS have their own, " +
			"built from trust/windows and trust/macos")
	}

	var store *layout
	for i := range layouts {
		if info, err := os.Stat(layouts[i].dir); err == nil && info.IsDir() {
			store = &layouts[i]
			break
		}
	}
	if store == nil {
		return fmt.Errorf("no known trust store: neither %s nor %s exists", layouts[0].dir, layouts[1].dir)
	}

	if command == "list" {
		return list(store.dir)
	}
	path := *file
	if path == "" {
		dir := *caDir
		if dir == "" {
			dir = os.Getenv("SIMPLE_CA_DIR")
		}
		if dir == "" {
			dir = "."
		}
		dir, err := filepath.Abs(dir)
		if err != nil {
			return err
		}

		// The directory of an issuing CA, whose certificate is not self-signed, is in that of its root CA.
		if certs, err := readCerts(filepath.Join(dir, "ca_cert.pem")); err == nil && !bytes.Equal(certs[0].RawSubject, certs[0].RawIssuer) {
			dir = filepath.Dir(dir)
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		path = filepath.Join(dir, "ca_bundle.pem")
	}
	root, issuing, err := loadCAs(path)
	if err != nil {
		return err
	}
	changed := false
	for _, cert := range append([]*x509.Certificate{root}, issuing...) {
		role := "issuing CA"
		if cert == root {
			role = "root CA"
		}
		path := filepath.Join(store.dir, fileName(cert))
		if command == "add" {
			if _, err := os.Stat(path); err == nil {
				fmt.Printf("%s %s is trusted already\n", role, cert.Subject)
				continue
			}
			err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
		} else {
			err = os.Remove(path)
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Printf("%s %s is not trusted by simple-ca-trust\n", role, cert.Subject)
				continue
			}
		}
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("%s: permission denied; changing the system trust store needs root, run it with sudo", store.dir)
		}
		if err != nil {
			return err
		}
		changed = true
		if command == "add" {
			fmt.Printf("%s %s added as %s\n", role, cert.Subject, path)
		} else {
			fmt.Printf("%s %s removed\n", role, cert.Subject)
		}
	}
	if !changed {
		return nil
	}
	refresh := exec.Command(store.refresh[0], store.refresh[1:]...)
	refresh.Stdout, refresh.Stderr = os.Stderr, os.Stderr
	if err := refresh.Run(); err != nil {
		return fmt.Errorf("%s: %w", store.refresh[0], err)
	}
	return nil
}

// loadCAs returns the root CA in the PEM or DER file at path and the issuing CAs it signed: the
// file must hold exactly one CA certificate signed by its own key, and every other certificate
// must be a CA certificate signed by it.
func loadCAs(path string) (*x509.Certificate, []*x509.Certificate, error) {
	certs, err := readCerts(path)
	if err != nil {
		return nil, nil, err
	}
	var root *x509.Certificate
	for _, cert := range certs {
		if !cert.IsCA {
			return nil, nil, fmt.Errorf("%s: %s is not a CA certificate", path, cert.Subject)
		}
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
			if root != nil {
				return nil, nil, fmt.Errorf("%s: more than one root CA: %s and %s", path, root.Subject, cert.Subject)
			}
			root = cert
		}
	}
	if root == nil {
		return nil, nil, fmt.Errorf("%s: no root CA, a CA certificate signed by its own key", path)
	}
	var issuing []*x509.Certificate
	for _, cert := range certs {
		if cert == root {
			continue
		}
		if err := cert.CheckSignatureFrom(root); err != nil {
			return nil, nil, fmt.Errorf("%s: %s is not signed by the root CA %s", path, cert.Subject, root.Subject)
		}
		issuing = append(issuing, cert)
	}
	return root, issuing, nil
}

// readCerts returns the certificates of the PEM file at path, or of the DER file holding one.
func readCerts(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("%s: no PEM or DER certificate", path)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// fileName returns the name cert is stored under in the trust store: simple-ca- and the first 16
// hexadecimal digits of its SHA-256 fingerprint, with the .crt extension Debian requires.
func fileName(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "simple-ca-" + hex.EncodeToString(sum[:8]) + ".crt"
}

// list writes the CAs simple-ca-trust added to the trust store in dir: their role, subject,
// expiry and SHA-256 fingerprint, written as simple-ca ca show writes it.
func list(dir string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "simple-ca-*.crt"))
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ROLE\tSUBJECT\tEXPIRES\tSHA-256")
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return fmt.Errorf("%s: no PEM certificate", path)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		role := "issuing CA"
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			role = "root CA"
		}
		sum := sha256.Sum256(cert.Raw)
		pairs := make([]string, len(sum))
		for i, b := range sum {
			pairs[i] = fmt.Sprintf("%02X", b)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", role, cert.Subject, cert.NotAfter.UTC().Format(time.DateTime+" UTC"),
			strings.Join(pairs, ":"))
	}
	return tw.Flush()
}

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil:
	case errors.Is(err, errUsage):
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
