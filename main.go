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
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// ---- version ----------------------------------------------------------------

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// version returns the version given at link time, else the version this binary was built
// from, or "dev" outside a module build.
func version() string {
	if buildVersion != "" {
		return buildVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// ---- CLI --------------------------------------------------------------------

// resolveCADir returns the --ca-dir value, else $SIMPLE_CA_DIR, else the working directory.
func resolveCADir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("SIMPLE_CA_DIR"); env != "" {
		return env
	}
	cwd, _ := os.Getwd()
	return cwd
}

// loadRootConfig loads simple-ca.json of the root CA of the CA in caDir.
func loadRootConfig(caDir string) (*config, error) {
	rootDir, _, err := locateCA(caDir)
	if err != nil {
		return nil, err
	}
	return loadConfig(rootDir)
}

// errUsage reports a command line that was rejected after its usage was printed.
var errUsage = errors.New("invalid command line")

// commands lists the subcommands in the order of the usage text.
var commands = []struct {
	name, summary string
	run           func(args []string) error
}{
	{"make-ca", "Create a root or issuing CA.", runMakeCA},
	{"make-cert", "Create a server or user certificate signed by the CA.", runMakeCert},
	{"sign", "Sign a certificate signing request with the CA.", runSign},
	{"make-pfx", "Create a PKCS#12 (PFX) bundle for a leaf certificate.", runMakePFX},
	{"make-crl", "Generate a CRL for a CA.", runMakeCRL},
	{"revoke-cert", "Revoke a certificate.", runRevokeCert},
	{"info", "Show a CA, or the certificates in a file.", runInfo},
	{"list", "List the certificates a CA issued.", runList},
	{"make-token", "Create a token of the signing API of a CA.", runMakeToken},
	{"list-tokens", "List the tokens of the signing API of a CA.", runListTokens},
	{"revoke-token", "Revoke a token of the signing API of a CA.", runRevokeToken},
	{"purge-tokens", "Remove the expired tokens of the signing API of a CA.", runPurgeTokens},
	{"serve", "Serve the CA certificates and CRLs over HTTP.", runServe},
}

// printUsage writes the usage of simple-ca to w.
func printUsage(w io.Writer) {
	fmt.Fprint(w, "Usage: simple-ca COMMAND [options] [ARGS]\n\n"+
		"Create and manage a simple Certificate Authority.\n\nCommands:\n")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nOptions:\n  -h, --help   print this help\n  --version    print the version\n\n"+
		"Run \"simple-ca COMMAND -h\" for the options of a command.\n")
}

// newFlagSet returns the flag set of the subcommand name, whose usage names its arguments and
// summary.
func newFlagSet(name, arguments, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet("simple-ca "+name, flag.ContinueOnError)
	fs.Usage = func() {
		line := strings.TrimSpace("simple-ca " + name + " [options] " + arguments)
		fmt.Fprintf(fs.Output(), "Usage: %s\n\n%s\n\nOptions:\n", line, summary)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses the options of a subcommand, which come before its arguments, and checks that
// it was given from minArgs to maxArgs arguments, maxArgs -1 for any number. It returns the
// arguments and the names of the options given.
func parseArgs(fs *flag.FlagSet, args []string, minArgs, maxArgs int) ([]string, map[string]bool, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, err
		}
		return nil, nil, errUsage
	}
	if fs.NArg() < minArgs || (maxArgs >= 0 && fs.NArg() > maxArgs) {
		fmt.Fprintf(fs.Output(), "%s: wrong number of arguments\n", fs.Name())
		fs.Usage()
		return nil, nil, errUsage
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	return fs.Args(), given, nil
}

// runMakeCA runs the make-ca subcommand.
func runMakeCA(args []string) error {
	fs := newFlagSet("make-ca", "CA_NAME", "Create a root or issuing CA.")
	days := fs.Int("days", 3650, "validity period in `days`")
	issuingCA := fs.String("issuing-ca", "", "create an issuing CA with this directory `name`")
	baseURL := fs.String("ca-publish-base-url", "", "base `URL` for AIA and CRL distribution point extensions")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA")
	writeConf := fs.Bool("write-conf", false, "also write openssl.cnf, a configuration of openssl ca, to the CA directory")
	rest, given, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	cfg, err := loadConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.CA > 0 {
		*days = cfg.Days.CA
	}
	if err := makeCA(dir, rest[0], *days, *issuingCA, *baseURL); err != nil {
		return err
	}
	if !*writeConf {
		return nil
	}
	target := dir
	if *issuingCA != "" {
		target = filepath.Join(dir, *issuingCA)
	}
	path, err := writeOpenSSLConf(target)
	if err != nil {
		return err
	}
	fmt.Printf("openssl ca configuration written to %s\n", path)
	return nil
}

// runMakeCert runs the make-cert subcommand.
func runMakeCert(args []string) error {
	fs := newFlagSet("make-cert", "CN|EMAIL [EMAIL|CN] [SAN ...]",
		"Create a server, user or none certificate signed by the CA in --ca-dir.\n\n"+
			"server, none: CN [SAN ...]; the CN is a hostname or FQDN, a SAN a hostname, FQDN, IPv4 or\n"+
			"IPv6 address, or numeric OID. A none certificate has no key usages of its own.\n"+
			"user: CN|EMAIL [EMAIL|CN] [SAN ...]; the CN, the emailAddress or both, in either order,\n"+
			"then email addresses or numeric OIDs, after both the CN and the emailAddress.")
	certDir := fs.String("cert-dir", "", "output `directory` (default: the CA directory)")
	caDir := fs.String("ca-dir", "", "`directory` of the signing CA, the root CA or an issuing CA")
	certType := fs.String("type", "server", "certificate `type`: server, user, none or a type of simple-ca.json")
	days := fs.Int("days", 365, "validity period in `days`")
	ekus, kus := usageFlags(fs)
	rest, given, err := parseArgs(fs, args, 1, -1)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	cfg, err := loadRootConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.Cert > 0 {
		*days = cfg.Days.Cert
	}
	return makeCert(rest[0], rest[1:], dir, *certDir, *certType, *days, *ekus, *kus)
}

// usageFlags defines the --eku and --ku options of fs and returns the extended key usages and
// key usages they are given.
func usageFlags(fs *flag.FlagSet) (ekus, kus *[]string) {
	ekus, kus = new([]string), new([]string)
	fs.Func("eku", "extended key `usage` added to those of the type, a name such as clientAuth or a\n"+
		"numeric OID; repeated for more", func(s string) error {
		*ekus = append(*ekus, s)
		return nil
	})
	fs.Func("ku", "comma-separated key `usages` added to those of the type, such as\n"+
		"digitalSignature,keyEncipherment; repeated for more", func(s string) error {
		for _, ku := range strings.Split(s, ",") {
			ku = strings.TrimSpace(ku)
			if ku == "" {
				return fmt.Errorf("empty key usage in '%s'", s)
			}
			*kus = append(*kus, ku)
		}
		return nil
	})
	return ekus, kus
}

// runSign runs the sign subcommand.
func runSign(args []string) error {
	fs := newFlagSet("sign", "CSR_FILE",
		"Sign the certificate signing request in CSR_FILE, PEM or DER, with the CA in --ca-dir.\n\n"+
			"Only the subject and the subject alternative names of the request are copied; the type\n"+
			"sets the key usages and extended key usages. NAME.EXT is written as NAME_cert.pem.\n"+
			"The certificate is shown and signed once the answer to the question is y.")
	certDir := fs.String("cert-dir", "", "output `directory` (default: the CA directory)")
	caDir := fs.String("ca-dir", "", "`directory` of the signing CA, the root CA or an issuing CA")
	certType := fs.String("type", "server", "certificate `type`: server, user, none or a type of simple-ca.json")
	days := fs.Int("days", 365, "validity period in `days`")
	force := fs.Bool("force", false, "sign without asking")
	ekus, kus := usageFlags(fs)
	rest, given, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	cfg, err := loadRootConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.Cert > 0 {
		*days = cfg.Days.Cert
	}
	return signCSR(rest[0], dir, *certDir, *certType, *days, *ekus, *kus, *force, os.Stdin)
}

// runMakePFX runs the make-pfx subcommand.
func runMakePFX(args []string) error {
	fs := newFlagSet("make-pfx", "CERT_PATH", "Create a PKCS#12 (PFX) bundle for a leaf certificate.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA that signed the certificate")
	password := fs.String("password", "", "PFX `password` (default: changeit)")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return makePFX(rest[0], resolveCADir(*caDir), *password)
}

// runMakeCRL runs the make-crl subcommand.
func runMakeCRL(args []string) error {
	fs := newFlagSet("make-crl", "", "Generate the CRL of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	days := fs.Int("days", 30, "CRL validity in `days`")
	all := fs.Bool("all", false, "generate the CRLs of the root CA of --ca-dir and of all its issuing CAs")
	_, given, err := parseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	rootDir, _, err := locateCA(dir)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(rootDir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.CRL > 0 {
		*days = cfg.Days.CRL
	}
	if !*all {
		return makeCRL(dir, *days)
	}

	// Every CA is tried, also after one fails.
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return err
	}
	dirs := []string{rootDir}
	for _, e := range entries {
		sub := filepath.Join(rootDir, e.Name())
		if e.IsDir() && fileExists(filepath.Join(sub, "ca_cert.pem")) && fileExists(filepath.Join(sub, "ca_key.pem")) {
			dirs = append(dirs, sub)
		}
	}
	var errs []error
	for _, d := range dirs {
		if err := makeCRL(d, *days); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
		}
	}
	return errors.Join(errs...)
}

// runRevokeCert runs the revoke-cert subcommand.
func runRevokeCert(args []string) error {
	fs := newFlagSet("revoke-cert", "CERT_PATH", "Revoke a certificate the CA in --ca-dir issued.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA that signed the certificate")
	reason := fs.String("reason", "", "revocation `reason`: unspecified, keyCompromise, CACompromise, affiliationChanged,\n"+
		"superseded or cessationOfOperation (default: none)")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return revokeCert(rest[0], resolveCADir(*caDir), *reason)
}

// runInfo runs the info subcommand.
func runInfo(args []string) error {
	fs := newFlagSet("info", "[CERT_FILE]",
		"Show the CA in --ca-dir, its certificate counts and its CRL, or the certificates in CERT_FILE.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	rest, given, err := parseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	if len(rest) == 1 {
		if given["ca-dir"] {
			fmt.Fprintf(fs.Output(), "%s: --ca-dir does not apply to CERT_FILE\n", fs.Name())
			fs.Usage()
			return errUsage
		}
		return showCert(os.Stdout, rest[0])
	}
	return showInfo(os.Stdout, resolveCADir(*caDir))
}

// runList runs the list subcommand.
func runList(args []string) error {
	fs := newFlagSet("list", "", "List the certificates the CA in --ca-dir issued; without a status option, all of them.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	valid := fs.Bool("valid", false, "list the valid certificates")
	revoked := fs.Bool("revoked", false, "list the revoked certificates")
	expired := fs.Bool("expired", false, "list the expired certificates")
	_, _, err := parseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	var statuses []string
	if *valid {
		statuses = append(statuses, "valid")
	}
	if *revoked {
		statuses = append(statuses, "revoked")
	}
	if *expired {
		statuses = append(statuses, "expired")
	}
	return listCerts(os.Stdout, dir, statuses)
}

// runMakeToken runs the make-token subcommand.
func runMakeToken(args []string) error {
	fs := newFlagSet("make-token", "NAME",
		"Create the token NAME of the signing API of the CA in --ca-dir, and print it.\n\n"+
			"The token is a JWT signed with the CA key, valid for that CA alone. It allows the\n"+
			"certificate types of --type, and the names of the --domain domains and below them.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	valid := fs.Duration("valid", time.Hour, "validity `period` of the token, such as 30m, 8h or 720h")
	var certTypes, domains []string
	fs.Func("type", "certificate `type` the token allows; repeated for more (default: server)", func(s string) error {
		certTypes = append(certTypes, s)
		return nil
	})
	fs.Func("domain", "`domain` whose names, and the names below it, the token allows; repeated for more", func(s string) error {
		domains = append(domains, s)
		return nil
	})
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if len(certTypes) == 0 {
		certTypes = []string{"server"}
	}
	token, err := makeToken(resolveCADir(*caDir), rest[0], *valid, certTypes, domains)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runListTokens runs the list-tokens subcommand.
func runListTokens(args []string) error {
	fs := newFlagSet("list-tokens", "", "List the tokens of the signing API of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return listTokens(os.Stdout, resolveCADir(*caDir))
}

// runRevokeToken runs the revoke-token subcommand.
func runRevokeToken(args []string) error {
	fs := newFlagSet("revoke-token", "NAME", "Revoke the token NAME of the signing API of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return revokeToken(resolveCADir(*caDir), rest[0])
}

// runPurgeTokens runs the purge-tokens subcommand.
func runPurgeTokens(args []string) error {
	fs := newFlagSet("purge-tokens", "", "Remove the expired tokens of the signing API of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	n, err := purgeTokens(resolveCADir(*caDir))
	if err != nil {
		return err
	}
	fmt.Printf("%d expired tokens removed\n", n)
	return nil
}

// runServe runs the serve subcommand until it fails or is interrupted.
func runServe(args []string) error {
	fs := newFlagSet("serve", "", "Serve the certificates and CRLs of the root CA of the CA in --ca-dir, and of its\n"+
		"issuing CAs, over HTTP.")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA or of one of its issuing CAs")
	address := fs.String("address", "127.0.0.1", "`address` of the interface to listen on; 0.0.0.0 for all interfaces")
	port := fs.Int("port", 8080, "TCP `port` to listen on")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with the certificate chain in this PEM `file`")
	tlsKey := fs.String("tls-key", "", "private key of --tls-cert, a PEM `file`")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	if *address == "" {
		fmt.Fprintf(fs.Output(), "%s: --address must not be empty; 0.0.0.0 is all interfaces\n", fs.Name())
		fs.Usage()
		return errUsage
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("--port must be from 1 to 65535, got %d", *port)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be given together")
	}
	rootDir, _, err := locateCA(resolveCADir(*caDir))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(*address, strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: newServeMux(rootDir), ReadHeaderTimeout: 10 * time.Second}

	// The expired tokens of the root CA and its issuing CAs are removed on start and every
	// tokensPurgeInterval.
	go func() {
		for {
			dirs := []string{rootDir}
			entries, _ := os.ReadDir(rootDir)
			for _, e := range entries {
				if e.IsDir() && fileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
					dirs = append(dirs, filepath.Join(rootDir, e.Name()))
				}
			}
			for _, d := range dirs {
				n, err := purgeTokens(d)
				if err != nil {
					log.Printf("purging the tokens of %s: %v", d, err)
				} else if n > 0 {
					log.Printf("%d expired tokens of %s removed", n, d)
				}
			}
			time.Sleep(tokensPurgeInterval)
		}
	}()
	if *tlsCert != "" {
		fmt.Printf("Serving the CAs of %s on https://%s/\n", rootDir, listener.Addr())
		return server.ServeTLS(listener, *tlsCert, *tlsKey)
	}
	fmt.Printf("Serving the CAs of %s on http://%s/\n", rootDir, listener.Addr())
	return server.Serve(listener)
}

// run runs the subcommand named by the first of args, or prints the usage or the version.
func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		printUsage(os.Stdout)
		return nil
	case "-version", "--version":
		fmt.Println("simple-ca version", version())
		return nil
	}
	for _, c := range commands {
		if c.name == args[0] {
			return c.run(args[1:])
		}
	}
	fmt.Fprintf(os.Stderr, "simple-ca: unknown command %q\n\n", args[0])
	printUsage(os.Stderr)
	return errUsage
}

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
	case errors.Is(err, errUsage):
		os.Exit(2)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}
