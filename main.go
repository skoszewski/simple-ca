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
	"os"
	"runtime/debug"
	"slices"
	"strings"
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

// resolveTLS returns the --tls-cert and --tls-key values, each else $SIMPLE_CA_TLS_CERT or
// $SIMPLE_CA_TLS_KEY, and an error when only one of the two is given.
func resolveTLS(cert, key string) (string, string, error) {
	if cert == "" {
		cert = os.Getenv("SIMPLE_CA_TLS_CERT")
	}
	if key == "" {
		key = os.Getenv("SIMPLE_CA_TLS_KEY")
	}
	if (cert == "") != (key == "") {
		return "", "", errors.New("--tls-cert and --tls-key, or SIMPLE_CA_TLS_CERT and SIMPLE_CA_TLS_KEY, must be given together")
	}
	return cert, key, nil
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

// command is a command of simple-ca, run by run, or a group of the commands in sub.
type command struct {
	name, summary string
	run           func(args []string) error
	sub           []command
}

// commands lists the groups and the commands in the order of the usage text.
var commands = []command{
	{name: "ca", summary: "Create and show root and issuing CAs.", sub: []command{
		{name: "create", summary: "Create a root or issuing CA.", run: runCACreate},
		{name: "show", summary: "Show a CA, its certificate counts and its CRL.", run: runCAShow},
	}},
	{name: "cert", summary: "Create, sign, export, revoke, list and show certificates.", sub: []command{
		{name: "create", summary: "Create a server, user or none certificate signed by the CA.", run: runCertCreate},
		{name: "sign", summary: "Sign a certificate signing request with the CA.", run: runCertSign},
		{name: "pfx", summary: "Create a PKCS#12 (PFX) bundle for a leaf certificate.", run: runCertPFX},
		{name: "revoke", summary: "Revoke a certificate.", run: runCertRevoke},
		{name: "list", summary: "List the certificates a CA issued.", run: runCertList},
		{name: "show", summary: "Show the certificates in a file.", run: runCertShow},
	}},
	{name: "crl", summary: "Create certificate revocation lists.", sub: []command{
		{name: "create", summary: "Create the CRL of a CA, or of a root CA and all its issuing CAs.", run: runCRLCreate},
	}},
	{name: "token", summary: "Manage the tokens of the signing API and the web pages of serve.", sub: []command{
		{name: "create", summary: "Create a token of a CA.", run: runTokenCreate},
		{name: "list", summary: "List the tokens of a CA.", run: runTokenList},
		{name: "describe", summary: "Print the attributes of a token of a CA, or of a token itself.", run: runTokenDescribe},
		{name: "revoke", summary: "Revoke a token of a CA.", run: runTokenRevoke},
		{name: "renew", summary: "Renew a token of a CA, expired or not.", run: runTokenRenew},
		{name: "purge", summary: "Remove the expired and revoked tokens of a CA.", run: runTokenPurge},
		{name: "jwks", summary: "Print the JSON Web Key Set verifying the tokens of a CA.", run: runTokenJWKS},
	}},
	{name: "audit", summary: "Read the audit log of a root CA and its issuing CAs.", sub: []command{
		{name: "list", summary: "Print the records of the audit log, filtered.", run: runAuditList},
	}},
	{name: "serve", summary: "Serve the CA certificates, CRLs, ACME, the signing API and the web pages over HTTP.", run: runServe},
}

// printUsage writes the usage of simple-ca to w, or of the group g when it is not nil.
func printUsage(w io.Writer, g *command) {
	list, usage, what := commands, "simple-ca GROUP COMMAND [options] [ARGS]\n       simple-ca serve [options]",
		"Create and manage a simple Certificate Authority."
	if g != nil {
		list, usage, what = g.sub, "simple-ca "+g.name+" COMMAND [options] [ARGS]", g.summary
	}
	fmt.Fprintf(w, "Usage: %s\n\n%s\n\nCommands:\n", usage, what)
	for _, c := range list {
		fmt.Fprintf(w, "  %-8s %s\n", c.name, c.summary)
	}
	if g == nil {
		fmt.Fprint(w, "\nOptions:\n  -h, --help   print this help\n  --version    print the version\n\n"+
			"Run \"simple-ca GROUP -h\" for the commands of a group, and \"simple-ca GROUP COMMAND -h\"\n"+
			"for the options of a command.\n")
		return
	}
	fmt.Fprintf(w, "\nRun \"simple-ca %s COMMAND -h\" for the options of a command.\n", g.name)
}

// hiddenFlags are the former names of options, accepted as aliases and left out of the usage, by
// subcommand, those of every subcommand under "".
var hiddenFlags = map[string][]string{"": {"ca-publish-base-url"}, "token create": {"type"}}

// newFlagSet returns the flag set of the subcommand name, whose usage names its arguments and
// summary, and its options without its hiddenFlags.
func newFlagSet(name, arguments, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet("simple-ca "+name, flag.ContinueOnError)
	fs.Usage = func() {
		line := strings.TrimSpace("simple-ca " + name + " [options] " + arguments)
		fmt.Fprintf(fs.Output(), "Usage: %s\n\n%s\n\nOptions:\n", line, summary)
		shown := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
		shown.SetOutput(fs.Output())
		fs.VisitAll(func(f *flag.Flag) {
			if !slices.Contains(hiddenFlags[""], f.Name) && !slices.Contains(hiddenFlags[name], f.Name) {
				shown.Var(f.Value, f.Name, f.Usage)
				shown.Lookup(f.Name).DefValue = f.DefValue
			}
		})
		shown.PrintDefaults()
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

// run runs the command named by args, a group and one of its commands or serve, or prints the
// usage of simple-ca or of a group, or the version.
func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr, nil)
		return errUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		printUsage(os.Stdout, nil)
		return nil
	case "-version", "--version":
		fmt.Println("simple-ca version", version())
		return nil
	}
	i := slices.IndexFunc(commands, func(c command) bool { return c.name == args[0] })
	if i < 0 {
		fmt.Fprintf(os.Stderr, "simple-ca: unknown command %q\n\n", args[0])
		printUsage(os.Stderr, nil)
		return errUsage
	}
	g := &commands[i]
	if g.run != nil {
		return g.run(args[1:])
	}
	if len(args) == 1 {
		printUsage(os.Stderr, g)
		return errUsage
	}
	switch args[1] {
	case "-h", "-help", "--help", "help":
		printUsage(os.Stdout, g)
		return nil
	}
	j := slices.IndexFunc(g.sub, func(c command) bool { return c.name == args[1] })
	if j < 0 {
		fmt.Fprintf(os.Stderr, "simple-ca %s: unknown command %q\n\n", g.name, args[1])
		printUsage(os.Stderr, g)
		return errUsage
	}
	return g.sub[j].run(args[2:])
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
