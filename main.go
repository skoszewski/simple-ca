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
	"os"
	"runtime/debug"
	"slices"

	"github.com/skoszewski/simple-ca/pkg/simpleca/cli"
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

// commands lists the groups and the commands of simple-ca in the order of the usage text: the
// groups of cli.CertGroups with token before key, then audit and serve.
var commands = func() []cli.Command {
	groups := cli.CertGroups()
	key := slices.IndexFunc(groups, func(c cli.Command) bool { return c.Name == "key" })
	return slices.Concat(groups[:key], []cli.Command{
		{Name: "token", Summary: "Manage the tokens of the signing API and the web pages of serve.", Sub: []cli.Command{
			{Name: "create", Summary: "Create a token of a CA.", Run: runTokenCreate},
			{Name: "list", Summary: "List the tokens of a CA.", Run: runTokenList},
			{Name: "describe", Summary: "Print the attributes of a token of a CA, or of a token itself.", Run: runTokenDescribe},
			{Name: "revoke", Summary: "Revoke a token of a CA.", Run: runTokenRevoke},
			{Name: "renew", Summary: "Renew a token of a CA, expired or not.", Run: runTokenRenew},
			{Name: "purge", Summary: "Remove the expired and revoked tokens of a CA.", Run: runTokenPurge},
			{Name: "issue", Summary: "Print a JWT of a token type, not stored, for workload identity federation.", Run: runTokenIssue},
			{Name: "jwks", Summary: "Print the JSON Web Key Set verifying the tokens of a CA.", Run: runTokenJWKS},
		}},
	}, groups[key:], []cli.Command{
		{Name: "audit", Summary: "Read the audit log of a root CA and its issuing CAs.", Sub: []cli.Command{
			{Name: "list", Summary: "Print the records of the audit log, filtered.", Run: runAuditList},
		}},
		{Name: "serve", Summary: "Serve the CA certificates, CRLs, ACME, the signing API and the web pages over HTTP.", Run: runServe},
	})
}()

// run runs the command line args of simple-ca with its commands.
func run(args []string) error {
	return cli.Run(commands, args)
}

func main() {
	var err error
	if len(os.Args) == 1 {
		err = runREPL()
	} else {
		err = run(os.Args[1:])
	}
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
	case errors.Is(err, cli.ErrUsage):
		os.Exit(2)
	case errors.Is(err, errReported):
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// init sets the version of simple-ca, the usage line of its REPL and the former option names of
// token create for the commands of cli.
func init() {
	cli.Version = version()
	cli.UsageLines = []string{"simple-ca                 the commands of a session on a terminal, else of stdin"}
	cli.HiddenFlags["token create"] = []string{"type"}
}
