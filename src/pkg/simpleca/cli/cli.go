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

// Package cli is the certificate commands of simple-ca and simple-ca-lite, with their command
// table, options and usage texts.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// The settings of the program that runs the commands.
var (
	// Program is the name of the program in the usage texts.
	Program = "simple-ca"
	// Version is the version --version prints.
	Version = "dev"
	// UsageLines are the lines of the usage of the program after those of its commands.
	UsageLines []string
	// SessionCADir returns the CA directory of a session, empty outside one; nil without sessions.
	SessionCADir func() string
)

// ErrUsage reports a command line that was rejected after its usage was printed.
var ErrUsage = errors.New("invalid command line")

// Command is a command of the program, run by Run, or a group of the commands in Sub.
type Command struct {
	Name, Summary string
	Run           func(args []string) error
	Sub           []Command
}

// CertGroups returns the groups of the certificate commands, ca, cert, crl and key, in the order
// of the usage text.
func CertGroups() []Command {
	return []Command{
		{Name: "ca", Summary: "Create and show root and issuing CAs.", Sub: []Command{
			{Name: "create", Summary: "Create a root or issuing CA.", Run: runCACreate},
			{Name: "show", Summary: "Show a CA, its certificate counts and its CRL.", Run: runCAShow},
		}},
		{Name: "cert", Summary: "Create, sign, export, revoke, list and show certificates.", Sub: []Command{
			{Name: "create", Summary: "Create a server, user or none certificate signed by the CA.", Run: runCertCreate},
			{Name: "sign", Summary: "Sign a certificate signing request with the CA.", Run: runCertSign},
			{Name: "pfx", Summary: "Create a PKCS#12 (PFX) bundle for a leaf certificate.", Run: runCertPFX},
			{Name: "revoke", Summary: "Revoke a certificate.", Run: runCertRevoke},
			{Name: "list", Summary: "List the certificates a CA issued.", Run: runCertList},
			{Name: "show", Summary: "Show the certificates in a file.", Run: runCertShow},
		}},
		{Name: "crl", Summary: "Create certificate revocation lists.", Sub: []Command{
			{Name: "create", Summary: "Create the CRL of a CA, or of a root CA and all its issuing CAs.", Run: runCRLCreate},
		}},
		{Name: "key", Summary: "Encrypt and decrypt the private keys of CAs and certificates.", Sub: []Command{
			{Name: "encrypt", Summary: "Encrypt the private keys of a CA with the passphrase.", Run: runKeyEncrypt},
			{Name: "decrypt", Summary: "Decrypt the private keys of a CA.", Run: runKeyDecrypt},
		}},
	}
}

// Run runs the command of commands that args name, a group and one of its commands or a command
// of its own, or prints the usage of the program or of a group, or the version.
func Run(commands []Command, args []string) error {
	if len(args) == 0 {
		PrintUsage(os.Stderr, commands, nil)
		return ErrUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		PrintUsage(os.Stdout, commands, nil)
		return nil
	case "-version", "--version":
		fmt.Println(Program, "version", Version)
		return nil
	}
	i := slices.IndexFunc(commands, func(c Command) bool { return c.Name == args[0] })
	if i < 0 {
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", Program, args[0])
		PrintUsage(os.Stderr, commands, nil)
		return ErrUsage
	}
	g := &commands[i]
	if g.Run != nil {
		return g.Run(args[1:])
	}
	if len(args) == 1 {
		PrintUsage(os.Stderr, commands, g)
		return ErrUsage
	}
	switch args[1] {
	case "-h", "-help", "--help", "help":
		PrintUsage(os.Stdout, commands, g)
		return nil
	}
	j := slices.IndexFunc(g.Sub, func(c Command) bool { return c.Name == args[1] })
	if j < 0 {
		fmt.Fprintf(os.Stderr, "%s %s: unknown command %q\n\n", Program, g.Name, args[1])
		PrintUsage(os.Stderr, commands, g)
		return ErrUsage
	}
	return g.Sub[j].Run(args[2:])
}

// PrintUsage writes the usage of the program, with the groups and the commands of commands, to w,
// or the usage of the group g when it is not nil.
func PrintUsage(w io.Writer, commands []Command, g *Command) {
	list, lines, what := commands, []string{Program + " GROUP COMMAND [options] [ARGS]"},
		"Create and manage a simple Certificate Authority."
	for _, c := range commands {
		if c.Run != nil {
			lines = append(lines, Program+" "+c.Name+" [options]")
		}
	}
	lines = append(lines, UsageLines...)
	if g != nil {
		list, lines, what = g.Sub, []string{Program + " " + g.Name + " COMMAND [options] [ARGS]"}, g.Summary
	}
	fmt.Fprintf(w, "Usage: %s\n\n%s\n\nCommands:\n", strings.Join(lines, "\n       "), what)
	for _, c := range list {
		fmt.Fprintf(w, "  %-8s %s\n", c.Name, c.Summary)
	}
	if g == nil {
		fmt.Fprintf(w, "\nOptions:\n  -h, --help   print this help\n  --version    print the version\n\n"+
			"Run \"%[1]s GROUP -h\" for the commands of a group, and \"%[1]s GROUP COMMAND -h\"\n"+
			"for the options of a command.\n", Program)
		return
	}
	fmt.Fprintf(w, "\nRun \"%s %s COMMAND -h\" for the options of a command.\n", Program, g.Name)
}

// ResolveCADir returns the --ca-dir value, else the CA directory of SessionCADir, else
// $SIMPLE_CA_DIR, else the working directory.
func ResolveCADir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if SessionCADir != nil {
		if dir := SessionCADir(); dir != "" {
			return dir
		}
	}
	if env := os.Getenv("SIMPLE_CA_DIR"); env != "" {
		return env
	}
	cwd, _ := os.Getwd()
	return cwd
}

// Input is what commands read as their standard input: empty in a script, whose lines
// stdin holds.
var Input io.Reader = os.Stdin
