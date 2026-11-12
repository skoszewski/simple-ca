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

// Command simple-ca-wif sets up workload identity federation of a cloud with the CA of
// simple-ca, on the CA host: the workload identity pool and provider of Google Cloud with the
// keys of the CA, and the token, the access and federation.json of a machine.
package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"golang.org/x/term"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

// command is a command of a cloud: its name, its summary and its function.
type command struct {
	name, summary string
	run           func(args []string) error
}

// clouds lists the clouds and their commands in the order of the usage text.
var clouds = []struct {
	name     string
	commands []command
}{
	{"google", []command{
		{"setup", "Create the workload identity pool and provider of the CA in Google Cloud.", runGoogleSetup},
		{"machine", "Make the token, the access and federation.json of a machine.", runGoogleMachine},
	}},
}

// usage prints the usage of simple-ca-wif.
func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: simple-ca-wif google setup [options]
       simple-ca-wif google machine [options] NAME
       simple-ca-wif --version

Commands:
`)
	for _, c := range clouds {
		for _, cmd := range c.commands {
			fmt.Fprintf(w, "  %-16s %s\n", c.name+" "+cmd.name, cmd.summary)
		}
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return errUsage
	}
	name := os.Args[1]
	switch name {
	case "help", "-h", "-help", "--help":
		usage(os.Stdout)
		return nil
	case "version", "-version", "--version":
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		fmt.Println("simple-ca-wif", cmp.Or(version, "dev"))
		return nil
	}
	for _, c := range clouds {
		if c.name != name {
			continue
		}
		if len(os.Args) < 3 {
			usage(os.Stderr)
			return errUsage
		}
		for _, cmd := range c.commands {
			if cmd.name == os.Args[2] {
				return cmd.run(os.Args[3:])
			}
		}
		fmt.Fprintf(os.Stderr, "simple-ca-wif: unknown command '%s %s'\n", name, os.Args[2])
		usage(os.Stderr)
		return errUsage
	}
	fmt.Fprintf(os.Stderr, "simple-ca-wif: unknown cloud '%s'\n", name)
	usage(os.Stderr)
	return errUsage
}

// newFlagSet returns the flag set of the command name, whose usage names its arguments and its
// description.
func newFlagSet(name, arguments, description string) *flag.FlagSet {
	fs := flag.NewFlagSet("simple-ca-wif "+name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: simple-ca-wif %s [options]%s\n\n%s\n\nOptions:\n", name, arguments, description)
		fs.PrintDefaults()
	}
	return fs
}

// usageError prints msg and the usage of fs, and returns errUsage.
func usageError(fs *flag.FlagSet, msg string) error {
	fmt.Fprintf(fs.Output(), "%s: %s\n", fs.Name(), msg)
	fs.Usage()
	return errUsage
}

// resolveCADir returns the CA directory of --ca-dir, else of SIMPLE_CA_DIR, else the working
// directory.
func resolveCADir(flagVal string) string {
	return cmp.Or(flagVal, os.Getenv("SIMPLE_CA_DIR"), ".")
}

// init lets simpleca.KeyPassphrase read the passphrase of the private keys from a terminal.
func init() {
	simpleca.PromptPassphrase = func(prompt string) ([]byte, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, simpleca.ErrNoPassphrase
		}
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return b, err
	}
}

func main() {
	if err := run(); errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "simple-ca-wif:", err)
		os.Exit(1)
	}
}
