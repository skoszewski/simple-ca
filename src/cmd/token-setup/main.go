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

// Command token-setup exchanges a one-time setup code of simple-ca serve for its token.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/client"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

func run() error {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `Usage: token-setup [options] CODE

Exchanges the one-time setup code for its token at /api/token-setup of simple-ca serve, and
prints the token, or writes it to --token-file.

Options:
`)
		flag.PrintDefaults()
	}
	serverURL := flag.String("url", os.Getenv("SIMPLE_CA_URL"),
		"`URL` of the server, such as https://pki.example.com; a path is left out\n(default: SIMPLE_CA_URL)")
	tokenFile := flag.String("token-file", os.Getenv("SIMPLE_CA_TOKEN_FILE"),
		"new `file` the token is written to (default: SIMPLE_CA_TOKEN_FILE)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		if version == "" {
			version = "dev"
		}
		fmt.Println("token-setup", version)
		return nil
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(flag.CommandLine.Output(), "token-setup: CODE is required")
		flag.Usage()
		return errUsage
	}
	u, err := url.Parse(*serverURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("'%s' is not a URL such as https://pki.example.com; give --url or set SIMPLE_CA_URL", *serverURL)
	}
	// The token file is made before the code is used, new and readable by its owner alone.
	written := *tokenFile == ""
	var file *os.File
	if *tokenFile != "" {
		if file, err = os.OpenFile(*tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return fmt.Errorf("--token-file: %w; the token is written to a new file", err)
		}
		defer func() {
			file.Close()
			if !written {
				os.Remove(*tokenFile)
			}
		}()
	}

	token, err := client.Exchange(*serverURL, strings.TrimSpace(flag.Arg(0)))
	if err != nil {
		return err
	}

	if *tokenFile == "" {
		fmt.Println(token)
		return nil
	}
	if _, err := file.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("--token-file: %w", err)
	}
	written = true
	fmt.Printf("Token written to %s\n", *tokenFile)
	return nil
}

func main() {
	if err := run(); errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "token-setup:", err)
		os.Exit(1)
	}
}
