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
	"cmp"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/secrets"
)

// ---- secret commands --------------------------------------------------------

// secretValid is the default validity of a secret, from its creation to the use of its code.
const secretValid = 24 * time.Hour

// runSecretCreate runs secret create.
func runSecretCreate(args []string) error {
	fs := cli.NewFlagSet("secret create", "NAME",
		"Creates the secret NAME of the CA in --ca-dir, of the contents of --file or of the standard\n"+
			"input, and prints its one-time code. The code shows the value once on the page /get-secret\n"+
			"of serve, or at /api/get-secret, and the secret is removed then.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := cli.DurationVar(fs, "valid", secretValid, "validity `period` of the code: minutes, or a number with h or d, such as 30, 8h\n"+
		"or 7d; at most 30d")
	file := fs.String("file", "", "`file` holding the value, in place of the standard input")
	var clients []string
	fs.Func("network", "comma-separated client `prefixes` the code is used from; may be specified multiple\n"+
		"times (default: any)", prefixList(&clients))
	rest, _, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	in := os.Stdin
	if *file != "" {
		if in, err = os.Open(*file); err != nil {
			return err
		}
		defer in.Close()
	}
	value, err := io.ReadAll(io.LimitReader(in, secrets.MaxValue+1))
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	actor := simpleca.CLIActor()
	code, err := secrets.Add(dir, rest[0], value, *valid, clients, actor)
	if err != nil {
		return err
	}
	simpleca.Audit(dir, "secret.create", "name", rest[0], "valid", simpleca.DurationText(*valid),
		"networks", strings.Join(clients, ","), "via", "cli", "actor", actor)
	fmt.Println(code)
	return nil
}

// runSecretList runs secret list.
func runSecretList(args []string) error {
	fs := cli.NewFlagSet("secret list", "",
		"Lists the secrets of the CA in --ca-dir whose codes are not used and not expired, without\n"+
			"their values.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if !simpleca.FileExists(filepath.Join(dir, "ca_cert.pem")) {
		return fmt.Errorf("CA certificate not found in %q, which is not a CA directory", dir)
	}
	db, err := secrets.Load(dir)
	if err != nil {
		return err
	}
	now := time.Now()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tEXPIRES\tCLIENTS\tCREATOR")
	for _, name := range slices.Sorted(maps.Keys(db.Secrets)) {
		s := db.Secrets[name]
		if !now.Before(s.Expires) {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", simpleca.Printable(name), s.Created.UTC().Format(cert.DisplayTimeFormat),
			s.Expires.UTC().Format(cert.DisplayTimeFormat), cmp.Or(strings.Join(showPrefixes(s.Clients), ","), "any"),
			simpleca.Printable(cmp.Or(s.Creator, "-")))
	}
	return tw.Flush()
}

// runSecretRevoke runs secret revoke.
func runSecretRevoke(args []string) error {
	fs := cli.NewFlagSet("secret revoke", "NAME",
		"Removes the secret NAME of the CA in --ca-dir; its code stops working at once.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if err := secrets.Remove(dir, rest[0]); err != nil {
		return err
	}
	simpleca.Audit(dir, "secret.revoke", "name", rest[0], "via", "cli", "actor", simpleca.CLIActor())
	fmt.Printf("Secret %q revoked\n", rest[0])
	return nil
}
