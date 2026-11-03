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
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// ---- token commands ---------------------------------------------------------

// runTokenCreate runs token create.
func runTokenCreate(args []string) error {
	fs := newFlagSet("token create", "NAME",
		"Create the token NAME of the CA in --ca-dir, and print it.\n\n"+
			"The token is a JWT signed with the CA key and valid for that CA only. Scopes: sign (the\n"+
			"signing API and the signing form of serve), tokens (the /tokens/ page of serve --webui),\n"+
			"certs (its /certificates/ page). A root CA token opens the pages for every CA; an issuing\n"+
			"CA token opens only its own CA.\n\n"+
			"With the scope sign, the token allows the --type certificate types, the --domain domains\n"+
			"and their subdomains, and the --ip addresses; at least one --domain, --ip or --localhost\n"+
			"is required. With --host or --network, the token is accepted only from those clients.\n\n"+
			"With --otc, it prints a one-time setup code instead, valid for --otc-valid, and makes the\n"+
			"token when the code is exchanged at /api/token-setup of serve, or used to sign in to its\n"+
			"pages; the token is valid for --valid from then on.\n\n"+
			"Options not given default to the tokens section of simple-ca.json, then to the defaults\n"+
			"below. --host and --network together replace hosts and networks. The defaults of --type,\n"+
			"--domain, --ip and --localhost apply only with the scope sign.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := fs.Duration("valid", time.Hour, "validity `period` of the token, such as 30m, 8h or 720h")
	localhost := fs.Bool("localhost", false, "allow the name localhost and the IP address 127.0.0.1")
	var scopes, certTypes, domains, ips, clients []string
	fs.Func("scope", "`scope` of the token: sign, tokens, certs, or * for all; may be specified multiple times\n"+
		"(default: sign)", func(s string) error {
		scopes = append(scopes, s)
		return nil
	})
	fs.Func("type", "certificate `type` the token allows, or * for any; may be specified multiple times\n"+
		"(default: server)", func(s string) error {
		certTypes = append(certTypes, s)
		return nil
	})
	fs.Func("domain", "`domain` the token allows, with its subdomains, or * for any name; may be specified\n"+
		"multiple times", func(s string) error {
		domains = append(domains, s)
		return nil
	})
	fs.Func("ip", "IP `address` or prefix allowed in the certificate IP SANs, such as 192.0.2.10 or\n"+
		"10.0.0.0/8, or * for any address; may be specified multiple times", func(s string) error {
		ips = append(ips, s)
		return nil
	})
	fs.Func("host", "client IP `address` the token is accepted from; may be specified multiple times\n"+
		"(default: any)", func(s string) error {
		clients = append(clients, s)
		return nil
	})
	fs.Func("network", "comma-separated client `prefixes` the token is accepted from, such as\n"+
		"192.168.1.0/24,10.0.0.0/8; may be specified multiple times (default: any)", prefixList(&clients))
	setup := setupFlags(fs)
	rest, given, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	cfg, err := loadRootConfig(dir)
	if err != nil {
		return err
	}

	// The options not given take the defaults of tokens in simple-ca.json.
	defaults := cfg.Tokens
	if !given["valid"] && defaults.Valid != "" {
		if *valid, err = time.ParseDuration(defaults.Valid); err != nil {
			return fmt.Errorf("tokens.valid of %s: '%s' is not a duration such as 8h", cfg.path, defaults.Valid)
		}
	}
	if !given["scope"] {
		scopes = slices.Clone(defaults.Scopes)
	}
	if len(scopes) == 0 {
		scopes = []string{"sign"}
	}
	if allows(scopes, "sign") {
		if !given["type"] {
			certTypes = slices.Clone(defaults.Types)
		}
		if !given["domain"] {
			domains = slices.Clone(defaults.Domains)
		}
		if !given["ip"] {
			ips = slices.Clone(defaults.IPs)
		}
		if !given["localhost"] {
			*localhost = defaults.Localhost
		}
		if len(certTypes) == 0 {
			certTypes = []string{"server"}
		}
	}
	if !given["host"] && !given["network"] {
		clients = append(slices.Clone(defaults.Hosts), defaults.Networks...)
	}
	if *localhost {
		domains = append(domains, "localhost")
		ips = append(ips, "127.0.0.1")
	}
	setupValid, setupClients, err := setup(given)
	if err != nil {
		return err
	}
	token, err := addToken(dir, rest[0], *valid, scopes, certTypes, domains, ips, clients, setupValid, setupClients)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// prefixList returns the function of a flag appending the prefixes of a comma-separated list to
// list.
func prefixList(list *[]string) func(string) error {
	return func(s string) error {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p == "" {
				return fmt.Errorf("empty prefix in '%s'", s)
			}
			*list = append(*list, p)
		}
		return nil
	}
}

// setupFlags defines --otc, --otc-valid and --otc-network of fs, and returns the function giving,
// once fs is parsed with the flags given, the validity of the setup code, zero without --otc, and
// the clients it is exchanged from.
func setupFlags(fs *flag.FlagSet) func(given map[string]bool) (time.Duration, []string, error) {
	otc := fs.Bool("otc", false, "print a one-time setup code, exchanged for the token, instead of the token")
	valid := fs.Duration("otc-valid", tokenSetupValid, "validity `period` of the setup code, such as 15m or 1h")
	var clients []string
	fs.Func("otc-network", "comma-separated client `prefixes` the setup code is exchanged from; may be\n"+
		"specified multiple times (default: any)", prefixList(&clients))
	return func(given map[string]bool) (time.Duration, []string, error) {
		switch {
		case *otc:
			return *valid, clients, nil
		case given["otc-valid"] || given["otc-network"]:
			return 0, nil, errors.New("--otc-valid and --otc-network need --otc")
		}
		return 0, nil, nil
	}
}

// runTokenList runs token list.
func runTokenList(args []string) error {
	fs := newFlagSet("token list", "", "List the tokens of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return listTokens(os.Stdout, resolveCADir(*caDir))
}

// runTokenDescribe runs token describe.
func runTokenDescribe(args []string) error {
	fs := newFlagSet("token describe", "[NAME]",
		"Print the attributes of the token NAME of the CA in --ca-dir, or of the token in the file of\n"+
			"--token-file, or on the standard input with --stdin.\n\n"+
			"A token read from a file or the standard input shows what its JWT holds: its name, its\n"+
			"scopes and its times. With --ca-dir, its signature is checked against that CA, and what it\n"+
			"allows and where it is used from are read from the tokens-db.json of the CA.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	tokenFile := fs.String("token-file", "", "`file` holding the token")
	stdin := fs.Bool("stdin", false, "read the token from the standard input")
	rest, given, err := parseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	switch {
	case *tokenFile != "" && *stdin:
		return errors.New("give --token-file or --stdin, not both")
	case len(rest) == 1 && (*tokenFile != "" || *stdin):
		return errors.New("give NAME, or --token-file or --stdin, not both")
	case len(rest) == 0 && *tokenFile == "" && !*stdin:
		return errors.New("give NAME, --token-file or --stdin")
	}

	var name string
	var tok *apiToken
	limits := true
	var notes [][2]string
	var refused string
	if len(rest) == 1 {
		dir := resolveCADir(*caDir)
		if !fileExists(filepath.Join(dir, "ca_cert.pem")) {
			return fmt.Errorf("CA certificate not found in %s. Please point --ca-dir to a CA directory", dir)
		}
		db, err := loadTokens(dir)
		if err != nil {
			return err
		}
		if name, tok = rest[0], db.Tokens[rest[0]]; tok == nil {
			return fmt.Errorf("token '%s' not found in %s", name, filepath.Join(dir, tokensFile))
		}
	} else {
		var b []byte
		if *stdin {
			b, err = io.ReadAll(os.Stdin)
		} else {
			b, err = os.ReadFile(*tokenFile)
		}
		if err != nil {
			return err
		}
		// The signature is checked, and the entry read, with the CA of --ca-dir alone.
		var caCert *x509.Certificate
		dir := resolveCADir(*caDir)
		if given["ca-dir"] {
			if caCert, err = loadCert(filepath.Join(dir, "ca_cert.pem")); err != nil {
				return err
			}
		}
		c, err := verifyJWT(caCert, strings.TrimSpace(string(b)))
		switch {
		case err != nil && caCert != nil:
			return fmt.Errorf("the token is not one signed by the CA in %s", dir)
		case err != nil:
			return errors.New("the token is not a JWT of simple-ca token create")
		}
		name, limits = c.Subject, false
		tok = &apiToken{ID: c.ID, Scopes: strings.Fields(c.Scope), Issued: time.Unix(c.IssuedAt, 0),
			Expires: time.Unix(c.ExpiresAt, 0)}
		if caCert == nil {
			notes = append(notes, [2]string{"Signature", "not checked; --ca-dir of its CA checks it and shows its limits"})
		} else if db, err := loadTokens(dir); err != nil {
			return err
		} else if entry := db.Tokens[name]; entry != nil && entry.ID != "" && entry.ID == c.ID {
			tok, limits = entry, true
		} else {
			refused = "refused: the token was renewed, revoked or removed in " + filepath.Join(dir, tokensFile)
		}
	}
	attributes := describeToken(name, tok, limits)
	if refused != "" {
		attributes[1][1] = refused
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, a := range append(attributes, notes...) {
		fmt.Fprintf(tw, "%s:\t%s\n", a[0], a[1])
	}
	return tw.Flush()
}

// runTokenRevoke runs token revoke.
func runTokenRevoke(args []string) error {
	fs := newFlagSet("token revoke", "NAME", "Revoke the token NAME of the CA in --ca-dir. Its JWT stops working at once;\n"+
		"the token stays listed, and can be renewed, until token purge removes it.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return revokeToken(resolveCADir(*caDir), rest[0])
}

// runTokenPurge runs token purge.
func runTokenPurge(args []string) error {
	fs := newFlagSet("token purge", "[NAME]",
		"Remove the expired and revoked tokens of the CA in --ca-dir, or only the token NAME,\n"+
			"which must be expired or revoked. Removed tokens cannot be renewed.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := parseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	if len(rest) == 1 {
		if err := purgeToken(resolveCADir(*caDir), rest[0]); err != nil {
			return err
		}
		fmt.Printf("Token %s removed\n", rest[0])
		return nil
	}
	n, err := purgeTokens(resolveCADir(*caDir), 0)
	if err != nil {
		return err
	}
	fmt.Printf("%d expired or revoked tokens removed\n", n)
	return nil
}

// runTokenRenew runs token renew.
func runTokenRenew(args []string) error {
	fs := newFlagSet("token renew", "NAME",
		"Renew the token NAME of the CA in --ca-dir, expired or not, and print it. It gets a new\n"+
			"JWT, valid from now, with the same scopes and limits; the old JWT stops working.\n\n"+
			"With --otc, it prints a one-time setup code instead, as token create does: the old JWT\n"+
			"stops working at once, and the new one is made when the code is exchanged.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := fs.Duration("valid", 0, "validity `period` of the token, such as 30m, 8h or 720h (default: the period it had)")
	setup := setupFlags(fs)
	rest, given, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	setupValid, setupClients, err := setup(given)
	if err != nil {
		return err
	}
	token, err := reissueToken(resolveCADir(*caDir), rest[0], *valid, setupValid, setupClients)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}
