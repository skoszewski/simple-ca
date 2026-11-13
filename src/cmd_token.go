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

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// ---- token commands ---------------------------------------------------------

// runTokenCreate runs token create.
func runTokenCreate(args []string) error {
	fs := cli.NewFlagSet("token create", "NAME",
		"Creates the token NAME of the CA in --ca-dir and prints it, or with --otc a one-time setup\n"+
			"code. An encrypted CA key needs its passphrase.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := cli.DurationVar(fs, "valid", time.Hour, "validity `period` of the token: minutes, or a number with h, d, m (30 days) or y\n"+
		"(365 days), such as 30, 8h, 180d or 1y")
	localhost := fs.Bool("localhost", false, "allow the name localhost and the IP address 127.0.0.1")
	var fed tokens.TokenFederate
	fs.StringVar(&fed.Type, "federate-type", "", "token `type` of the JWTs of the scope federate: google, azure or a type of\n"+
		"federation.types of simple-ca.json")
	fs.StringVar(&fed.Audience, "audience", "", "`audience` of the JWTs of the scope federate, in place of that of the token type")
	fs.Func("claim", "`name=value` claim of the JWTs of the scope federate, a string; may be specified\n"+
		"multiple times", claimFlag(&fed.Claims))
	var scopes, certTypes, domains, ips, clients []string
	fs.Func("scope", "`scope` of the token: sign, tokens, certs, audit, federate, or * for all; may be specified\n"+
		"multiple times (default: sign)", func(s string) error {
		scopes = append(scopes, s)
		return nil
	})
	certType := func(s string) error {
		certTypes = append(certTypes, s)
		return nil
	}
	fs.Func("cert-type", "certificate `type` the token allows, or * for any; may be specified multiple times\n"+
		"(default: server)", certType)
	fs.Func("type", "former name of --cert-type", certType)
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
	rest, given, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}

	// The options not given take the defaults of tokens in simple-ca.json.
	defaults := cfg.Tokens
	if !given["valid"] && defaults.Valid != "" {
		if *valid, err = simpleca.ParseDuration(defaults.Valid); err != nil {
			return fmt.Errorf("tokens.valid of %q: %w", cfg.Path, err)
		}
	}
	if !given["scope"] {
		scopes = slices.Clone(defaults.Scopes)
	}
	if len(scopes) == 0 {
		scopes = []string{"sign"}
	}
	if tokens.Allows(scopes, "sign") {
		if !given["type"] && !given["cert-type"] {
			certTypes = slices.Clone(defaults.Types)
		}
		if !given["domain"] {
			domains = slices.Clone(defaults.Domains)
		}
		if !given["ip"] {
			ips = slices.Clone(defaults.IPs)
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
	// The settings of the scope federate are given together with --federate-type.
	var federate *tokens.TokenFederate
	switch {
	case given["federate-type"]:
		federate = &fed
	case given["audience"] || given["claim"]:
		return errors.New("--audience and --claim need --federate-type")
	}
	token, err := tokens.AddToken(dir, rest[0], federate, *valid, scopes, certTypes, domains, ips, clients, setupValid, setupClients)
	if err != nil {
		return err
	}
	record := append([]any{"name", rest[0], "scopes", strings.Join(scopes, ","), "setup_code", setupValid > 0},
		tokens.FederateAudit(federate)...)
	simpleca.Audit(dir, "token.create", append(record, "via", "cli", "actor", simpleca.CLIActor())...)
	fmt.Println(token)
	return nil
}

// claimFlag returns the function of a flag adding a claim name=value to claims.
func claimFlag(claims *map[string]string) func(string) error {
	return func(s string) error {
		name, value, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("%q is not a claim such as env=prod", s)
		}
		if *claims == nil {
			*claims = map[string]string{}
		}
		(*claims)[name] = value
		return nil
	}
}

// runTokenIssue runs token issue.
func runTokenIssue(args []string) error {
	fs := cli.NewFlagSet("token issue", "NAME",
		"Prints a JWT of the --token-type token type for NAME, signed with the key of the CA in\n"+
			"--ca-dir, for workload identity federation; it is not stored. An encrypted CA key needs its passphrase.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	var fed tokens.TokenFederate
	fs.StringVar(&fed.Type, "token-type", "", "token `type`: google, azure or a type of federation.types of simple-ca.json")
	fs.StringVar(&fed.Audience, "audience", "", "`audience` of the JWT, in place of that of the token type")
	fs.Func("claim", "`name=value` claim of the JWT, a string; may be specified multiple times", claimFlag(&fed.Claims))
	valid := cli.DurationVar(fs, "valid", 0, "validity `period` of the JWT, such as 30 (minutes) or 8h, at most the max_valid of\n"+
		"the type (default: the valid of the type)")
	rest, _, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	name := rest[0]
	switch {
	case fed.Type == "":
		return errors.New("--token-type is required; token create makes the tokens of simple-ca")
	case !simpleca.KebabCaseRE.MatchString(name):
		return fmt.Errorf("name %q is not a kebab-case name, such as web-deploy", name)
	}
	dir := cli.ResolveCADir(*caDir)
	caKeyPath := filepath.Join(dir, "ca_key.pem")
	if !simpleca.FileExists(filepath.Join(dir, "ca_cert.pem")) || !simpleca.FileExists(caKeyPath) {
		return fmt.Errorf("CA certificate and key not found in %q. Please point --ca-dir to a CA directory", dir)
	}
	if err := simpleca.ReadKeyPassphrase(caKeyPath); err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}
	_, caID, err := simpleca.LocateCA(dir)
	if err != nil {
		return err
	}
	federation, err := fed.Resolve(cfg, caID, name)
	if err != nil {
		return err
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return err
	}
	jwt, id, _, err := tokens.IssueJWT(caKey, federation, *valid, time.Time{})
	if err != nil {
		return err
	}
	simpleca.Audit(dir, "token.issue", "name", name, "token_type", federation.TypeName, "audience", federation.Audience,
		"subject", federation.Subject, "jti", id, "via", "cli", "actor", simpleca.CLIActor())
	fmt.Println(jwt)
	return nil
}

// prefixList returns the function of a flag appending the prefixes of a comma-separated list to
// list.
func prefixList(list *[]string) func(string) error {
	return func(s string) error {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p == "" {
				return fmt.Errorf("empty prefix in %q", s)
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
	valid := cli.DurationVar(fs, "otc-valid", tokenSetupValid, "validity `period` of the setup code, such as 15 (minutes) or 1h")
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
	fs := cli.NewFlagSet("token list", "", "Lists the tokens of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return listTokens(os.Stdout, cli.ResolveCADir(*caDir))
}

// runTokenDescribe runs token describe.
func runTokenDescribe(args []string) error {
	fs := cli.NewFlagSet("token describe", "[NAME]",
		"Prints the attributes of the token NAME of the CA in --ca-dir, or of the token in the file of\n"+
			"--token-file, or on the standard input with --stdin.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	tokenFile := fs.String("token-file", "", "`file` holding the token")
	stdin := fs.Bool("stdin", false, "read the token from the standard input")
	rest, given, err := cli.ParseArgs(fs, args, 0, 1)
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
	var tok *tokens.APIToken
	limits := true
	var notes [][2]string
	var refused string
	if len(rest) == 1 {
		dir := cli.ResolveCADir(*caDir)
		if !simpleca.FileExists(filepath.Join(dir, "ca_cert.pem")) {
			return fmt.Errorf("CA certificate not found in %q. Please point --ca-dir to a CA directory", dir)
		}
		db, err := tokens.LoadTokens(dir)
		if err != nil {
			return err
		}
		if name, tok = rest[0], db.Tokens[rest[0]]; tok == nil {
			return fmt.Errorf("token %q not found in %q", name, filepath.Join(dir, tokens.TokensFile))
		}
	} else {
		var b []byte
		if *stdin {
			b, err = io.ReadAll(cli.Input)
		} else {
			b, err = os.ReadFile(*tokenFile)
		}
		if err != nil {
			return err
		}
		// The signature is checked, and the entry read, with the CA of --ca-dir alone.
		var caCert *x509.Certificate
		dir := cli.ResolveCADir(*caDir)
		if given["ca-dir"] {
			if caCert, err = simpleca.LoadCert(filepath.Join(dir, "ca_cert.pem")); err != nil {
				return err
			}
		}
		c, err := verifyJWT(caCert, strings.TrimSpace(string(b)))
		switch {
		case err != nil && caCert != nil:
			return fmt.Errorf("the token is not one signed by the CA in %q", dir)
		case err != nil:
			return errors.New("the token is not a JWT of simple-ca token create")
		}
		name, tok, limits = c.Subject, c.Token(), false
		if caCert == nil {
			notes = append(notes, [2]string{"Signature", "not checked; --ca-dir of its CA checks it and shows its limits"})
		} else if db, err := tokens.LoadTokens(dir); err != nil {
			return err
		} else if entry := db.Tokens[name]; entry != nil && entry.ID != "" && entry.ID == c.ID {
			tok, limits = entry, true
		} else {
			refused = "refused: the token was renewed, revoked or removed in " + filepath.Join(dir, tokens.TokensFile)
		}
	}
	attributes := describeToken(name, tok, limits)
	if refused != "" {
		attributes[1][1] = refused
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, a := range append(attributes, notes...) {
		fmt.Fprintf(tw, "%s:\t%s\n", simpleca.Printable(a[0]), simpleca.Printable(a[1]))
	}
	return tw.Flush()
}

// runTokenRevoke runs token revoke.
func runTokenRevoke(args []string) error {
	fs := cli.NewFlagSet("token revoke", "NAME",
		"Revokes the token NAME of the CA in --ca-dir; its JWT stops working at once.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if err := revokeToken(dir, rest[0]); err != nil {
		return err
	}
	simpleca.Audit(dir, "token.revoke", "name", rest[0], "via", "cli", "actor", simpleca.CLIActor())
	fmt.Printf("Token %q revoked\n", rest[0])
	return nil
}

// runTokenPurge runs token purge.
func runTokenPurge(args []string) error {
	fs := cli.NewFlagSet("token purge", "[NAME]",
		"Removes the expired and revoked tokens of the CA in --ca-dir, or only the token NAME, which\n"+
			"must be expired or revoked; removed tokens cannot be renewed.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := cli.ParseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if len(rest) == 1 {
		if err := purgeToken(dir, rest[0]); err != nil {
			return err
		}
		simpleca.Audit(dir, "token.purge", "name", rest[0], "via", "cli", "actor", simpleca.CLIActor())
		fmt.Printf("Token %q removed\n", rest[0])
		return nil
	}
	n, err := purgeTokens(dir, 0)
	if err != nil {
		return err
	}
	if n > 0 {
		simpleca.Audit(dir, "token.purge", "count", n, "via", "cli", "actor", simpleca.CLIActor())
	}
	fmt.Printf("%d expired or revoked tokens removed\n", n)
	return nil
}

// runTokenRenew runs token renew.
func runTokenRenew(args []string) error {
	fs := cli.NewFlagSet("token renew", "NAME",
		"Renews the token NAME of the CA in --ca-dir with a new JWT and prints it, or with --otc a\n"+
			"one-time setup code; the old JWT stops working. An encrypted CA key needs its passphrase.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := cli.DurationVar(fs, "valid", 0, "validity `period` of the token, such as 30 (minutes), 8h, 180d, 6m or 1y (default:\n"+
		"the period it had)")
	setup := setupFlags(fs)
	rest, given, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	setupValid, setupClients, err := setup(given)
	if err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
		return err
	}
	token, err := reissueToken(dir, rest[0], *valid, setupValid, setupClients)
	if err != nil {
		return err
	}
	simpleca.Audit(dir, "token.renew", "name", rest[0], "setup_code", setupValid > 0, "via", "cli", "actor", simpleca.CLIActor())
	fmt.Println(token)
	return nil
}

// runTokenJWKS runs token jwks.
func runTokenJWKS(args []string) error {
	fs := cli.NewFlagSet("token jwks", "",
		"Prints the JSON Web Key Set of the CA in --ca-dir, the public key verifying its tokens.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	dir := cli.ResolveCADir(*caDir)
	if !simpleca.FileExists(filepath.Join(dir, "ca_cert.pem")) {
		return fmt.Errorf("CA certificate not found in %q. Please point --ca-dir to a CA directory", dir)
	}
	b, err := tokens.CAJWKS(dir)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
