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
	"fmt"
	"os"
	"slices"
	"strings"
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
		"192.168.1.0/24,10.0.0.0/8; may be specified multiple times (default: any)", func(s string) error {

		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p == "" {
				return fmt.Errorf("empty prefix in '%s'", s)
			}
			clients = append(clients, p)
		}
		return nil
	})
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
	token, err := makeToken(dir, rest[0], *valid, scopes, certTypes, domains, ips, clients)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
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
			"JWT, valid from now, with the same scopes and limits; the old JWT stops working.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := fs.Duration("valid", 0, "validity `period` of the token, such as 30m, 8h or 720h (default: the period it had)")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	token, err := renewToken(resolveCADir(*caDir), rest[0], *valid)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}
