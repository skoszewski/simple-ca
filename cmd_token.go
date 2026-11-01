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
		"Create the token NAME of the signing API of the CA in --ca-dir, and print it.\n\n"+
			"The token is a JWT signed with the CA key, valid for that CA alone. It allows the\n"+
			"certificate types of --type, the names of the --domain domains and below them, and the IP\n"+
			"addresses of --ip; at least one --domain, --ip or --localhost is given. With --host or\n"+
			"--network, it is accepted only from those client addresses.\n\n"+
			"An option not given takes its default from tokens of simple-ca.json, and the defaults\n"+
			"below without it; --host and --network replace hosts and networks together.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	valid := fs.Duration("valid", time.Hour, "validity `period` of the token, such as 30m, 8h or 720h")
	localhost := fs.Bool("localhost", false, "allow certificates of localhost, with the IP SAN 127.0.0.1")
	var certTypes, domains, ips, clients []string
	fs.Func("type", "certificate `type` the token allows; repeated for more (default: server)", func(s string) error {
		certTypes = append(certTypes, s)
		return nil
	})
	fs.Func("domain", "`domain` whose names, and the names below it, the token allows, or * for any name;\n"+
		"repeated for more", func(s string) error {
		domains = append(domains, s)
		return nil
	})
	fs.Func("ip", "IP `address` or prefix, such as 192.0.2.10 or 10.0.0.0/8, the IP SANs of the\n"+
		"certificates may be in, or * for any address; repeated for more", func(s string) error {
		ips = append(ips, s)
		return nil
	})
	fs.Func("host", "client IP `address` the token is accepted from; repeated for more (default: any)", func(s string) error {
		clients = append(clients, s)
		return nil
	})
	fs.Func("network", "comma-separated `prefixes`, such as 192.168.1.0/24,10.0.0.0/8, of the client\n"+
		"addresses the token is accepted from; repeated for more (default: any)", func(s string) error {
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
	if !given["host"] && !given["network"] {
		clients = append(slices.Clone(defaults.Hosts), defaults.Networks...)
	}
	if len(certTypes) == 0 {
		certTypes = []string{"server"}
	}
	if *localhost {
		domains = append(domains, "localhost")
		ips = append(ips, "127.0.0.1")
	}
	token, err := makeToken(dir, rest[0], *valid, certTypes, domains, ips, clients)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runTokenList runs token list.
func runTokenList(args []string) error {
	fs := newFlagSet("token list", "", "List the tokens of the signing API of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return listTokens(os.Stdout, resolveCADir(*caDir))
}

// runTokenRevoke runs token revoke.
func runTokenRevoke(args []string) error {
	fs := newFlagSet("token revoke", "NAME", "Revoke the token NAME of the signing API of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return revokeToken(resolveCADir(*caDir), rest[0])
}

// runTokenPurge runs token purge.
func runTokenPurge(args []string) error {
	fs := newFlagSet("token purge", "", "Remove the expired tokens of the signing API of the CA in --ca-dir.")
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
