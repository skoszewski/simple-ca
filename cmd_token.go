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
	"net/netip"
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
	fs := newFlagSet("token revoke", "NAME", "Revoke the token NAME of the signing API of the CA in --ca-dir: its JWT is refused\n"+
		"from then on, and the token is kept, to be renewed, until token purge removes it.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return revokeToken(resolveCADir(*caDir), rest[0])
}

// runTokenWebUI runs token webui until it fails or is interrupted.
func runTokenWebUI(args []string) error {
	return runWebUI(args, "token webui", 8081, false,
		"Serve a web page managing the tokens of the signing API of the root CA of the CA in\n"+
			"--ca-dir and of its issuing CAs, with its API below /api/: list, create, renew, revoke and\n"+
			"purge them.")
}

// runWebUI runs token webui, or cert webui with certs, named command, on port by default, until it
// fails or is interrupted; summary describes it.
func runWebUI(args []string, command string, port int, certs bool, summary string) error {
	fs := newFlagSet(command, "", summary+"\n\n"+
		"The API takes the key printed at the start as the bearer token of each request, until\n"+
		command+" stops; the page asks for it, or reads it from ?key= of its URL.")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA or of one of its issuing CAs")
	address := fs.String("address", "127.0.0.1", "`address` of the interface to listen on")
	fs.IntVar(&port, "port", port, "TCP `port` to listen on")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	rootDir, _, err := locateCA(resolveCADir(*caDir))
	if err != nil {
		return err
	}
	ui := &webuiServer{rootDir: rootDir, key: randomID(), certs: certs}
	what := "tokens"
	if certs {
		what = "certificates"
	}
	return runHTTPServer(ui.mux(), *address, port, "", "", func(origin string) {
		if ip, err := netip.ParseAddr(*address); err != nil || !ip.IsLoopback() {
			fmt.Fprintln(os.Stderr, "warning: the page is served over plain HTTP beyond this machine; "+
				"its key can be read on the network")
		}
		fmt.Printf("Managing the %s of the CAs of %s; open this URL, or give the page its key, valid\n"+
			"until %s stops:\n  %s/?key=%s\n", what, rootDir, command, origin, ui.key)
	})
}

// runTokenPurge runs token purge.
func runTokenPurge(args []string) error {
	fs := newFlagSet("token purge", "[NAME]",
		"Remove the expired and revoked tokens of the signing API of the CA in --ca-dir, or the\n"+
			"token NAME alone, expired or revoked, for good: a token removed cannot be renewed.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
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
		"Renew the token NAME of the signing API of the CA in --ca-dir, expired or not, and print\n"+
			"it: it gets a new JWT ID and is valid from now, allowing what it allowed before, and the\n"+
			"JWT it had is refused from then on.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
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
