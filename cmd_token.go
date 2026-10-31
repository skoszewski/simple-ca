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
	"time"
)

// ---- token commands ---------------------------------------------------------

// runTokenCreate runs token create.
func runTokenCreate(args []string) error {
	fs := newFlagSet("token create", "NAME",
		"Create the token NAME of the signing API of the CA in --ca-dir, and print it.\n\n"+
			"The token is a JWT signed with the CA key, valid for that CA alone. It allows the\n"+
			"certificate types of --type, and the names of the --domain domains and below them.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA, the root CA or an issuing CA")
	valid := fs.Duration("valid", time.Hour, "validity `period` of the token, such as 30m, 8h or 720h")
	var certTypes, domains []string
	fs.Func("type", "certificate `type` the token allows; repeated for more (default: server)", func(s string) error {
		certTypes = append(certTypes, s)
		return nil
	})
	fs.Func("domain", "`domain` whose names, and the names below it, the token allows; repeated for more", func(s string) error {
		domains = append(domains, s)
		return nil
	})
	rest, _, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if len(certTypes) == 0 {
		certTypes = []string{"server"}
	}
	token, err := makeToken(resolveCADir(*caDir), rest[0], *valid, certTypes, domains)
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
