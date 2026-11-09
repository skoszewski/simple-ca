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
	"path/filepath"
)

// ---- ca commands ------------------------------------------------------------

// runCACreate runs ca create.
func runCACreate(args []string) error {
	fs := newFlagSet("ca create", "CA_NAME", "Create a root or issuing CA.")
	days := fs.Int("days", 3650, "validity period in `days`")
	issuingCA := fs.String("issuing-ca", "", "create an issuing CA with this directory `name`")
	baseURL := fs.String("ca-url", "", "base `URL` for AIA and CRL distribution point extensions")
	fs.StringVar(baseURL, "ca-publish-base-url", "", "former name of --ca-url")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA")
	keyType := fs.String("key-type", "rsa", "`type` of the CA key: rsa (RSA 4096, RS256 tokens) or ec (ECDSA P-256, ES256 tokens)")
	writeConf := fs.Bool("write-conf", false, "also write openssl.cnf for the openssl ca command to the CA directory")
	rest, given, err := parseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	cfg, err := loadConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.CA > 0 {
		*days = cfg.Days.CA
	}
	if err := makeCA(dir, rest[0], *days, *issuingCA, *baseURL, *keyType); err != nil {
		return err
	}
	target := dir
	if *issuingCA != "" {
		target = filepath.Join(dir, *issuingCA)
	}
	audit(target, "ca.create", "subject", rest[0], "days", *days, "key_type", *keyType, "via", "cli", "actor", cliActor())
	if !*writeConf {
		return nil
	}
	path, err := writeOpenSSLConf(target)
	if err != nil {
		return err
	}
	fmt.Printf("openssl ca configuration written to %s\n", path)
	return nil
}

// runCAShow runs ca show.
func runCAShow(args []string) error {
	fs := newFlagSet("ca show", "", "Show the CA in --ca-dir, its certificate counts and its CRL.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return showInfo(os.Stdout, resolveCADir(*caDir))
}
