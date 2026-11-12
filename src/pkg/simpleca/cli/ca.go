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

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// runCACreate runs ca create.
func runCACreate(args []string) error {
	fs := NewFlagSet("ca create", "CA_NAME",
		"Creates the root CA CA_NAME in --ca-dir, or with --issuing-ca an issuing CA in its subdirectory,\n"+
			"signed by the root CA. An encrypted root CA key needs its passphrase.")
	days := fs.Int("days", 3650, "validity period in `days`; an issuing CA is valid as long as its root CA by default")
	issuingCA := fs.String("issuing-ca", "", "create an issuing CA with this directory `name`")
	baseURL := fs.String("ca-url", "", "base `URL` for AIA and CRL distribution point extensions")
	fs.StringVar(baseURL, "ca-publish-base-url", "", "former name of --ca-url")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA")
	keyType := fs.String("key-type", "rsa", "`type` of the CA key: rsa (RSA 4096, RS256 tokens) or ec (ECDSA P-256, ES256 tokens)")
	writeConf := fs.Bool("write-conf", false, "also write openssl.cnf for the openssl ca command to the CA directory")
	rest, given, err := ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	if *issuingCA != "" {
		if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
			return err
		}
	}
	cfg, err := simpleca.LoadConfig(dir)
	if err != nil {
		return err
	}
	switch {
	case !given["days"] && cfg.Days.CA > 0:
		*days = cfg.Days.CA
	case !given["days"] && *issuingCA != "":
		*days = 0
	}
	if err := cert.MakeCA(dir, rest[0], *days, *issuingCA, *baseURL, *keyType); err != nil {
		return err
	}
	target := dir
	if *issuingCA != "" {
		target = filepath.Join(dir, *issuingCA)
	}
	if crt, err := simpleca.LoadCert(filepath.Join(target, "ca_cert.pem")); *days == 0 && err == nil {
		*days = int(crt.NotAfter.Sub(crt.NotBefore).Hours() / 24)
	}
	simpleca.Audit(target, "ca.create", "subject", rest[0], "days", *days, "key_type", *keyType, "via", "cli", "actor", simpleca.CLIActor())
	if !*writeConf {
		return nil
	}
	path, err := cert.WriteOpenSSLConf(target)
	if err != nil {
		return err
	}
	fmt.Printf("openssl ca configuration written to %s\n", path)
	return nil
}

// runCAShow runs ca show.
func runCAShow(args []string) error {
	fs := NewFlagSet("ca show", "", "Shows the CA in --ca-dir, its certificate counts and its CRL.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	return cert.ShowInfo(os.Stdout, ResolveCADir(*caDir))
}
