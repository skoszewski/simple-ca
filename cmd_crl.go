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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// ---- crl commands -----------------------------------------------------------

// runCRLCreate runs crl create.
func runCRLCreate(args []string) error {
	fs := newFlagSet("crl create", "", "Generate the CRL of the CA in --ca-dir.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	days := fs.Int("days", 30, "CRL validity in `days`")
	all := fs.Bool("all", false, "generate the CRLs of the root CA of --ca-dir and of all its issuing CAs")
	_, given, err := parseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	rootDir, _, err := simpleca.LocateCA(dir)
	if err != nil {
		return err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.CRL > 0 {
		*days = cfg.Days.CRL
	}
	if !*all {
		if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
			return err
		}
		if err := makeCRL(dir, *days); err != nil {
			return err
		}
		auditCRL(dir, "via", "cli", "actor", simpleca.CLIActor())
		fmt.Printf("CRL written to %s\n", filepath.Join(dir, "crl.pem"))
		return nil
	}

	// Every CA is tried, also after one fails.
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return err
	}
	dirs := []string{rootDir}
	for _, e := range entries {
		sub := filepath.Join(rootDir, e.Name())
		if e.IsDir() && simpleca.FileExists(filepath.Join(sub, "ca_cert.pem")) && simpleca.FileExists(filepath.Join(sub, "ca_key.pem")) {
			dirs = append(dirs, sub)
		}
	}
	keys := make([]string, len(dirs))
	for i, d := range dirs {
		keys[i] = filepath.Join(d, "ca_key.pem")
	}
	if err := simpleca.ReadKeyPassphrase(keys...); err != nil {
		return err
	}
	var errs []error
	for _, d := range dirs {
		if err := makeCRL(d, *days); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", d, err))
			continue
		}
		auditCRL(d, "via", "cli", "actor", simpleca.CLIActor())
		fmt.Printf("CRL written to %s\n", filepath.Join(d, "crl.pem"))
	}
	return errors.Join(errs...)
}
