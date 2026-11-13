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
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// runKeyEncrypt runs key encrypt.
func runKeyEncrypt(args []string) error {
	return convertKeys(args, true)
}

// runKeyDecrypt runs key decrypt.
func runKeyDecrypt(args []string) error {
	return convertKeys(args, false)
}

// convertKeys runs key encrypt, with encrypt, or key decrypt: it rewrites ca_key.pem and the
// *_key.pem files of the CA in --ca-dir, or of the root CA and all its issuing CAs with --all, as
// encrypted or unencrypted PKCS#8, skipping those already in that form.
func convertKeys(args []string, encrypt bool) error {
	verb, what := "decrypt", "Decrypts the private keys of the CA in --ca-dir, ca_key.pem and the *_key.pem files, as\n"+
		"unencrypted PKCS#8."
	if encrypt {
		verb, what = "encrypt", "Encrypts the private keys of the CA in --ca-dir, ca_key.pem and the *_key.pem files, as\n"+
			"encrypted PKCS#8."
	}
	fs := NewFlagSet("key "+verb, "", what+" The passphrase is SIMPLE_CA_KEY_PASSWORD, else the file of\n"+
		"SIMPLE_CA_KEY_PASSWORD_FILE, else typed at the prompt of a terminal.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	all := fs.Bool("all", false, verb+" the keys of the root CA of --ca-dir and of all its issuing CAs")
	if _, _, err := ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	rootDir, _, err := simpleca.LocateCA(dir)
	if err != nil {
		return err
	}
	dirs := []string{dir}
	if *all {
		dirs = nil
		for _, id := range simpleca.CAIDs(rootDir) {
			dirs = append(dirs, filepath.Join(rootDir, id))
		}
	}
	keys := map[string][]string{}
	var paths []string
	for _, d := range dirs {
		if keys[d], err = filepath.Glob(filepath.Join(d, "*_key.pem")); err != nil {
			return err
		}
		paths = append(paths, keys[d]...)
	}
	if encrypt {
		_, err = simpleca.KeyPassphrase(true)
	} else {
		err = simpleca.ReadKeyPassphrase(paths...)
	}
	if err != nil {
		return err
	}

	// Every key is tried, also after one fails.
	var errs []error
	for _, d := range dirs {
		var done []string
		for _, path := range keys[d] {
			converted, err := cert.ConvertKey(path, encrypt)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if converted {
				done = append(done, filepath.Base(path))
				fmt.Printf("%sed %q\n", strings.ToUpper(verb[:1])+verb[1:], path)
			}
		}
		if len(done) > 0 {
			simpleca.Audit(d, "key."+verb, "files", strings.Join(done, ","), "via", "cli", "actor", simpleca.CLIActor())
		}
	}
	return errors.Join(errs...)
}
