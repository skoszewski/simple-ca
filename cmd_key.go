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
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---- key commands -----------------------------------------------------------

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
	verb, what := "decrypt", "Decrypt the private keys of the CA in --ca-dir, ca_key.pem and the *_key.pem files, with the\n"+
		"passphrase of the private keys, and write them as unencrypted PKCS#8."
	if encrypt {
		verb, what = "encrypt", "Encrypt the private keys of the CA in --ca-dir, ca_key.pem and the *_key.pem files, with the\n"+
			"passphrase of the private keys, as encrypted PKCS#8; keys already encrypted are skipped."
	}
	fs := newFlagSet("key "+verb, "", what+"\n\n"+
		"The passphrase is $SIMPLE_CA_KEY_PASSWORD, else the file named by\n"+
		"$SIMPLE_CA_KEY_PASSWORD_FILE, else, on a terminal, typed at the prompt.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	all := fs.Bool("all", false, verb+" the keys of the root CA of --ca-dir and of all its issuing CAs")
	if _, _, err := parseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	dir := resolveCADir(*caDir)
	rootDir, _, err := locateCA(dir)
	if err != nil {
		return err
	}
	dirs := []string{dir}
	if *all {
		dirs = nil
		for _, id := range caIDs(rootDir) {
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
		_, err = keyPassphrase(true)
	} else {
		err = readKeyPassphrase(paths...)
	}
	if err != nil {
		return err
	}

	// Every key is tried, also after one fails.
	var errs []error
	for _, d := range dirs {
		var done []string
		for _, path := range keys[d] {
			converted, err := convertKey(path, encrypt)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if converted {
				done = append(done, filepath.Base(path))
				fmt.Printf("%sed %s\n", strings.ToUpper(verb[:1])+verb[1:], path)
			}
		}
		if len(done) > 0 {
			audit(d, "key."+verb, "files", strings.Join(done, ","), "via", "cli", "actor", cliActor())
		}
	}
	return errors.Join(errs...)
}

// convertKey rewrites the private key in path as encrypted PKCS#8, with encrypt, or unencrypted
// PKCS#8, and reports whether it did; a key already in that form is left as it is.
func convertKey(path string, encrypt bool) (bool, error) {
	if keyEncrypted(path) == encrypt {
		return false, nil
	}
	key, err := loadKey(path)
	if err != nil {
		return false, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	blockType := "PRIVATE KEY"
	if encrypt {
		pass, err := keyPassphrase(false)
		if err != nil {
			return false, err
		}
		if der, err = encryptKeyDER(der, pass); err != nil {
			return false, err
		}
		blockType = "ENCRYPTED PRIVATE KEY"
	}

	// The key is written to a new file of the owner alone, which then replaces it.
	f, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(f.Name(), path)
}
