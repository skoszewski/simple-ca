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
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"golang.org/x/term"
)

// ---- helpers ----------------------------------------------------------------

// dirExists reports whether path is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// durationFlag is a flag.Value of a duration in the form simpleca.ParseDuration reads.
type durationFlag time.Duration

func (f *durationFlag) String() string { return simpleca.DurationText(time.Duration(*f)) }

func (f *durationFlag) Set(s string) error {
	d, err := simpleca.ParseDuration(s)
	if err == nil {
		*f = durationFlag(d)
	}
	return err
}

// durationVar defines the duration flag name of fs, with the default value, and returns where
// it is stored.
func durationVar(fs *flag.FlagSet, name string, value time.Duration, usage string) *time.Duration {
	fs.Var((*durationFlag)(&value), name, usage)
	return &value
}

// randomSerial returns a random positive certificate serial number of at most 159 bits.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, limit)
}

// writePEMFile writes der as a single PEM block of blockType to path with the given mode.
func writePEMFile(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

// keyTypes are the key types of --key-type: rsa, RSA 4096, and ec, ECDSA P-256.
var keyTypes = []string{"rsa", "ec"}

// newKey returns a new private key of keyType, rsa or ec.
func newKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case "rsa":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ec":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("key type '%s' must be rsa or ec", keyType)
}

// writeKey writes key to path as a PKCS#8 PEM file readable by the owner alone, encrypted with
// the passphrase of the private keys when it is known.
func writeKey(key crypto.Signer, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	blockType := "ENCRYPTED PRIVATE KEY"
	pass, err := simpleca.KeyPassphrase(false)
	switch {
	case errors.Is(err, simpleca.ErrNoPassphrase):
		blockType = "PRIVATE KEY"
	case err != nil:
		return err
	default:
		if der, err = simpleca.EncryptKeyDER(der, pass); err != nil {
			return err
		}
	}
	// The key replaces the file at once, so an earlier file's mode is not kept.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = cmp.Or(tmp.Chmod(0o600), pem.Encode(tmp, &pem.Block{Type: blockType, Bytes: der}), tmp.Close())
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---- private key encryption -------------------------------------------------

// init lets simpleca.KeyPassphrase read the passphrase of the private keys from a terminal.
func init() {
	simpleca.PromptPassphrase = func(prompt string) ([]byte, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, simpleca.ErrNoPassphrase
		}
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return b, err
	}
}

// keyStatus returns ENC for the encrypted private key file at path, PLAIN for an unencrypted one,
// and - when there is no file.
func keyStatus(path string) string {
	switch {
	case !simpleca.FileExists(path):
		return "-"
	case simpleca.KeyEncrypted(path):
		return "ENC"
	}
	return "PLAIN"
}

// writeCert writes a DER certificate to path as a PEM file.
func writeCert(der []byte, path string) error {
	return writePEMFile(path, "CERTIFICATE", der, 0o644)
}

// serialHex formats a serial number the way `openssl x509 -serial` prints it.
func serialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}
