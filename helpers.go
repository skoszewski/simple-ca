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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"regexp"
)

// ---- helpers ----------------------------------------------------------------

// kebabCaseRE matches a kebab-case name, the form of the names of issuing CAs, certificate types
// and tokens: words of lower-case letters and digits joined by single hyphens, such as web-server.
var kebabCaseRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// dirExists reports whether path is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExists reports whether path exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
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

// keyType returns the key type of the public key pub, rsa or ec.
func keyType(pub crypto.PublicKey) string {
	if _, ok := pub.(*ecdsa.PublicKey); ok {
		return "ec"
	}
	return "rsa"
}

// writeKey writes key to path as an unencrypted PKCS#8 PEM file readable by the owner alone.
func writeKey(key crypto.Signer, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(path, "PRIVATE KEY", der, 0o600)
}

// writeCert writes a DER certificate to path as a PEM file.
func writeCert(der []byte, path string) error {
	return writePEMFile(path, "CERTIFICATE", der, 0o644)
}

// loadCert reads the first PEM block of path as a certificate.
func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

// loadKey reads the first PEM block of path as a private key: PKCS#8 RSA or ECDSA P-256, PKCS#1
// RSA, or SEC1 ECDSA P-256.
func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("no RSA or ECDSA private key in %s", path)
			}
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("the ECDSA key in %s is not on the curve P-256", path)
		}
		return k, nil
	}
	return nil, fmt.Errorf("the key in %s is not an RSA or ECDSA P-256 key", path)
}

// serialHex formats a serial number the way `openssl x509 -serial` prints it.
func serialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}
