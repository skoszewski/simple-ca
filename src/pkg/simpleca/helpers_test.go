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

package simpleca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA is a CA directory made by the tests, with its certificate and key.
type testCA struct {
	dir  string
	cert *x509.Certificate
	key  crypto.Signer
}

// newKey returns a new key of keyType, rsa or ec.
func newKey(t *testing.T, keyType string) crypto.Signer {
	t.Helper()
	var key crypto.Signer
	var err error
	if keyType == "ec" {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// writePEM writes one PEM block to path, readable by its owner alone.
func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeKey writes key to path in PKCS#8, encrypted with pass unless it is empty.
func writeKey(t *testing.T, path string, key crypto.Signer, pass string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	blockType := "PRIVATE KEY"
	if pass != "" {
		if der, err = EncryptKeyDER(der, pass); err != nil {
			t.Fatal(err)
		}
		blockType = "ENCRYPTED PRIVATE KEY"
	}
	writePEM(t, path, blockType, der)
}

// writeCA makes the CA name in dir with ca_cert.pem and ca_key.pem: a self-signed root CA without
// parent, else an issuing CA signed by parent.
func writeCA(t *testing.T, dir, name, keyType string, parent *testCA) *testCA {
	t.Helper()
	key := newKey(t, keyType)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuer, issuerKey := tmpl, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca_cert.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	writeKey(t, filepath.Join(dir, "ca_key.pem"), key, "")
	return &testCA{dir: dir, cert: cert, key: key}
}

// newRoot makes a root CA in a new directory.
func newRoot(t *testing.T, keyType string) *testCA {
	t.Helper()
	return writeCA(t, t.TempDir(), "Test Root CA", keyType, nil)
}

// newIssuing makes the issuing CA name of root, in its subdirectory name.
func newIssuing(t *testing.T, root *testCA, name, keyType string) *testCA {
	t.Helper()
	return writeCA(t, filepath.Join(root.dir, name), name+" CA", keyType, root)
}

// writeConfig writes the JSON settings to simple-ca.json of dir.
func writeConfig(t *testing.T, dir, settings string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// resetKeys forgets the passphrase and the keys read, and restores PromptPassphrase when the test
// ends; it clears the passphrase variables of the environment for the test.
func resetKeys(t *testing.T) {
	t.Helper()
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", "")
	forget := func() {
		keyPasswordMu.Lock()
		keyPassword = ""
		keyPasswordMu.Unlock()
		loadedKeysMu.Lock()
		clear(loadedKeys)
		loadedKeysMu.Unlock()
	}
	forget()
	prompt := PromptPassphrase
	t.Cleanup(func() {
		forget()
		PromptPassphrase = prompt
	})
}
