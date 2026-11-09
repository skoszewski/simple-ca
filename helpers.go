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
	"bytes"
	"cmp"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/term"
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

// writeKey writes key to path as a PKCS#8 PEM file readable by the owner alone, encrypted with
// the passphrase of the private keys when it is known.
func writeKey(key crypto.Signer, path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	blockType := "ENCRYPTED PRIVATE KEY"
	pass, err := keyPassphrase(false)
	switch {
	case errors.Is(err, errNoPassphrase):
		blockType = "PRIVATE KEY"
	case err != nil:
		return err
	default:
		if der, err = encryptKeyDER(der, pass); err != nil {
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

// errNoPassphrase is the error of keyPassphrase when no source gives the passphrase.
var errNoPassphrase = errors.New("no passphrase for private keys; set SIMPLE_CA_KEY_PASSWORD or SIMPLE_CA_KEY_PASSWORD_FILE")

// keyPassword is the passphrase of the private keys once keyPassphrase has read it.
var (
	keyPassword   string
	keyPasswordMu sync.Mutex
)

// keyPassphrase returns the passphrase of the private keys: $SIMPLE_CA_KEY_PASSWORD, else the
// file named by $SIMPLE_CA_KEY_PASSWORD_FILE without its line end, else, with tty and stdin a
// terminal, one read from it unechoed; it fails with errNoPassphrase when none gives it.
func keyPassphrase(tty bool) (string, error) {
	keyPasswordMu.Lock()
	defer keyPasswordMu.Unlock()
	if keyPassword != "" {
		return keyPassword, nil
	}
	env, file := os.Getenv("SIMPLE_CA_KEY_PASSWORD"), os.Getenv("SIMPLE_CA_KEY_PASSWORD_FILE")
	var pass string
	switch {
	case env != "" && file != "":
		return "", errors.New("SIMPLE_CA_KEY_PASSWORD and SIMPLE_CA_KEY_PASSWORD_FILE must not be set together")
	case env != "":
		pass = env
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		pass = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		if pass == "" {
			return "", fmt.Errorf("the passphrase in %s is empty", file)
		}
	case tty && term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(os.Stderr, "Passphrase for private keys: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if len(b) == 0 {
			return "", errors.New("the passphrase must not be empty")
		}
		pass = string(b)
	default:
		return "", errNoPassphrase
	}
	keyPassword = pass
	return pass, nil
}

// readKeyPassphrase reads the passphrase of the private keys, from a terminal too, when one of the
// key files paths is encrypted; a command calls it at its start.
func readKeyPassphrase(paths ...string) error {
	if !slices.ContainsFunc(paths, keyEncrypted) {
		return nil
	}
	_, err := keyPassphrase(true)
	return err
}

// keyStatus returns ENC for the encrypted private key file at path, PLAIN for an unencrypted one,
// and - when there is no file.
func keyStatus(path string) string {
	switch {
	case !fileExists(path):
		return "-"
	case keyEncrypted(path):
		return "ENC"
	}
	return "PLAIN"
}

// keyEncrypted reports whether the first PEM block of the file path is an encrypted private key.
func keyEncrypted(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	return block != nil && block.Type == "ENCRYPTED PRIVATE KEY"
}

// The object identifiers of PBES2 (RFC 8018) and of the algorithms it is read with.
var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// keyIterations is the PBKDF2 iteration count of the keys simple-ca encrypts, and keyMaxIterations
// the most it reads a key with.
const (
	keyIterations    = 600000
	keyMaxIterations = 10000000
)

// encryptedPrivateKeyInfo is the EncryptedPrivateKeyInfo of RFC 5958.
type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// pbes2Params is the PBES2-params of RFC 8018.
type pbes2Params struct {
	KDF    pkix.AlgorithmIdentifier
	Cipher pkix.AlgorithmIdentifier
}

// pbkdf2Params is the PBKDF2-params of RFC 8018, with a specified salt.
type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// encryptKeyDER returns the PKCS#8 private key der as an EncryptedPrivateKeyInfo, encrypted with
// PBES2: PBKDF2 with HMAC-SHA256 and AES-256-CBC.
func encryptKeyDER(der []byte, pass string) ([]byte, error) {
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, pass, salt, keyIterations, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	n := aes.BlockSize - len(der)%aes.BlockSize
	data := append(bytes.Clone(der), bytes.Repeat([]byte{byte(n)}, n)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	kdf, err := asn1.Marshal(pbkdf2Params{Salt: salt, Iterations: keyIterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue}})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdf}},
		Cipher: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}}})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: params}},
		Data:      data})
}

// decryptKeyDER returns the PKCS#8 private key of the EncryptedPrivateKeyInfo der, encrypted with
// PBES2: PBKDF2 with HMAC-SHA1 or HMAC-SHA256, and AES-128, AES-192 or AES-256 in CBC mode.
func decryptKeyDER(der []byte, pass string) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) > 0 {
		return nil, errors.New("not a PKCS#8 encrypted private key")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("the key is encrypted with %s, not PBES2", info.Algorithm.Algorithm)
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("bad PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("the key derivation function %s is not PBKDF2", params.KDF.Algorithm)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("bad PBKDF2 parameters: %w", err)
	}
	var prf func() hash.Hash
	switch {
	case kdf.PRF.Algorithm == nil || kdf.PRF.Algorithm.Equal(oidHMACWithSHA1):
		prf = sha1.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA256):
		prf = sha256.New
	default:
		return nil, fmt.Errorf("the PBKDF2 function %s is not HMAC-SHA1 or HMAC-SHA256", kdf.PRF.Algorithm)
	}
	var size int
	switch {
	case params.Cipher.Algorithm.Equal(oidAES128CBC):
		size = 16
	case params.Cipher.Algorithm.Equal(oidAES192CBC):
		size = 24
	case params.Cipher.Algorithm.Equal(oidAES256CBC):
		size = 32
	default:
		return nil, fmt.Errorf("the cipher %s is not AES-CBC", params.Cipher.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.Cipher.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("bad AES-CBC initialization vector")
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != size || kdf.Iterations < 1 || kdf.Iterations > keyMaxIterations {
		return nil, errors.New("bad PBKDF2 parameters")
	}
	if len(info.Data) == 0 || len(info.Data)%aes.BlockSize != 0 {
		return nil, errors.New("bad encrypted key length")
	}
	key, err := pbkdf2.Key(prf, pass, kdf.Salt, kdf.Iterations, size)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data := bytes.Clone(info.Data)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	n := int(data[len(data)-1])
	if n < 1 || n > aes.BlockSize || !bytes.Equal(data[len(data)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("wrong passphrase")
	}
	return data[:len(data)-n], nil
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

// loadedKeys are the keys loadKey has read, by path, with the contents of their files.
var (
	loadedKeys   = map[string]loadedKey{}
	loadedKeysMu sync.Mutex
)

// loadedKey is a key loadKey has read, with the contents of its file.
type loadedKey struct {
	file []byte
	key  crypto.Signer
}

// loadKey reads the first PEM block of path as a private key: PKCS#8 RSA or ECDSA P-256,
// encrypted or not, PKCS#1 RSA, or SEC1 ECDSA P-256; a key is read again only when its file
// changes.
func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	loadedKeysMu.Lock()
	loaded, ok := loadedKeys[path]
	loadedKeysMu.Unlock()
	if ok && bytes.Equal(loaded.file, b) {
		return loaded.key, nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	der := block.Bytes
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		pass, err := keyPassphrase(false)
		if err != nil {
			return nil, fmt.Errorf("%s is encrypted: %w", path, err)
		}
		if der, err = decryptKeyDER(der, pass); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(der); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(der); err != nil {
			if key, err = x509.ParseECPrivateKey(der); err != nil {
				return nil, fmt.Errorf("no RSA or ECDSA private key in %s", path)
			}
		}
	}
	var signer crypto.Signer
	switch k := key.(type) {
	case *rsa.PrivateKey:
		signer = k
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("the ECDSA key in %s is not on the curve P-256", path)
		}
		signer = k
	default:
		return nil, fmt.Errorf("the key in %s is not an RSA or ECDSA P-256 key", path)
	}
	loadedKeysMu.Lock()
	loadedKeys[path] = loadedKey{file: b, key: signer}
	loadedKeysMu.Unlock()
	return signer, nil
}

// serialHex formats a serial number the way `openssl x509 -serial` prints it.
func serialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}
