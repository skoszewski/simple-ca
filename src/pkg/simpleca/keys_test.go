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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// samePublic reports whether the keys a and b have the same public key.
func samePublic(a, b crypto.Signer) bool {
	return a.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(b.Public())
}

func TestKeyType(t *testing.T) {
	if got := KeyType(newKey(t, "ec").Public()); got != "ec" {
		t.Errorf("KeyType of an ECDSA key = %q, want ec", got)
	}
	if got := KeyType(newKey(t, "rsa").Public()); got != "rsa" {
		t.Errorf("KeyType of an RSA key = %q, want rsa", got)
	}
}

func TestLoadKeyFormats(t *testing.T) {
	dir := t.TempDir()
	rsaKey := newKey(t, "rsa").(*rsa.PrivateKey)
	ecKey := newKey(t, "ec").(*ecdsa.PrivateKey)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(key any) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	sec1 := func(key *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for _, c := range []struct {
		name, blockType string
		der             []byte
		want            crypto.Signer
		err             string
	}{
		{"pkcs8-rsa", "PRIVATE KEY", pkcs8(rsaKey), rsaKey, ""},
		{"pkcs8-ec", "PRIVATE KEY", pkcs8(ecKey), ecKey, ""},
		{"pkcs1", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), rsaKey, ""},
		{"sec1", "EC PRIVATE KEY", sec1(ecKey), ecKey, ""},
		{"pkcs8-p384", "PRIVATE KEY", pkcs8(p384), nil, "not on the curve P-256"},
		{"sec1-p384", "EC PRIVATE KEY", sec1(p384), nil, "not on the curve P-256"},
		{"pkcs8-ed25519", "PRIVATE KEY", pkcs8(edKey), nil, "not an RSA or ECDSA P-256 key"},
		{"garbage", "PRIVATE KEY", []byte{1, 2, 3}, nil, "no RSA or ECDSA private key"},
	} {
		path := filepath.Join(dir, c.name+".pem")
		writePEM(t, path, c.blockType, c.der)
		key, err := LoadKey(path)
		switch {
		case c.err == "" && (err != nil || !samePublic(key, c.want)):
			t.Errorf("LoadKey of %s: %v, want the key written", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("LoadKey of %s: %v, want an error with %q", c.name, err, c.err)
		}
	}
	text := filepath.Join(dir, "text.pem")
	if err := os.WriteFile(text, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(text); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("LoadKey of a file without PEM: %v, want an error", err)
	}
	if _, err := LoadKey(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("LoadKey of a missing file succeeded, want an error")
	}
}

func TestLoadKeyRereadsChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	first, second := newKey(t, "ec"), newKey(t, "ec")
	writeKey(t, path, first, "")
	a, err := LoadKey(path)
	if err != nil || !samePublic(a, first) {
		t.Fatalf("LoadKey: %v", err)
	}
	if b, err := LoadKey(path); err != nil || b != a {
		t.Fatalf("LoadKey of an unchanged file: %v, want the key read before", err)
	}
	writeKey(t, path, second, "")
	if c, err := LoadKey(path); err != nil || !samePublic(c, second) {
		t.Fatalf("LoadKey of a changed file: %v, want the new key", err)
	}
}

func TestKeyPassphrase(t *testing.T) {
	resetKeys(t)
	forget := func() {
		keyPasswordMu.Lock()
		keyPassword = ""
		keyPasswordMu.Unlock()
	}
	dir := t.TempDir()
	file := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if _, err := KeyPassphrase(true); !errors.Is(err, ErrNoPassphrase) {
		t.Errorf("KeyPassphrase without a source: %v, want ErrNoPassphrase", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "env-pass")
	if pass, err := KeyPassphrase(false); err != nil || pass != "env-pass" {
		t.Errorf("KeyPassphrase of SIMPLE_CA_KEY_PASSWORD: %q, %v", pass, err)
	}
	forget()
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", file("both", "file-pass\n"))
	if _, err := KeyPassphrase(false); err == nil || !strings.Contains(err.Error(), "must not be set together") {
		t.Errorf("KeyPassphrase with both variables: %v, want an error", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	for content, want := range map[string]string{"file-pass\r\n": "file-pass", "file-pass\n": "file-pass",
		"file pass": "file pass", "two\nlines\n": "two\nlines"} {
		t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", file("pass", content))
		if pass, err := KeyPassphrase(false); err != nil || pass != want {
			t.Errorf("KeyPassphrase of a file of %q: %q, %v, want %q", content, pass, err, want)
		}
		forget()
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", file("empty", "\n"))
	if _, err := KeyPassphrase(false); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("KeyPassphrase of an empty file: %v, want an error", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", filepath.Join(dir, "missing"))
	if _, err := KeyPassphrase(false); err == nil || errors.Is(err, ErrNoPassphrase) {
		t.Errorf("KeyPassphrase of a missing file: %v, want a read error", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", "")

	// The prompt is asked with tty alone, and its passphrase is kept.
	var prompts []string
	answer, answerErr := []byte("typed"), error(nil)
	PromptPassphrase = func(prompt string) ([]byte, error) {
		prompts = append(prompts, prompt)
		return answer, answerErr
	}
	if _, err := KeyPassphrase(false); !errors.Is(err, ErrNoPassphrase) || len(prompts) != 0 {
		t.Errorf("KeyPassphrase without tty: %v, %d prompts, want ErrNoPassphrase and none", err, len(prompts))
	}
	if pass, err := KeyPassphrase(true); err != nil || pass != "typed" || len(prompts) != 1 ||
		prompts[0] != "Passphrase for private keys: " {
		t.Errorf("KeyPassphrase with tty: %q, %v, prompts %q", pass, err, prompts)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "other")
	if pass, err := KeyPassphrase(true); err != nil || pass != "typed" || len(prompts) != 1 {
		t.Errorf("KeyPassphrase after one was read: %q, %v, want the one read", pass, err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	forget()
	answer = nil
	if _, err := KeyPassphrase(true); err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("KeyPassphrase of an empty answer: %v, want an error", err)
	}
	answerErr = ErrNoPassphrase
	if _, err := KeyPassphrase(true); !errors.Is(err, ErrNoPassphrase) {
		t.Errorf("KeyPassphrase of a failed prompt: %v, want its error", err)
	}
}

func TestEncryptedKey(t *testing.T) {
	resetKeys(t)
	dir := t.TempDir()
	key := newKey(t, "ec")
	encrypted, plain := filepath.Join(dir, "encrypted.pem"), filepath.Join(dir, "plain.pem")
	writeKey(t, encrypted, key, "s3cr3t")
	writeKey(t, plain, key, "")
	if !KeyEncrypted(encrypted) || KeyEncrypted(plain) || KeyEncrypted(filepath.Join(dir, "missing.pem")) {
		t.Fatal("KeyEncrypted tells an encrypted key from the others wrong")
	}
	if _, err := LoadKey(encrypted); !errors.Is(err, ErrNoPassphrase) || !strings.Contains(err.Error(), "is encrypted") {
		t.Fatalf("LoadKey of an encrypted key without a passphrase: %v, want ErrNoPassphrase", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "wrong")
	if _, err := LoadKey(encrypted); err == nil {
		t.Fatal("LoadKey with a wrong passphrase succeeded, want an error")
	}
	resetKeys(t)
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "s3cr3t")
	if got, err := LoadKey(encrypted); err != nil || !samePublic(got, key) {
		t.Fatalf("LoadKey of an encrypted key: %v, want the key", err)
	}
}

func TestEncryptKeyDER(t *testing.T) {
	der, err := x509.MarshalPKCS8PrivateKey(newKey(t, "ec"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := EncryptKeyDER(der, "s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptKeyDER(der, "s3cr3t")
	if err != nil || bytes.Equal(a, b) {
		t.Fatalf("two encryptions of a key: %v, want them to differ by salt and IV", err)
	}

	// The key is PBES2 with PBKDF2, HMAC-SHA256, keyIterations and AES-256-CBC.
	var info encryptedPrivateKeyInfo
	var params pbes2Params
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(a, &info); err != nil || !info.Algorithm.Algorithm.Equal(oidPBES2) {
		t.Fatalf("EncryptedPrivateKeyInfo: %v, %v", info.Algorithm.Algorithm, err)
	}
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil ||
		!params.KDF.Algorithm.Equal(oidPBKDF2) || !params.Cipher.Algorithm.Equal(oidAES256CBC) {
		t.Fatalf("PBES2 parameters %+v, %v", params, err)
	}
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || kdf.Iterations != keyIterations ||
		len(kdf.Salt) != 16 || !kdf.PRF.Algorithm.Equal(oidHMACWithSHA256) {
		t.Fatalf("PBKDF2 parameters %+v, %v", kdf, err)
	}
	if got, err := decryptKeyDER(a, "s3cr3t"); err != nil || !bytes.Equal(got, der) {
		t.Fatalf("decryptKeyDER: %v, want the key encrypted", err)
	}
	if _, err := decryptKeyDER(a, "wrong"); err == nil {
		t.Fatal("decryptKeyDER with a wrong passphrase succeeded, want an error")
	}
}

// encryptPBES2 returns der encrypted with PBES2 of the PBKDF2 function prf, none for the default
// HMAC-SHA1, the AES-CBC cipher of keyLen bytes named by cipherOID, and iterations.
func encryptPBES2(t *testing.T, der []byte, pass string, prf asn1.ObjectIdentifier, cipherOID asn1.ObjectIdentifier,
	keyLen, iterations int) []byte {
	t.Helper()
	salt, iv := make([]byte, 8), make([]byte, aes.BlockSize)
	rand.Read(salt)
	rand.Read(iv)
	h := sha1.New
	params := pbkdf2Params{Salt: salt, Iterations: iterations}
	if prf != nil {
		h = sha256.New
		params.PRF = pkix.AlgorithmIdentifier{Algorithm: prf, Parameters: asn1.NullRawValue}
	}
	key, err := pbkdf2.Key(h, pass, salt, iterations, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	n := aes.BlockSize - len(der)%aes.BlockSize
	data := append(bytes.Clone(der), bytes.Repeat([]byte{byte(n)}, n)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	marshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pbes2 := marshal(pbes2Params{
		KDF:    pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: marshal(params)}},
		Cipher: pkix.AlgorithmIdentifier{Algorithm: cipherOID, Parameters: asn1.RawValue{FullBytes: marshal(iv)}}})
	return marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbes2}}, Data: data})
}

func TestDecryptKeyDERAlgorithms(t *testing.T) {
	der, err := x509.MarshalPKCS8PrivateKey(newKey(t, "ec"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		prf    asn1.ObjectIdentifier
		cipher asn1.ObjectIdentifier
		keyLen int
	}{
		{"HMAC-SHA1 AES-128", nil, oidAES128CBC, 16},
		{"HMAC-SHA256 AES-192", oidHMACWithSHA256, oidAES192CBC, 24},
		{"HMAC-SHA256 AES-256", oidHMACWithSHA256, oidAES256CBC, 32},
	} {
		got, err := decryptKeyDER(encryptPBES2(t, der, "s3cr3t", c.prf, c.cipher, c.keyLen, 2048), "s3cr3t")
		if err != nil || !bytes.Equal(got, der) {
			t.Errorf("decryptKeyDER of %s: %v, want the key", c.name, err)
		}
	}
	// The iteration count is raised over keyMaxIterations after the encryption.
	var info encryptedPrivateKeyInfo
	var params pbes2Params
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(encryptPBES2(t, der, "s3cr3t", oidHMACWithSHA256, oidAES256CBC, 32, 2048), &info); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		t.Fatal(err)
	}
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		t.Fatal(err)
	}
	kdf.Iterations = keyMaxIterations + 1
	kdfDER, err := asn1.Marshal(kdf)
	if err != nil {
		t.Fatal(err)
	}
	params.KDF.Parameters = asn1.RawValue{FullBytes: kdfDER}
	paramsDER, err := asn1.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	info.Algorithm.Parameters = asn1.RawValue{FullBytes: paramsDER}
	tooMany, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	desCBC := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	for name, enc := range map[string][]byte{
		"too many iterations": tooMany,
		"DES-CBC":             encryptPBES2(t, der, "s3cr3t", oidHMACWithSHA256, desCBC, 32, 2048),
		"an unknown PRF":      encryptPBES2(t, der, "s3cr3t", asn1.ObjectIdentifier{1, 2, 3, 4}, oidAES256CBC, 32, 2048),
		"not ASN.1":           {1, 2, 3},
		"a plain key":         der,
	} {
		if _, err := decryptKeyDER(enc, "s3cr3t"); err == nil {
			t.Errorf("decryptKeyDER of %s succeeded, want an error", name)
		}
	}
}

func TestReadKeyPassphrase(t *testing.T) {
	resetKeys(t)
	dir := t.TempDir()
	key := newKey(t, "ec")
	encrypted, plain := filepath.Join(dir, "encrypted.pem"), filepath.Join(dir, "plain.pem")
	writeKey(t, encrypted, key, "typed")
	writeKey(t, plain, key, "")
	prompts := 0
	PromptPassphrase = func(string) ([]byte, error) {
		prompts++
		return []byte("typed"), nil
	}
	if err := ReadKeyPassphrase(plain, filepath.Join(dir, "missing.pem")); err != nil || prompts != 0 {
		t.Fatalf("ReadKeyPassphrase of plain keys: %v, %d prompts, want none", err, prompts)
	}
	if err := ReadKeyPassphrase(plain, encrypted); err != nil || prompts != 1 {
		t.Fatalf("ReadKeyPassphrase of an encrypted key: %v, %d prompts, want one", err, prompts)
	}
	if got, err := LoadKey(encrypted); err != nil || !samePublic(got, key) || prompts != 1 {
		t.Fatalf("LoadKey after ReadKeyPassphrase: %v, %d prompts, want the key without a prompt", err, prompts)
	}
	resetKeys(t)
	PromptPassphrase = nil
	if err := ReadKeyPassphrase(encrypted); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("ReadKeyPassphrase without a prompt: %v, want ErrNoPassphrase", err)
	}
}

func TestEncryptedCAKey(t *testing.T) {
	resetKeys(t)
	PromptPassphrase = nil
	root := newRoot(t, "rsa")
	keyPath := filepath.Join(root.dir, "ca_key.pem")
	writeKey(t, keyPath, root.key, "ca-pass")
	if _, err := LoadKey(keyPath); !errors.Is(err, ErrNoPassphrase) {
		t.Fatalf("LoadKey of an encrypted CA key without a passphrase: %v, want ErrNoPassphrase", err)
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "ca-pass")
	got, err := LoadKey(keyPath)
	if err != nil || !samePublic(got, root.key) {
		t.Fatalf("LoadKey of the encrypted CA key with its passphrase: %v, want the CA key", err)
	}
}
