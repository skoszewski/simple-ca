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

package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
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
		if der, err = simpleca.EncryptKeyDER(der, pass); err != nil {
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
	if err := os.WriteFile(filepath.Join(dir, simpleca.ConfigFile), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// samePublic reports whether the keys a and b have the same public key.
func samePublic(a, b crypto.Signer) bool {
	return a.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(b.Public())
}

// verifyJWT checks the signature of jwt with the key of the JSON Web Key Set jwks, and that its
// header names that key, and returns its header and claims.
func verifyJWT(t *testing.T, jwt string, jwks []byte) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", jwt)
	}
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("JWKS %s: %v, want one key", jwks, err)
	}
	k := set.Keys[0]
	b64 := func(s string) []byte {
		t.Helper()
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%q is not base64url: %v", s, err)
		}
		return b
	}
	var header, claims map[string]any
	if err := json.Unmarshal(b64(parts[0]), &header); err != nil {
		t.Fatalf("JWT header: %v", err)
	}
	if err := json.Unmarshal(b64(parts[1]), &claims); err != nil {
		t.Fatalf("JWT claims: %v", err)
	}
	if header["alg"] != k.Alg || header["kid"] != k.Kid || header["typ"] != "JWT" {
		t.Fatalf("JWT header %v, want alg %s, kid %s and typ JWT", header, k.Alg, k.Kid)
	}
	sig := b64(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	var err error
	switch k.Kty {
	case "RSA":
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(b64(k.N)), E: int(new(big.Int).SetBytes(b64(k.E)).Int64())}
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
	case "EC":
		pub, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, b64(k.X)...), b64(k.Y)...))
		if perr != nil {
			t.Fatalf("the EC JWK: %v", perr)
		}
		if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			err = errors.New("the ES256 signature does not verify")
		}
	default:
		t.Fatalf("JWK of kty %q", k.Kty)
	}
	if err != nil {
		t.Fatalf("the signature of the JWT: %v", err)
	}
	return header, claims
}
