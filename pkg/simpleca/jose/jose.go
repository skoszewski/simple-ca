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

// Package jose signs JWTs with the CA keys, and reads JSON Web Keys and verifies JSON Web
// Signatures.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// ErrUnsupportedAlg is the error of VerifyJWS for a JWS algorithm it does not verify.
var ErrUnsupportedAlg = errors.New("unsupported algorithm")

// JWK is the public key of a CA as a JSON Web Key of RFC 7517, without x5c and x5t: the modulus
// and the exponent of an RSA key, or the curve and the coordinates of an EC key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// PublicJWK returns the JWK of the RSA or ECDSA P-256 public key pub, its key ID the JWK
// thumbprint of RFC 7638, the SHA-256 of its required members in lexicographic order.
func PublicJWK(pub crypto.PublicKey) JWK {
	b64 := base64.RawURLEncoding.EncodeToString
	var k JWK
	var members string
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		bytes, _ := p.Bytes()
		k = JWK{Kty: "EC", Crv: "P-256", X: b64(bytes[1:33]), Y: b64(bytes[33:65])}
		members = `{"crv":"` + k.Crv + `","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case *rsa.PublicKey:
		k = JWK{Kty: "RSA", N: b64(p.N.Bytes()), E: b64(big.NewInt(int64(p.E)).Bytes())}
		members = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	}
	thumbprint := sha256.Sum256([]byte(members))
	k.Use, k.Alg, k.Kid = "sig", JWTAlg(pub), b64(thumbprint[:])
	return k
}

// SignJWT returns the JWT of the JSON claims signed with caKey, RS256 for an RSA key and ES256 for
// an ECDSA P-256 key, its header naming the key by its JWK thumbprint.
func SignJWT(caKey crypto.Signer, claims []byte) (string, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{JWTAlg(caKey.Public()), PublicJWK(caKey.Public()).Kid, "JWT"})
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := caKey.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		// An ES256 signature is r and s of 32 bytes each, not ASN.1 (RFC 7518 3.4).
		var r, s *big.Int
		if r, s, err = ecdsa.Sign(rand.Reader, k, digest[:]); err == nil {
			sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	default:
		err = errors.New("the CA key is not an RSA or ECDSA P-256 key")
	}
	if err != nil {
		return "", err
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// JWTAlg returns the JWS algorithm of the JWTs the key of pub signs: ES256 for an ECDSA key,
// RS256 for an RSA key.
func JWTAlg(pub crypto.PublicKey) string {
	if simpleca.KeyType(pub) == "ec" {
		return "ES256"
	}
	return "RS256"
}

// ParseJWK returns the public key of a JSON Web Key, RSA of at most 8192 bits, EC P-256, P-384 or
// P-521, or Ed25519, and its thumbprint of RFC 7638.
func ParseJWK(raw json.RawMessage) (crypto.PublicKey, string, error) {
	var k struct{ Kty, Crv, X, Y, N, E string }
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", err
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return b
	}
	var pub crypto.PublicKey
	var members string
	switch k.Kty {
	case "RSA":
		n, e := decode(k.N), decode(k.E)
		if len(n) == 0 || len(n) > 1024 || len(e) == 0 || len(e) > 4 {
			return nil, "", errors.New("invalid RSA key")
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		members = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "EC":
		curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
		curve, ok := curves[k.Crv]
		if !ok {
			return nil, "", fmt.Errorf("unsupported curve %q", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, y := decode(k.X), decode(k.Y)
		if len(x) != size || len(y) != size {
			return nil, "", errors.New("invalid EC key")
		}
		ecKey, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, "", err
		}
		pub = ecKey
		members = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "OKP":
		x := decode(k.X)
		if k.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
			return nil, "", errors.New("invalid or unsupported OKP key")
		}
		pub = ed25519.PublicKey(x)
		members = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, k.X)
	default:
		return nil, "", fmt.Errorf("unsupported key type %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(members))
	return pub, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// VerifyJWS checks the signature sig of signed by pub with the JWS algorithm alg.
func VerifyJWS(alg string, pub crypto.PublicKey, signed, sig []byte) error {
	verifyEC := func(curve elliptic.Curve, h crypto.Hash) error {
		k, ok := pub.(*ecdsa.PublicKey)
		size := (curve.Params().BitSize + 7) / 8
		if !ok || k.Curve != curve || len(sig) != 2*size {
			return errors.New("the key or the signature does not fit the algorithm")
		}
		d := h.New()
		d.Write(signed)
		if !ecdsa.Verify(k, d.Sum(nil), new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])) {
			return errors.New("invalid signature")
		}
		return nil
	}
	switch alg {
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("the key does not fit the algorithm")
		}
		h := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
	case "ES256":
		return verifyEC(elliptic.P256(), crypto.SHA256)
	case "ES384":
		return verifyEC(elliptic.P384(), crypto.SHA384)
	case "ES512":
		return verifyEC(elliptic.P521(), crypto.SHA512)
	case "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, signed, sig) {
			return errors.New("invalid signature")
		}
		return nil
	}
	return fmt.Errorf("%w %q", ErrUnsupportedAlg, alg)
}
