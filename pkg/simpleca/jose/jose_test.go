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

package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// testKeys returns an RSA and an ECDSA P-256 key, by the JWS algorithm of their JWTs.
func testKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"RS256": rsaKey, "ES256": ecKey}
}

func TestPublicJWKRoundTrip(t *testing.T) {
	for alg, key := range testKeys(t) {
		jwk := PublicJWK(key.Public())
		if jwk.Alg != alg || jwk.Use != "sig" || jwk.Kid == "" {
			t.Errorf("PublicJWK of the %s key: %+v, want alg %s, use sig and a key ID", alg, jwk, alg)
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			t.Fatal(err)
		}
		pub, thumbprint, err := ParseJWK(raw)
		if err != nil {
			t.Fatalf("ParseJWK of the %s JWK: %v", alg, err)
		}
		if !pub.(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Errorf("ParseJWK of the %s JWK returns another key", alg)
		}
		if thumbprint != jwk.Kid {
			t.Errorf("ParseJWK of the %s JWK: thumbprint %s, want the key ID %s", alg, thumbprint, jwk.Kid)
		}
	}
}

func TestParseJWKRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"an unknown key type":  `{"kty": "oct", "k": "c2VjcmV0"}`,
		"an unknown curve":     `{"kty": "EC", "crv": "P-192", "x": "AA", "y": "AA"}`,
		"short EC coordinates": `{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}`,
		"an RSA key without n": `{"kty": "RSA", "e": "AQAB"}`,
		"not JSON":             `kty`,
	} {
		if _, _, err := ParseJWK(json.RawMessage(raw)); err == nil {
			t.Errorf("ParseJWK of %s succeeded, want an error", name)
		}
	}
}

func TestSignJWTVerifyJWS(t *testing.T) {
	keys := testKeys(t)
	for alg, key := range keys {
		jwt, err := SignJWT(key, []byte(`{"sub":"test"}`))
		if err != nil {
			t.Fatalf("SignJWT with the %s key: %v", alg, err)
		}
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Fatalf("SignJWT with the %s key: %q is not a JWT", alg, jwt)
		}
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var h struct{ Alg, Kid, Typ string }
		if err := json.Unmarshal(header, &h); err != nil || h.Alg != alg || h.Kid != PublicJWK(key.Public()).Kid || h.Typ != "JWT" {
			t.Errorf("the header of the %s JWT: %s, %v", alg, header, err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		signed := []byte(parts[0] + "." + parts[1])
		if err := VerifyJWS(alg, key.Public(), signed, sig); err != nil {
			t.Errorf("VerifyJWS of the %s JWT: %v", alg, err)
		}

		// A changed payload or signature is refused.
		tampered := []byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"other"}`)))
		if err := VerifyJWS(alg, key.Public(), tampered, sig); err == nil {
			t.Errorf("VerifyJWS of a changed %s payload succeeded, want an error", alg)
		}
		bad := append([]byte{}, sig...)
		bad[len(bad)-1] ^= 1
		if err := VerifyJWS(alg, key.Public(), signed, bad); err == nil {
			t.Errorf("VerifyJWS of a changed %s signature succeeded, want an error", alg)
		}
	}

	// The key of another algorithm and an unsupported algorithm are refused.
	if err := VerifyJWS("RS256", keys["ES256"].Public(), []byte("x"), []byte("y")); err == nil {
		t.Error("VerifyJWS RS256 with an EC key succeeded, want an error")
	}
	if err := VerifyJWS("ES256", keys["RS256"].Public(), []byte("x"), make([]byte, 64)); err == nil {
		t.Error("VerifyJWS ES256 with an RSA key succeeded, want an error")
	}
	for _, alg := range []string{"HS256", "none", ""} {
		if err := VerifyJWS(alg, keys["RS256"].Public(), []byte("x"), []byte("y")); !errors.Is(err, ErrUnsupportedAlg) {
			t.Errorf("VerifyJWS %q: %v, want ErrUnsupportedAlg", alg, err)
		}
	}
}
