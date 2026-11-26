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

package secrets

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newCA writes the certificate of a CA to dir, self-signed for a root CA, else signed by parent,
// and returns the certificate and its key.
func newCA(t *testing.T, dir string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: dir},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "ca_cert.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return crt, key
}

func TestSecrets(t *testing.T) {
	root := t.TempDir()
	rootCert, rootKey := newCA(t, root, nil, nil)
	issuing := filepath.Join(root, "issuing-ca")
	newCA(t, issuing, rootCert, rootKey)
	client := netip.MustParseAddr("10.1.2.3")
	value := []byte("s3cret-value\n")

	code, err := Add(issuing, "db-password", value, time.Hour, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 19 || strings.Count(code, "-") != 3 {
		t.Fatalf("code %q is not XXXX-XXXX-XXXX-XXXX", code)
	}
	stored, err := os.ReadFile(filepath.Join(issuing, SecretsFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("s3cret")) || bytes.Contains(stored, []byte(code)) {
		t.Fatalf("%s holds the value or the code: %s", SecretsFile, stored)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Join(issuing, SecretsFile)); info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has the mode %v", SecretsFile, info.Mode().Perm())
		}
	}
	if _, err := Add(issuing, "db-password", value, time.Hour, nil, "admin"); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("a second secret of the same name: %v", err)
	}

	if _, _, _, err := Take(root, "AAAA-BBBB-CCCC-DDDD", client); !errors.Is(err, ErrUnknown) {
		t.Errorf("a wrong code: %v", err)
	}
	ca, name, got, err := Take(root, strings.ToLower(strings.ReplaceAll(code, "-", " ")), client)
	if err != nil || ca != "issuing-ca" || name != "db-password" || !bytes.Equal(got, value) {
		t.Fatalf("Take = %q %q %q %v", ca, name, got, err)
	}
	if _, _, _, err := Take(root, code, client); !errors.Is(err, ErrUnknown) {
		t.Errorf("a used code: %v", err)
	}

	limited, err := Add(root, "limited", value, time.Hour, []string{"192.168.0.0/16"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Take(root, limited, client); !errors.Is(err, ErrClient) || !strings.Contains(err.Error(), "10.1.2.3") {
		t.Errorf("a client outside the networks: %v", err)
	}
	if _, _, _, err := Take(root, limited, netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Errorf("a client in the networks: %v", err)
	}

	expiring, err := Add(root, "expiring", value, time.Second, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, _, _, err := Take(root, expiring, client); !errors.Is(err, ErrExpired) {
		t.Errorf("an expired code: %v", err)
	}
	if db, _ := Load(root); len(db.Secrets) != 0 {
		t.Errorf("the expired secret is kept: %v", db.Secrets)
	}

	revoked, err := Add(root, "revoked", value, time.Hour, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := Remove(root, "revoked"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Take(root, revoked, client); !errors.Is(err, ErrUnknown) {
		t.Errorf("a revoked secret: %v", err)
	}
	if err := Remove(root, "revoked"); err == nil {
		t.Error("removing a missing secret works")
	}
}

func TestSecretTampered(t *testing.T) {
	root := t.TempDir()
	newCA(t, root, nil, nil)
	code, err := Add(root, "moved", []byte("value"), time.Hour, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	db, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	db.Secrets["renamed"] = db.Secrets["moved"]
	delete(db.Secrets, "moved")
	if err := db.Save(root); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Take(root, code, netip.MustParseAddr("127.0.0.1")); err == nil || errors.Is(err, ErrUnknown) {
		t.Errorf("a secret under another name decrypts: %v", err)
	}
}

func TestAddLimits(t *testing.T) {
	root := t.TempDir()
	newCA(t, root, nil, nil)
	for _, tt := range []struct {
		name    string
		value   []byte
		valid   time.Duration
		clients []string
		want    string
	}{
		{"Bad_Name", []byte("v"), time.Hour, nil, "kebab-case"},
		{"empty", nil, time.Hour, nil, "empty"},
		{"large", make([]byte, MaxValue+1), time.Hour, nil, "larger"},
		{"short", []byte("v"), time.Millisecond, nil, "validity"},
		{"long", []byte("v"), MaxValid + time.Hour, nil, "validity"},
		{"network", []byte("v"), time.Hour, []string{"nowhere"}, "client"},
	} {
		if _, err := Add(root, tt.name, tt.value, tt.valid, tt.clients, ""); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
	if _, err := Add(root, "largest", make([]byte, MaxValue), MaxValid, nil, ""); err != nil {
		t.Errorf("the largest value and validity: %v", err)
	}
	if _, err := Add(t.TempDir(), "no-ca", []byte("v"), time.Hour, nil, ""); err == nil {
		t.Error("a secret of a directory without a CA is added")
	}
}
