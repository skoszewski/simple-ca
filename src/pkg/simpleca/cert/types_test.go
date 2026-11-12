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

package cert

import (
	"crypto/x509"
	"encoding/asn1"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestBuiltinCertTypes(t *testing.T) {
	types, err := Types(&simpleca.Config{Path: simpleca.ConfigFile})
	if err != nil || TypeNames(types) != "none, server, user" {
		t.Fatalf("built-in types %v, %v", TypeNames(types), err)
	}
	for name, want := range map[string]CertTypeDef{
		"server": {"server", []string{"digitalSignature", "keyEncipherment"}, []string{"serverAuth", "clientAuth"}},
		"user":   {"user", []string{"digitalSignature", "contentCommitment"}, []string{"clientAuth", "emailProtection", "codeSigning"}},
		"none":   {"server", nil, nil},
	} {
		got := types[name]
		if got.Names != want.Names || !slices.Equal(got.KeyUsage, want.KeyUsage) || !slices.Equal(got.ExtKeyUsage, want.ExtKeyUsage) {
			t.Errorf("built-in type %s = %+v, want %+v", name, got, want)
		}
	}
}

func TestConfigCertTypes(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, `{"types": {`+
		`"device": {"key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]}, `+
		`"person": {"names": "user", "key_usage": ["digitalSignature", "keyEncipherment"], "ext_key_usage": []}, `+
		`"user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}}}`)
	cfg, err := simpleca.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	types, err := Types(cfg)
	if err != nil {
		t.Fatalf("CertTypes: %v", err)
	}
	if names := TypeNames(types); names != "device, none, person, server, user" {
		t.Fatalf("TypeNames = %q, want the built-in types and those of the file", names)
	}
	for _, c := range []struct {
		certType string
		names    string
		keyUsage x509.KeyUsage
		ekus     []x509.ExtKeyUsage
		oids     int
	}{
		{"device", "server", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 1},
		{"person", "user", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil, 0},
		{"user", "user", x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning}, 0},
		{"server", "server", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 0},
	} {
		def := types[c.certType]
		keyUsage, ekus, oids, err := ParseUsages(def.KeyUsage, def.ExtKeyUsage)
		if err != nil || def.Names != c.names || keyUsage != c.keyUsage || !slices.Equal(ekus, c.ekus) || len(oids) != c.oids {
			t.Errorf("%s: names %s, key usage %b, EKUs %v, other EKUs %v, %v", c.certType, def.Names, keyUsage, ekus, oids, err)
		}
	}
	if def := builtinTypes["user"]; len(def.KeyUsage) != 2 {
		t.Errorf("the built-in type user was changed: %+v", def)
	}
}

func TestConfigCertTypesRefused(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ types, want string }{
		{`{"types": {"Bad_Name": {"key_usage": ["digitalSignature"]}}}`, "kebab-case"},
		{`{"types": {"device": {"names": "robot"}}}`, "names must be 'server' or 'user'"},
		{`{"types": {"device": {"key_usage": ["keyCertSign"]}}}`, "invalid key usage 'keyCertSign'"},
		{`{"types": {"device": {"ext_key_usage": ["deviceAuth"]}}}`, "invalid EKU 'deviceAuth'"},
	} {
		writeConfig(t, dir, c.types)
		cfg, err := simpleca.LoadConfig(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Types(cfg); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), cfg.Path) {
			t.Errorf("CertTypes of %s: %v, want an error with %q", c.types, err, c.want)
		}
	}
}

func TestParseUsages(t *testing.T) {
	keyUsage, ekus, oids, err := ParseUsages([]string{"DIGITALSIGNATURE", "cRLSign", "crlsign"},
		[]string{"serverauth", "ServerAuth", "1.3.6.1.4.1.99999.10", "1.3.6.1.4.1.99999.10", "OCSPSigning", "2.5.29.37.0"})
	if err != nil || keyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageCRLSign ||
		!slices.Equal(ekus, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning}) ||
		len(oids) != 2 || !oids[0].Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 10}) ||
		!oids[1].Equal(asn1.ObjectIdentifier{2, 5, 29, 37, 0}) {
		t.Fatalf("ParseUsages: %b %v %v %v, want the usages once each, in order", keyUsage, ekus, oids, err)
	}
	for _, u := range KeyUsageNames {
		_, _, _, err := ParseUsages([]string{u.Name}, nil)
		if (err == nil) == (u.Usage == x509.KeyUsageCertSign) {
			t.Errorf("ParseUsages of the key usage %s: %v", u.Name, err)
		}
	}
	for usage, name := range ExtKeyUsageNames {
		if _, ekus, _, err := ParseUsages(nil, []string{name}); err != nil || !slices.Equal(ekus, []x509.ExtKeyUsage{usage}) {
			t.Errorf("ParseUsages of the EKU %s: %v, %v", name, ekus, err)
		}
	}
	for _, c := range []struct{ kus, ekus []string }{
		{[]string{"keyCertSign"}, nil}, {[]string{"nosuch"}, nil}, {nil, []string{"deviceAuth"}}, {nil, []string{"1"}},
		{nil, []string{"1.2.x"}},
	} {
		if _, _, _, err := ParseUsages(c.kus, c.ekus); err == nil {
			t.Errorf("ParseUsages(%v, %v) succeeded, want an error", c.kus, c.ekus)
		}
	}
}

func TestConfigTypes(t *testing.T) {
	caDir := t.TempDir()

	if err := MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"types": {`+
		`"device": {"key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]}, `+
		`"person": {"names": "user", "key_usage": ["digitalSignature", "keyEncipherment"], "ext_key_usage": []}, `+
		`"user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", simpleca.ConfigFile, err)
	}

	for _, c := range []struct {
		certType string
		args     []string
		file     string
		keyUsage x509.KeyUsage
		ekus     []x509.ExtKeyUsage
		oids     int
	}{
		{"device", []string{"dev1.example.com"}, "dev1", x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 1},
		{"person", []string{"Pat", "pat@example.com"}, "Pat", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil, 0},
		{"user", []string{"Una", "una@example.com"}, "Una",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning}, 0},
		{"server", []string{"web.example.com"}, "web", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, 0},
	} {
		if _, err := MakeCert(c.args[0], c.args[1:], caDir, "", c.certType, 365, nil, nil, ""); err != nil {
			t.Fatalf("makeCert %s: %v", c.certType, err)
		}
		crt, err := simpleca.LoadCert(filepath.Join(caDir, c.file+"_cert.pem"))
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		if crt.KeyUsage != c.keyUsage || !slices.Equal(crt.ExtKeyUsage, c.ekus) || len(crt.UnknownExtKeyUsage) != c.oids {
			t.Fatalf("%s: key usage %b, EKUs %v, other EKUs %v", c.certType, crt.KeyUsage, crt.ExtKeyUsage, crt.UnknownExtKeyUsage)
		}
	}
	if _, err := MakeCert("x.example.com", nil, caDir, "", "printer", 365, nil, nil, ""); err == nil ||
		!strings.Contains(err.Error(), "device, none, person, server, user") {
		t.Fatalf("expected an unknown type error naming the types, got %v", err)
	}

	for _, types := range []string{
		`{"types": {"Bad_Name": {"key_usage": ["digitalSignature"]}}}`,
		`{"types": {"device": {"names": "robot"}}}`,
		`{"types": {"device": {"key_usage": ["keyCertSign"]}}}`,
		`{"types": {"device": {"ext_key_usage": ["deviceAuth"]}}}`,
		`{"types": {"device": {"key_usages": ["digitalSignature"]}}}`,
		"types:\n  device:\n    key_usage: [digitalSignature]\n",
	} {
		if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(types), 0o644); err != nil {
			t.Fatalf("write %s: %v", simpleca.ConfigFile, err)
		}
		if _, err := MakeCert("y.example.com", nil, caDir, "", "server", 365, nil, nil, ""); err == nil {
			t.Fatalf("expected an error for\n%s", types)
		}
	}
}
