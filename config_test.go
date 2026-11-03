package main

import (
	"crypto/x509"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestConfigTypes(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", ""); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"types": {`+
		`"device": {"key_usage": ["digitalSignature"], "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]}, `+
		`"person": {"names": "user", "key_usage": ["digitalSignature", "keyEncipherment"], "ext_key_usage": []}, `+
		`"user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
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
		if _, err := makeCert(c.args[0], c.args[1:], caDir, "", c.certType, 365, nil, nil); err != nil {
			t.Fatalf("makeCert %s: %v", c.certType, err)
		}
		cert, err := loadCert(filepath.Join(caDir, c.file+"_cert.pem"))
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		if cert.KeyUsage != c.keyUsage || !slices.Equal(cert.ExtKeyUsage, c.ekus) || len(cert.UnknownExtKeyUsage) != c.oids {
			t.Fatalf("%s: key usage %b, EKUs %v, other EKUs %v", c.certType, cert.KeyUsage, cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
		}
	}
	if _, err := makeCert("x.example.com", nil, caDir, "", "printer", 365, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "device, none, person, server, user") {
		t.Fatalf("expected an unknown type error naming the types, got %v", err)
	}

	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if err := cfg.save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	saved, err := loadConfig(caDir)
	if err != nil {
		t.Fatalf("loadConfig after save: %v", err)
	}
	if p := saved.Types["person"].ExtKeyUsage; p == nil || len(*p) != 0 {
		t.Fatalf("the empty ext_key_usage of person did not survive a save: %v", p)
	}
	if saved.Types["user"].ExtKeyUsage != nil {
		t.Fatal("the ext_key_usage left out of user was written by a save")
	}

	for _, types := range []string{
		`{"types": {"Bad_Name": {"key_usage": ["digitalSignature"]}}}`,
		`{"types": {"device": {"names": "robot"}}}`,
		`{"types": {"device": {"key_usage": ["keyCertSign"]}}}`,
		`{"types": {"device": {"ext_key_usage": ["deviceAuth"]}}}`,
		`{"types": {"device": {"key_usages": ["digitalSignature"]}}}`,
		"types:\n  device:\n    key_usage: [digitalSignature]\n",
	} {
		if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(types), 0o644); err != nil {
			t.Fatalf("write %s: %v", configFile, err)
		}
		if _, err := makeCert("y.example.com", nil, caDir, "", "server", 365, nil, nil); err == nil {
			t.Fatalf("expected an error for\n%s", types)
		}
	}
}

func TestThemeConfig(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	css, err := themeConfig{Light: map[string]string{"head": "#7c2d12", "action": "oklch(0.55 0.2 40)"},
		Dark: map[string]string{"head": " darkred "}}.css("simple-ca.json")
	if err != nil || string(css) != ":root { --action: oklch(0.55 0.2 40); --head: #7c2d12; }\n"+
		`:root[data-theme="dark"] { --head: darkred; }`+"\n" {
		t.Errorf("css: %q, %v, want the variables of both themes", css, err)
	}
	if css, err := (themeConfig{}).css("simple-ca.json"); err != nil || css != "" {
		t.Errorf("css without colours: %q, %v, want none", css, err)
	}
	for _, theme := range []themeConfig{
		{Light: map[string]string{"header": "#123456"}},
		{Dark: map[string]string{"head": "red; } body { display: none"}},
		{Dark: map[string]string{"head": "url(x)"}},
	} {
		if _, err := theme.css("simple-ca.json"); err == nil {
			t.Errorf("css of %+v succeeded, want an error", theme)
		}
	}

	// theme.json of a CA directory holds the colours of that CA alone, none without it.
	dir := t.TempDir()
	if theme, err := loadTheme(dir); err != nil || theme.Light != nil || theme.Dark != nil {
		t.Errorf("loadTheme without theme.json: %+v, %v, want none", theme, err)
	}
	if css := pageTheme(dir); css != "" {
		t.Errorf("pageTheme without theme.json: %q, want none", css)
	}
	for _, c := range []struct{ file, want string }{
		{`{"light": {"head": "#7f1d1d"}}`, ":root { --head: #7f1d1d; }\n"},
		{`{"theme": {"light": {"head": "#7f1d1d"}}}`, ""},
		{`{"light": {"head": "not a colour"}}`, ""},
	} {
		if err := os.WriteFile(filepath.Join(dir, themeFile), []byte(c.file), 0o644); err != nil {
			t.Fatal(err)
		}
		if theme, err := loadTheme(dir); (err == nil) != (c.want != "") || (err == nil && theme.Light["head"] != "#7f1d1d") {
			t.Errorf("loadTheme of %s: %+v, %v, want the colours or an error", c.file, theme, err)
		}
		if css := pageTheme(dir); string(css) != c.want {
			t.Errorf("pageTheme of %s: %q, want %q", c.file, css, c.want)
		}
	}
}
