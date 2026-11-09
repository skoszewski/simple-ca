package main

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestIndex(t *testing.T) {
	caDir := t.TempDir()

	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Issuing CA", 0, "issuing-ca", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := makeCert("test", nil, filepath.Join(caDir, "issuing-ca"), "", "server", 365, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	if fileExists(filepath.Join(caDir, configFile)) {
		t.Fatalf("%s written without settings", configFile)
	}

	for _, c := range []struct{ dir, cert, subject string }{
		{caDir, filepath.Join(caDir, "issuing-ca", "ca_cert.pem"), "/CN=Issuing CA"},
		{filepath.Join(caDir, "issuing-ca"), filepath.Join(caDir, "issuing-ca", "test_cert.pem"), "/CN=test"},
	} {
		out, err := exec.Command("openssl", "x509", "-in", c.cert, "-noout", "-serial").Output()
		if err != nil {
			t.Fatalf("openssl x509 -serial: %v", err)
		}
		opensslSerial := strings.TrimPrefix(strings.TrimSpace(string(out)), "serial=")
		cert, err := loadCert(c.cert)
		if err != nil {
			t.Fatalf("loadCert: %v", err)
		}
		want := []indexEntry{{"V", cert.NotAfter.UTC().Format(utcTimeFormat), "", opensslSerial, "unknown", c.subject}}
		entries, err := readIndex(c.dir)
		if err != nil {
			t.Fatalf("readIndex: %v", err)
		}
		if !slices.Equal(entries, want) {
			t.Fatalf("index of %s is %+v, want %+v", c.dir, entries, want)
		}
	}
}

func TestEntryStatus(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		entry indexEntry
		want  string
	}{
		{indexEntry{status: "V", expires: "261030120001Z"}, "valid"},
		{indexEntry{status: "V", expires: "261030120000Z"}, "expired"},
		{indexEntry{status: "V", expires: "20501030120000Z"}, "valid"},
		{indexEntry{status: "E", expires: "271030120000Z"}, "expired"},
		{indexEntry{status: "R", expires: "271030120000Z", revoked: "261029120000Z"}, "revoked"},
	} {
		got, err := entryStatus(c.entry, now)
		if err != nil {
			t.Fatalf("entryStatus %+v: %v", c.entry, err)
		}
		if got != c.want {
			t.Fatalf("entryStatus %+v = %q, want %q", c.entry, got, c.want)
		}
	}
}
