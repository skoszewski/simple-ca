package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// newHierarchy makes a root CA with the issuing CA servers in a new directory, and returns it with
// the session reset when the test ends.
func newHierarchy(t *testing.T) string {
	t.Helper()
	caDir := t.TempDir()
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatal(err)
	}
	if err := makeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessionRoot, sessionCA = "", "" })
	return caDir
}

func TestSplitLine(t *testing.T) {
	for _, c := range []struct {
		line string
		want []string
	}{
		{"", nil},
		{"  ca   show ", []string{"ca", "show"}},
		{`ca create "My Root CA"`, []string{"ca", "create", "My Root CA"}},
		{`ca create 'My "Root" CA'`, []string{"ca", "create", `My "Root" CA`}},
		{`a "b \"c\" \\ d"`, []string{"a", `b "c" \ d`}},
		{`a My\ CA`, []string{"a", "My CA"}},
		{`a "" ''`, []string{"a", "", ""}},
		{`a"b"'c'`, []string{"abc"}},
	} {
		got, err := splitLine(c.line)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("splitLine(%q) = %q, %v; want %q", c.line, got, err, c.want)
		}
	}
	for _, line := range []string{`a "b`, `a 'b`, `a b\`} {
		if _, err := splitLine(line); err == nil {
			t.Errorf("splitLine(%q) gave no error", line)
		}
	}
}

func TestSessionStart(t *testing.T) {
	caDir := newHierarchy(t)
	root, err := filepath.Abs(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := placeCA(caDir); err != nil || sessionRoot != root || sessionCA != "" || prompt() != "simple-ca:root> " {
		t.Fatalf("root CA: %v, %q %q %q", err, sessionRoot, sessionCA, prompt())
	}
	if err := placeCA(filepath.Join(caDir, "servers")); err != nil || sessionRoot != root || sessionCA != "servers" ||
		prompt() != "simple-ca:servers> " {
		t.Fatalf("issuing CA: %v, %q %q %q", err, sessionRoot, sessionCA, prompt())
	}
	if got := resolveCADir(""); got != filepath.Join(root, "servers") {
		t.Fatalf("resolveCADir of the session = %s", got)
	}
	if got := resolveCADir("/other"); got != "/other" {
		t.Fatalf("resolveCADir with --ca-dir = %s", got)
	}

	// A copy of a CA certificate alone is not a CA.
	sessionRoot, sessionCA = "", ""
	copied := t.TempDir()
	b, err := os.ReadFile(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "ca_cert.pem"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := placeCA(copied); err == nil || sessionRoot != "" || prompt() != "simple-ca> " {
		t.Fatalf("a copied ca_cert.pem: %v, %q", err, prompt())
	}

	// Outside a CA, the session has no hierarchy until ca create makes the root CA.
	empty := t.TempDir()
	if err := placeCA(empty); err == nil || prompt() != "simple-ca> " {
		t.Fatalf("outside a CA: %v, %q", err, prompt())
	}
	if err := runLine([]string{"ca", "create", "--ca-dir", empty, "Lab Root"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIMPLE_CA_DIR", empty)
	if err := runLine([]string{"ca", "show"}); err != nil || sessionCA != "" || prompt() != "simple-ca:root> " {
		t.Fatalf("after ca create: %v, %q", err, prompt())
	}
}

func TestRunScript(t *testing.T) {
	caDir := newHierarchy(t)
	if err := placeCA(caDir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		script string
		want   error
	}{
		{"# a comment\n\n  ca show\nsimple-ca cert list\n", nil},
		{"ca show\nnosuch\nca show\n", errUsage},
		{"ca show\nserve\n", errReported},
		{"simple-ca serve --port 8080\n", errReported},
		{"exit\nnosuch\n", nil},
		{"ca create \"unclosed\n", errReported},
		{"context use servers\ncert create web.example.com\n", nil},
	} {
		if err := runScript(strings.NewReader(c.script)); !errors.Is(err, c.want) {
			t.Errorf("runScript(%q) = %v, want %v", c.script, err, c.want)
		}
	}
	if !fileExists(filepath.Join(caDir, "servers", "web_cert.pem")) {
		t.Fatal("cert create of the script did not issue from the issuing CA servers")
	}
	if err := run([]string{"context", "list"}); !errors.Is(err, errUsage) {
		t.Fatalf("context on the command line = %v, want errUsage", err)
	}
}

func TestContextCommands(t *testing.T) {
	caDir := newHierarchy(t)
	if err := placeCA(caDir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"context", "list"}, true},
		{[]string{"context", "set", "otc-valid", "1h"}, true},
		{[]string{"context", "set", "ca-dir", "x"}, false},
		{[]string{"context", "set", "Bad_Name", "x"}, false},
		{[]string{"context", "use", "nosuch"}, false},
		{[]string{"context", "use", "servers"}, true},
		{[]string{"context", "add", "domain", "a.example", "b.example"}, true},
		{[]string{"context", "add", "domain", "c.example"}, true},
		{[]string{"context", "delete", "domain", "b.example"}, true},
		{[]string{"context", "delete", "domain", "nosuch.example"}, false},
		{[]string{"context", "set", "days", "30"}, true},
		{[]string{"context", "delete", "days"}, true},
		{[]string{"context", "delete", "days"}, false},
		{[]string{"context", "show"}, true},
	} {
		if err := runLine(c.args); (err == nil) != c.ok {
			t.Fatalf("%q: %v", c.args, err)
		}
	}
	if sessionCA != "servers" {
		t.Fatalf("an unknown issuing CA changed the context to %q", sessionCA)
	}
	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.contextValues(""); !slices.Equal(got["otc_valid"], []string{"1h"}) || len(got) != 1 {
		t.Fatalf("values of the root CA = %v", got)
	}
	if got := cfg.contextValues("servers"); !slices.Equal(got["domain"], []string{"a.example", "c.example"}) || len(got) != 1 {
		t.Fatalf("values of servers = %v", got)
	}
	b, err := os.ReadFile(filepath.Join(caDir, configFile))
	if err != nil || !strings.Contains(string(b), `"otc_valid"`) || !strings.Contains(string(b), `"cas"`) {
		t.Fatalf("simple-ca.json: %v\n%s", err, b)
	}

	// context use --ca-dir moves to the CA named, here the root CA of the same hierarchy.
	if err := runLine([]string{"context", "use", "--ca-dir", caDir}); err != nil || sessionCA != "" {
		t.Fatalf("context use --ca-dir: %v, %q", err, sessionCA)
	}
}

func TestContextValues(t *testing.T) {
	caDir := newHierarchy(t)
	cfg, err := loadConfig(caDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.setContextValues("", map[string][]string{"valid": {"45d"}, "domain": {"a.example", "b.example"},
		"days": {"x"}})
	cfg.setContextValues("servers", map[string][]string{"valid": {"8h"}})
	if err := cfg.save(); err != nil {
		t.Fatal(err)
	}

	// newSet returns a flag set with --ca-dir, --valid and a repeated --domain.
	newSet := func() (*flag.FlagSet, *time.Duration, *[]string) {
		fs := newFlagSet("test", "", "test")
		fs.String("ca-dir", "", "")
		valid := durationVar(fs, "valid", time.Hour, "")
		var domains []string
		fs.Func("domain", "", func(s string) error { domains = append(domains, s); return nil })
		return fs, valid, &domains
	}

	fs, valid, domains := newSet()
	_, given, err := parseArgs(fs, []string{"--ca-dir", caDir}, 0, 0)
	if err != nil || *valid != 45*24*time.Hour || !slices.Equal(*domains, []string{"a.example", "b.example"}) ||
		!given["valid"] || !given["domain"] {
		t.Fatalf("root CA: %v, %v %v %v", err, *valid, *domains, given)
	}

	fs, valid, _ = newSet()
	if _, _, err := parseArgs(fs, []string{"--ca-dir", caDir, "--valid", "2h"}, 0, 0); err != nil || *valid != 2*time.Hour {
		t.Fatalf("an option on the line: %v, %v", err, *valid)
	}

	fs, valid, domains = newSet()
	if _, _, err := parseArgs(fs, []string{"--ca-dir", filepath.Join(caDir, "servers")}, 0, 0); err != nil ||
		*valid != 8*time.Hour || len(*domains) != 0 {
		t.Fatalf("issuing CA: %v, %v %v", err, *valid, *domains)
	}

	// A value the option refuses fails the command.
	fs = newFlagSet("test", "", "test")
	fs.String("ca-dir", "", "")
	fs.Int("days", 1, "")
	if _, _, err := parseArgs(fs, []string{"--ca-dir", caDir}, 0, 0); err == nil || !strings.Contains(err.Error(), "'days'") {
		t.Fatalf("a refused value: %v", err)
	}
}

func TestFileHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	t.Setenv("SIMPLE_CA_HISTORY", path)
	h := loadHistory()
	for _, line := range []string{"ca show ", "", "ca show", "cert list"} {
		h.Add(line)
	}
	if h.Len() != 2 || h.At(0) != "cert list" || h.At(1) != "ca show" {
		t.Fatalf("history = %q", h.entries)
	}
	if h = loadHistory(); h.Len() != 2 || h.At(0) != "cert list" {
		t.Fatalf("history read again = %q", h.entries)
	}
	for i := range historyLimit + 10 {
		h.Add(strings.Repeat("x", i+1))
	}
	if h = loadHistory(); h.Len() != historyLimit {
		t.Fatalf("history of %d lines kept %d", historyLimit+12, h.Len())
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("history file: %v %v", err, info)
	}
}
