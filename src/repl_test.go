package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"golang.org/x/term"
)

// newHierarchy makes a root CA with the issuing CA servers in a new directory, and returns it with
// the session reset when the test ends.
func newHierarchy(t *testing.T) string {
	t.Helper()
	caDir := t.TempDir()
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatal(err)
	}
	if err := cert.MakeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessionRoot, sessionCA = "", "" })
	return caDir
}

// startSession makes the commands take the args of a session until the test ends, and restores
// the working directory then.
func startSession(t *testing.T) {
	t.Helper()
	cli.Session = true
	t.Cleanup(func() { cli.Session = false })
	t.Chdir(".")
}

// runText runs a line of the session.
func runText(line string) error {
	args, err := lineArgs(line)
	if err != nil {
		return err
	}
	return runLine(args)
}

// sameDir fails the test unless the working directory is dir.
func sameDir(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	a, errA := os.Stat(wd)
	b, errB := os.Stat(dir)
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		t.Fatalf("working directory = %s, want %s", wd, dir)
	}
}

func TestLineArgs(t *testing.T) {
	for _, c := range []struct {
		line string
		want []string
	}{
		{"", nil},
		{"  ca   show ", []string{"ca", "show"}},
		{"simple-ca ca show", []string{"ca", "show"}},
		{"help", []string{"help"}},
		{"exit", []string{"exit"}},
		{"cert", []string{"cert"}},
		{"cert help", []string{"cert", "help"}},
		{"cert pfx help", []string{"cert", "pfx", "-h"}},
		{`ca create "My Root CA"`, []string{"ca", "create", "--", "My Root CA"}},
		{`cert create web.example.com days=30 san=a san='b c'`,
			[]string{"cert", "create", "--days=30", "--san=a", "--san=b c", "--", "web.example.com"}},
		{`context set otc-valid=1h`, []string{"context", "set", "--otc-valid=1h", "--"}},
		{`context delete domain`, []string{"context", "delete", "--", "domain"}},
	} {
		got, err := lineArgs(c.line)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("lineArgs(%q) = %q, %v; want %q", c.line, got, err, c.want)
		}
	}
	for _, line := range []string{`a "b`, `cert create days = 30`, `cert create --days 30 web`,
		`cert days=30 create`, `days=30`} {
		if got, err := lineArgs(line); err == nil {
			t.Errorf("lineArgs(%q) = %q, want an error", line, got)
		}
	}
}

func TestSessionStart(t *testing.T) {
	startSession(t)
	caDir := newHierarchy(t)
	root, err := filepath.Abs(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := placeCA(caDir); err != nil || sessionRoot != root || sessionCA != "" || prompt() != "simple-ca:root> " {
		t.Fatalf("root CA: %v, %q %q %q", err, sessionRoot, sessionCA, prompt())
	}
	sameDir(t, caDir)
	if err := placeCA(filepath.Join(caDir, "servers")); err != nil || sessionRoot != root || sessionCA != "servers" ||
		prompt() != "simple-ca:servers> " {
		t.Fatalf("issuing CA: %v, %q %q %q", err, sessionRoot, sessionCA, prompt())
	}
	sameDir(t, filepath.Join(caDir, "servers"))
	if got := cli.ResolveCADir(""); got != filepath.Join(root, "servers") {
		t.Fatalf("resolveCADir of the session = %s", got)
	}
	if got := cli.ResolveCADir("/other"); got != "/other" {
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

	// Outside a CA, the session has no hierarchy until ca create makes the root CA in the working
	// directory.
	empty := t.TempDir()
	if err := placeCA(empty); err == nil || prompt() != "simple-ca> " {
		t.Fatalf("outside a CA: %v, %q", err, prompt())
	}
	t.Chdir(empty)
	if err := runText(`ca create ca-dir=x "Lab Root"`); err == nil {
		t.Fatal("ca create took ca-dir")
	}
	if err := runText(`ca create "Lab Root"`); err != nil {
		t.Fatal(err)
	}
	if err := runText("ca show"); err != nil || sessionCA != "" || prompt() != "simple-ca:root> " {
		t.Fatalf("after ca create: %v, %q", err, prompt())
	}
	sameDir(t, empty)
}

func TestRunScript(t *testing.T) {
	startSession(t)
	caDir := newHierarchy(t)
	if err := placeCA(caDir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		script string
		want   error
	}{
		{"# a comment\n\n  ca show\nsimple-ca cert list\n", nil},
		{"ca show\nnosuch\nca show\n", cli.ErrUsage},
		{"ca show\nserve\n", errReported},
		{"simple-ca serve --port 8080\n", errReported},
		{"exit\nnosuch\n", nil},
		{"ca create \"unclosed\n", errReported},
		{"context use servers\ncert create web.example.com days=30\n", nil},
		{"cert pfx web_cert.pem password=secret\n", nil},
		{"cert pfx web_cert.pem nosuch=1\n", cli.ErrUsage},
		{"cert create other.example.com ca-dir=.\n", errReported},
		{"cert create other.example.com days = 30\n", errReported},
		{"cert create other.example.com -days 30\n", errReported},
		{"cert pfx help\n", nil},
	} {
		if err := runScript(strings.NewReader(c.script)); !errors.Is(err, c.want) {
			t.Errorf("runScript(%q) = %v, want %v", c.script, err, c.want)
		}
	}
	if !simpleca.FileExists(filepath.Join(caDir, "servers", "web_cert.pem")) {
		t.Fatal("cert create of the script did not issue from the issuing CA servers")
	}
	if !simpleca.FileExists(filepath.Join(caDir, "servers", "web.pfx")) {
		t.Fatal("cert pfx of a relative CERT_PATH did not find it in the issuing CA servers")
	}
	if simpleca.FileExists(filepath.Join(caDir, "servers", "other_cert.pem")) {
		t.Fatal("a refused cert create issued a certificate")
	}
	if err := run([]string{"context", "list"}); !errors.Is(err, cli.ErrUsage) {
		t.Fatalf("context on the command line = %v, want errUsage", err)
	}
}

func TestContextCommands(t *testing.T) {
	startSession(t)
	caDir := newHierarchy(t)
	if err := placeCA(caDir); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		line string
		ok   bool
	}{
		{"context list", true},
		{"context set otc-valid=1h", true},
		{"context set ca-dir=x", false},
		{"context set Bad_Name=x", false},
		{"context set otc-valid 1h", false},
		{"context set", false},
		{"context use nosuch", false},
		{"context use servers", true},
		{"context add domain=a.example domain=b.example", true},
		{"context add domain=c.example", true},
		{"context delete domain=b.example", true},
		{"context delete domain=nosuch.example", false},
		{"context set days=30 san=a san='b c'", true},
		{"context set san=d", true},
		{"context delete days san", true},
		{"context delete days", false},
		{"context show", true},
	} {
		if err := runText(c.line); (err == nil) != c.ok {
			t.Fatalf("%q: %v", c.line, err)
		}
	}
	if sessionCA != "servers" {
		t.Fatalf("an unknown issuing CA changed the context to %q", sessionCA)
	}
	sameDir(t, filepath.Join(caDir, "servers"))
	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ContextValues(""); !slices.Equal(got["otc_valid"], []string{"1h"}) || len(got) != 1 {
		t.Fatalf("values of the root CA = %v", got)
	}
	if got := cfg.ContextValues("servers"); !slices.Equal(got["domain"], []string{"a.example", "c.example"}) || len(got) != 1 {
		t.Fatalf("values of servers = %v", got)
	}
	b, err := os.ReadFile(filepath.Join(caDir, simpleca.ConfigFile))
	if err != nil || !strings.Contains(string(b), `"otc_valid"`) || !strings.Contains(string(b), `"cas"`) {
		t.Fatalf("simple-ca.json: %v\n%s", err, b)
	}

	// context use DIR moves to the CA in DIR, here the root CA of the same hierarchy, and context
	// use without an argument to the root CA.
	if err := runText("context use " + caDir); err != nil || sessionCA != "" {
		t.Fatalf("context use DIR: %v, %q", err, sessionCA)
	}
	sameDir(t, caDir)
	if err := runText("context use servers"); err != nil || sessionCA != "servers" {
		t.Fatalf("context use servers: %v, %q", err, sessionCA)
	}
	if err := runText("context use"); err != nil || sessionCA != "" {
		t.Fatalf("context use: %v, %q", err, sessionCA)
	}
	sameDir(t, caDir)
	if err := runText("context use ca-dir=" + caDir); err == nil {
		t.Fatal("context use took ca-dir")
	}
}

func TestContextValues(t *testing.T) {
	caDir := newHierarchy(t)
	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetContextValues("", map[string][]string{"valid": {"45d"}, "domain": {"a.example", "b.example"},
		"days": {"x"}})
	cfg.SetContextValues("servers", map[string][]string{"valid": {"8h"}})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// newSet returns a flag set with --ca-dir, --valid and a repeated --domain.
	newSet := func() (*flag.FlagSet, *time.Duration, *[]string) {
		fs := cli.NewFlagSet("test", "", "test")
		fs.String("ca-dir", "", "")
		valid := cli.DurationVar(fs, "valid", time.Hour, "")
		var domains []string
		fs.Func("domain", "", func(s string) error { domains = append(domains, s); return nil })
		return fs, valid, &domains
	}

	fs, valid, domains := newSet()
	_, given, err := cli.ParseArgs(fs, []string{"--ca-dir", caDir}, 0, 0)
	if err != nil || *valid != 45*24*time.Hour || !slices.Equal(*domains, []string{"a.example", "b.example"}) ||
		!given["valid"] || !given["domain"] {
		t.Fatalf("root CA: %v, %v %v %v", err, *valid, *domains, given)
	}

	fs, valid, _ = newSet()
	if _, _, err := cli.ParseArgs(fs, []string{"--ca-dir", caDir, "--valid", "2h"}, 0, 0); err != nil || *valid != 2*time.Hour {
		t.Fatalf("an option on the line: %v, %v", err, *valid)
	}

	fs, valid, domains = newSet()
	if _, _, err := cli.ParseArgs(fs, []string{"--ca-dir", filepath.Join(caDir, "servers")}, 0, 0); err != nil ||
		*valid != 8*time.Hour || len(*domains) != 0 {
		t.Fatalf("issuing CA: %v, %v %v", err, *valid, *domains)
	}

	// A value the option refuses fails the command.
	fs = cli.NewFlagSet("test", "", "test")
	fs.String("ca-dir", "", "")
	fs.Int("days", 1, "")
	if _, _, err := cli.ParseArgs(fs, []string{"--ca-dir", caDir}, 0, 0); err == nil || !strings.Contains(err.Error(), `"days"`) {
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

func TestComplete(t *testing.T) {
	startSession(t)
	var out bytes.Buffer
	tm := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{strings.NewReader(""), &out}, "")
	completes := func(line string, pos int, want string) {
		t.Helper()
		out.Reset()
		got, gotPos, ok := complete(tm, line, pos)
		if want == "" {
			if ok {
				t.Errorf("complete %q: %q, want nothing", line, got)
			}
			return
		}
		if !ok || got != want || gotPos != len(want)-len(line)+pos {
			t.Errorf("complete %q at %d: %q at %d, %v, want %q", line, pos, got, gotPos, ok, want)
		}
	}
	lists := func(line string, want ...string) {
		t.Helper()
		out.Reset()
		if _, _, ok := complete(tm, line, len(line)); ok {
			t.Errorf("complete %q completed, want the candidates listed", line)
		}
		for _, w := range want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("complete %q listed %q, want %q in it", line, out.String(), w)
			}
		}
	}

	lists("", "audit", "cert", "context", "token", "help", "exit", "quit")
	lists("c", "ca  cert  context  crl")
	completes("ce", 2, "cert ")
	completes("cert cr", 7, "cert create ")
	completes("cert cr x.pem", 7, "cert create  x.pem")
	completes("token r", 7, "token re")
	lists("token re", "renew  revoke")
	completes("nosuch x", 8, "")
	completes("context use ", 12, "")

	caDir := newHierarchy(t)
	if err := placeCA(caDir); err != nil {
		t.Fatal(err)
	}
	completes("context use ", 12, "context use servers ")
	completes("context set ", 12, "")
	if err := runText("context set otc-valid=1h"); err != nil {
		t.Fatal(err)
	}
	completes("context set ", 12, "context set otc-valid=")
	completes("context add o", 13, "context add otc-valid=")
	completes("context delete ", 15, "context delete otc-valid ")
}

func TestRunREPLScript(t *testing.T) {
	t.Chdir(".")
	caDir := newHierarchy(t)
	t.Setenv("SIMPLE_CA_DIR", "")
	stdin, input := os.Stdin, cli.Input
	t.Cleanup(func() { os.Stdin, cli.Input, cli.Session = stdin, input, false })
	for _, c := range []struct {
		script string
		want   error
	}{
		{"context use servers\ncontext list\nexit\nnosuch\n", nil},
		{"context use nosuch\n", errReported},
	} {
		script := filepath.Join(t.TempDir(), "script")
		if err := os.WriteFile(script, []byte(c.script), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(script)
		if err != nil {
			t.Fatal(err)
		}
		os.Chdir(caDir)
		os.Stdin = f
		err = runREPL()
		f.Close()
		if !errors.Is(err, c.want) || !cli.Session {
			t.Errorf("runREPL of %q: %v, session %v, want %v in a session", c.script, err, cli.Session, c.want)
		}
	}
	if sessionRoot == "" {
		t.Error("runREPL in a CA directory has no CA in its session")
	}
}

func TestHistoryPath(t *testing.T) {
	t.Setenv("SIMPLE_CA_HISTORY", "/srv/history")
	if got := historyPath(); got != "/srv/history" {
		t.Errorf("historyPath of SIMPLE_CA_HISTORY: %q", got)
	}
	t.Setenv("SIMPLE_CA_HISTORY", "")
	if runtime.GOOS == "windows" {
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := historyPath(); got != filepath.Join(home, ".simple-ca_history") {
		t.Errorf("historyPath of HOME: %q", got)
	}
	t.Setenv("HOME", "")
	if got := historyPath(); got != "" {
		t.Errorf("historyPath without a home directory: %q, want none", got)
	}
	if h := loadHistory(); h.path != "" || h.Len() != 0 {
		t.Errorf("history without a home directory: %q %q, want none kept", h.path, h.entries)
	}
}

func TestHistoryWarning(t *testing.T) {
	t.Setenv("SIMPLE_CA_HISTORY", t.TempDir())
	stderr := srvCaptureStderr(t)
	h := loadHistory()
	if h.path != "" {
		t.Errorf("history path %q of a directory, want none", h.path)
	}
	h.Add("ca show")
	if h.Len() != 1 {
		t.Errorf("history %q, want the line kept in memory", h.entries)
	}
	srvWaitFor(t, stderr, "warning: history: ", "; the history of this session is not kept\n")
}
