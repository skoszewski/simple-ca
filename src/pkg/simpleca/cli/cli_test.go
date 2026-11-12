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

package cli

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// setProgram sets Program and UsageLines for the test and restores them after it.
func setProgram(t *testing.T, program string, lines []string) {
	t.Helper()
	oldProgram, oldLines := Program, UsageLines
	t.Cleanup(func() { Program, UsageLines = oldProgram, oldLines })
	Program, UsageLines = program, lines
}

func TestRun(t *testing.T) {
	var ran string
	var got []string
	command := func(name string) func([]string) error {
		return func(args []string) error {
			ran, got = name, args
			return nil
		}
	}
	commands := []Command{
		{Name: "grp", Summary: "A group.", Sub: []Command{{Name: "cmd", Summary: "A command.", Run: command("grp cmd")}}},
		{Name: "solo", Summary: "A command outside a group.", Run: command("solo")},
	}
	for _, c := range []struct {
		args []string
		want error
		ran  string
		got  []string
	}{
		{nil, ErrUsage, "", nil},
		{[]string{"nosuch"}, ErrUsage, "", nil},
		{[]string{"grp"}, ErrUsage, "", nil},
		{[]string{"grp", "nosuch"}, ErrUsage, "", nil},
		{[]string{"-h"}, nil, "", nil},
		{[]string{"grp", "--help"}, nil, "", nil},
		{[]string{"grp", "cmd", "a", "b"}, nil, "grp cmd", []string{"a", "b"}},
		{[]string{"solo", "--x"}, nil, "solo", []string{"--x"}},
	} {
		ran, got = "", nil
		if err := Run(commands, c.args); !errors.Is(err, c.want) || ran != c.ran || !slices.Equal(got, c.got) {
			t.Errorf("Run %q: %v, ran %q with %q, want %v, %q with %q", c.args, err, ran, got, c.want, c.ran, c.got)
		}
	}

	// The groups of CertGroups alone have no token or serve.
	for _, args := range [][]string{{"token", "list"}, {"serve"}, {"audit", "list"}} {
		if err := Run(CertGroups(), args); !errors.Is(err, ErrUsage) {
			t.Errorf("Run %q with CertGroups: %v, want ErrUsage", args, err)
		}
	}
}

func TestPrintUsage(t *testing.T) {
	setProgram(t, "other-ca", nil)
	var b bytes.Buffer
	PrintUsage(&b, CertGroups(), nil)
	usage := b.String()
	if !strings.HasPrefix(usage, "Usage: other-ca GROUP COMMAND [options] [ARGS]\n\n") ||
		!strings.Contains(usage, `Run "other-ca GROUP -h"`) || strings.Contains(usage, "simple-ca") {
		t.Errorf("usage:\n%s\nwant the name other-ca alone", usage)
	}
	var listed []string
	_, list, _ := strings.Cut(usage, "Commands:\n")
	list, _, _ = strings.Cut(list, "\n\n")
	for _, line := range strings.Split(list, "\n") {
		listed = append(listed, strings.Fields(line)[0])
	}
	if !slices.Equal(listed, []string{"ca", "cert", "crl", "key"}) {
		t.Errorf("the usage lists %v, want the groups of CertGroups, ca, cert, crl and key", listed)
	}

	// The usage lines of the program follow the synopsis, and a group lists its commands.
	setProgram(t, "other-ca", []string{"other-ca --extra"})
	b.Reset()
	PrintUsage(&b, CertGroups(), nil)
	if !strings.HasPrefix(b.String(), "Usage: other-ca GROUP COMMAND [options] [ARGS]\n       other-ca --extra\n\n") {
		t.Errorf("usage with UsageLines:\n%s", b.String())
	}
	groups := CertGroups()
	b.Reset()
	PrintUsage(&b, groups, &groups[0])
	if !strings.HasPrefix(b.String(), "Usage: other-ca ca COMMAND [options] [ARGS]\n") ||
		!strings.Contains(b.String(), "  create ") || !strings.Contains(b.String(), "  show ") ||
		strings.Contains(b.String(), "--extra") {
		t.Errorf("usage of the group ca:\n%s", b.String())
	}
}

func TestResolveCADir(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	oldSession := SessionCADir
	t.Cleanup(func() { SessionCADir = oldSession })
	session := ""
	SessionCADir = func() string { return session }

	t.Setenv("SIMPLE_CA_DIR", "")
	if got, want := ResolveCADir(""), cwd; got != want {
		resolved, _ := filepath.EvalSymlinks(got)
		if wantResolved, _ := filepath.EvalSymlinks(want); resolved != wantResolved {
			t.Errorf("ResolveCADir without a value: %q, want the working directory %q", got, want)
		}
	}
	t.Setenv("SIMPLE_CA_DIR", "/env/ca")
	if got := ResolveCADir(""); got != "/env/ca" {
		t.Errorf("ResolveCADir with SIMPLE_CA_DIR: %q, want /env/ca", got)
	}
	session = "/session/ca"
	if got := ResolveCADir(""); got != "/session/ca" {
		t.Errorf("ResolveCADir in a session: %q, want /session/ca", got)
	}
	if got := ResolveCADir("/flag/ca"); got != "/flag/ca" {
		t.Errorf("ResolveCADir with --ca-dir: %q, want /flag/ca", got)
	}
	SessionCADir = nil
	if got := ResolveCADir(""); got != "/env/ca" {
		t.Errorf("ResolveCADir without sessions: %q, want /env/ca", got)
	}
}

func TestParseArgs(t *testing.T) {
	caDir := t.TempDir()
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("MakeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatalf("MakeCA servers: %v", err)
	}
	cfg, err := simpleca.LoadConfig(caDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetContextValues("", map[string][]string{"days": {"30"}, "name": {"root"}})
	cfg.SetContextValues("servers", map[string][]string{"days": {"7"}})
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	// newSet returns a flag set with --ca-dir, --days and --name.
	newSet := func() (*flag.FlagSet, *int, *string) {
		fs := NewFlagSet("test", "[ARG]", "A test command.")
		fs.SetOutput(io.Discard)
		fs.String("ca-dir", "", "")
		return fs, fs.Int("days", 1, ""), fs.String("name", "", "")
	}

	fs, days, name := newSet()
	args, given, err := ParseArgs(fs, []string{"--ca-dir", caDir, "arg"}, 0, 1)
	if err != nil || *days != 30 || *name != "root" || !slices.Equal(args, []string{"arg"}) || !given["days"] || !given["name"] {
		t.Errorf("ParseArgs of the root CA: %v, days %d, name %q, args %q, given %v, want the context values", err, *days, *name, args, given)
	}
	fs, days, _ = newSet()
	if _, _, err := ParseArgs(fs, []string{"--ca-dir", caDir, "--days", "90"}, 0, 1); err != nil || *days != 90 {
		t.Errorf("ParseArgs with --days: %v, days %d, want the value given", err, *days)
	}
	fs, days, name = newSet()
	if _, _, err := ParseArgs(fs, []string{"--ca-dir", filepath.Join(caDir, "servers")}, 0, 1); err != nil || *days != 7 || *name != "" {
		t.Errorf("ParseArgs of the issuing CA: %v, days %d, name %q, want its context alone", err, *days, *name)
	}
	fs, days, _ = newSet()
	if _, _, err := ParseArgs(fs, []string{"--ca-dir", t.TempDir()}, 0, 1); err != nil || *days != 1 {
		t.Errorf("ParseArgs outside a CA: %v, days %d, want the default", err, *days)
	}

	// The number of arguments, an unknown option and -h are checked.
	for _, c := range []struct {
		args []string
		want error
	}{
		{[]string{"--ca-dir", caDir, "a", "b"}, ErrUsage},
		{[]string{"--nosuch"}, ErrUsage},
		{[]string{"-h"}, flag.ErrHelp},
	} {
		fs, _, _ := newSet()
		if _, _, err := ParseArgs(fs, c.args, 0, 1); !errors.Is(err, c.want) {
			t.Errorf("ParseArgs %q: %v, want %v", c.args, err, c.want)
		}
	}
}
