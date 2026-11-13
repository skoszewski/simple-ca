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

package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// runCaptured runs simple-ca-wif with args and returns what it printed on stdout and stderr, and
// its error.
func runCaptured(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut []byte
	var wg sync.WaitGroup
	wg.Go(func() { out, _ = io.ReadAll(outR) })
	wg.Go(func() { errOut, _ = io.ReadAll(errR) })
	savedArgs, savedOut, savedErr := os.Args, os.Stdout, os.Stderr
	os.Args, os.Stdout, os.Stderr = append([]string{"simple-ca-wif"}, args...), outW, errW
	err = run()
	os.Args, os.Stdout, os.Stderr = savedArgs, savedOut, savedErr
	outW.Close()
	errW.Close()
	wg.Wait()
	return string(out), string(errOut), err
}

func TestRun(t *testing.T) {
	usage := "Usage: simple-ca-wif google setup [options]\n"
	_, errOut, err := runCaptured(t)
	if !errors.Is(err, errUsage) || !strings.HasPrefix(errOut, usage) {
		t.Errorf("no arguments: %v, stderr %q, want the usage error and the usage", err, errOut)
	}
	for _, help := range []string{"help", "-h", "--help"} {
		out, _, err := runCaptured(t, help)
		if err != nil || !strings.HasPrefix(out, usage) || !strings.Contains(out, "\n  google setup ") ||
			!strings.Contains(out, "\n  google machine ") {
			t.Errorf("%s: %v, stdout %q, want the usage with the commands", help, err, out)
		}
	}
	if out, _, err := runCaptured(t, "--version"); err != nil || !strings.HasPrefix(out, "simple-ca-wif ") ||
		len(strings.TrimSpace(out)) == len("simple-ca-wif") {
		t.Errorf("--version: %v, %q, want the version", err, out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"aws"}, "simple-ca-wif: unknown cloud \"aws\"\n" + usage},
		{[]string{"google"}, usage},
		{[]string{"google", "nosuch"}, "simple-ca-wif: unknown command \"google nosuch\"\n" + usage},
	} {
		_, errOut, err := runCaptured(t, c.args...)
		if !errors.Is(err, errUsage) || !strings.HasPrefix(errOut, c.want) {
			t.Errorf("%q: %v, stderr %q, want the usage error and %q", c.args, err, errOut, c.want)
		}
	}

	// A command of a cloud takes the arguments after its name.
	_, caDir := newTestCA(t)
	g := newFakeGoogle(t)
	if _, _, err := runCaptured(t, "google", "setup", "--ca-dir", caDir, "--project", "lab-project", "--pool", "lab-pool",
		"--issuer", "https://pki.example.com"); err != nil {
		t.Fatal(err)
	}
	wantLines(t, g.out.String(), `project "lab-project": number "123456789"`)
	_, errOut, err = runCaptured(t, "google", "machine")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "Usage: simple-ca-wif google machine") {
		t.Errorf("google machine without NAME: %v, stderr %q", err, errOut)
	}
}

func TestPromptPassphraseWithoutTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	saved := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = saved }()
	if b, err := simpleca.PromptPassphrase("Passphrase: "); !errors.Is(err, simpleca.ErrNoPassphrase) || b != nil {
		t.Errorf("PromptPassphrase without a terminal: %q, %v, want ErrNoPassphrase", b, err)
	}
}
