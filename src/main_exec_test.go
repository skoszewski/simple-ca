package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainExitCodes(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	for _, c := range []struct {
		name   string
		args   []string
		stdin  string
		code   int
		stderr string
	}{
		{"help", []string{"-h"}, "", 0, ""},
		{"usage", []string{"nosuch"}, "", 2, ""},
		{"error", []string{"ca", "show", "--ca-dir", empty}, "", 1, "ERROR: "},
		{"empty script", nil, "", 0, ""},
		{"script", nil, "# a comment\n\nexit\n", 0, ""},
		{"script with a wrong line", nil, "nosuch\n", 2, "line 1: invalid command line\n"},
		{"script with a failing line", nil, "\ncontext list\n", 1, "line 2: ERROR: "},
	} {
		cmd := exec.Command(exe, c.args...)
		cmd.Dir = empty
		cmd.Env = append(os.Environ(), "SIMPLE_CA_TEST_MAIN=1", "SIMPLE_CA_DIR=", "SIMPLE_CA_HISTORY=")
		cmd.Stdin = strings.NewReader(c.stdin)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if code != c.code || !strings.Contains(stderr.String(), c.stderr) {
			t.Errorf("%s: exit %d, stderr %q, want exit %d with %q", c.name, code, stderr.String(), c.code, c.stderr)
		}
	}
}
