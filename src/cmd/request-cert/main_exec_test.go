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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// mainArgs is the environment variable holding, as a JSON list, the arguments TestMainExit runs
// main with in a new process of the test binary.
const mainArgs = "SIMPLE_CA_TEST_MAIN_ARGS"

func TestMainExit(t *testing.T) {
	if v, ok := os.LookupEnv(mainArgs); ok {
		var args []string
		if err := json.Unmarshal([]byte(v), &args); err != nil {
			os.Exit(100)
		}
		os.Args = append([]string{"request-cert"}, args...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		os.Exit(0)
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args           []string
		env            []string
		code           int
		stdout, stderr string
	}{
		{[]string{"-version"}, nil, 0, "request-cert ", ""},
		{nil, nil, 2, "", "request-cert: CA_URL and CN are required\n"},
		{[]string{"pki.example.com", "web.example.com"}, nil, 1, "", "request-cert: CA_URL: "},
	} {
		b, _ := json.Marshal(c.args)
		cmd := exec.Command(program, "-test.run=^TestMainExit$")
		cmd.Dir = t.TempDir()
		cmd.Env = append(append(os.Environ(), c.env...), mainArgs+"="+string(b))
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		code := 0
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != c.code || !strings.Contains(out.String(), c.stdout) || !strings.Contains(errOut.String(), c.stderr) {
			t.Errorf("request-cert %q: exit %d, stdout %q, stderr %q; want exit %d, stdout with %q, stderr with %q",
				c.args, code, out.String(), errOut.String(), c.code, c.stdout, c.stderr)
		}
	}
}
