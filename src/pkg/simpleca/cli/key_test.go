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
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// inChild runs the test name again in a new process of the test binary with the passphrase of
// the private keys in SIMPLE_CA_KEY_PASSWORD, and reports whether this is that process. The
// passphrase, once read, stays for the process, and the other tests write unencrypted keys.
func inChild(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("SIMPLE_CA_TEST_CHILD") == name {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "SIMPLE_CA_TEST_CHILD="+name, "SIMPLE_CA_KEY_PASSWORD=key-secret",
		"SIMPLE_CA_KEY_PASSWORD_FILE=")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+name) {
		t.Fatalf("%s in a new process: %v\n%s", name, err, out)
	}
	return false
}

// captureStdout returns what the command line args prints on stdout, and its error.
func captureStdout(t *testing.T, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	err = run(args)
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out), err
}

// keyTypes returns the type of the first PEM block of each file, by its path relative to dir.
func keyTypes(t *testing.T, dir string, files ...string) map[string]string {
	t.Helper()
	types := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("%s has no PEM block", f)
		}
		types[f] = block.Type
	}
	return types
}

func TestKeyCommands(t *testing.T) {
	if !inChild(t, "TestKeyCommands") {
		return
	}
	root := t.TempDir()
	if err := cert.MakeCA(root, "Test CA", 3650, "", "", "ec"); err != nil {
		t.Fatal(err)
	}
	if err := cert.MakeCA(root, "Servers CA", 0, "servers", "", "ec"); err != nil {
		t.Fatal(err)
	}
	servers := filepath.Join(root, "servers")
	if _, err := cert.MakeCert("web.example.com", nil, servers, servers, "server", 30, nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	files := []string{"ca_key.pem", filepath.Join("servers", "ca_key.pem"), filepath.Join("servers", "web_key.pem")}
	want := func(step string, types ...string) {
		t.Helper()
		got := keyTypes(t, root, files...)
		for i, f := range files {
			if got[f] != types[i] {
				t.Errorf("%s: %s is %q, want %q", step, f, got[f], types[i])
			}
		}
	}
	const plain, encrypted = "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"
	want("the keys written with the passphrase", encrypted, encrypted, encrypted)

	// key decrypt --all decrypts the keys of the root CA and of its issuing CAs, once.
	out, err := captureStdout(t, "key", "decrypt", "--ca-dir", servers, "--all")
	wantOut := fmt.Sprintf("Decrypted %q\nDecrypted %q\nDecrypted %q\n", filepath.Join(root, files[0]),
		filepath.Join(root, files[1]), filepath.Join(root, files[2]))
	if err != nil || out != wantOut {
		t.Errorf("key decrypt --all: %v\n%s\nwant\n%s", err, out, wantOut)
	}
	want("key decrypt --all", plain, plain, plain)
	if out, err := captureStdout(t, "key", "decrypt", "--ca-dir", servers, "--all"); err != nil || out != "" {
		t.Errorf("key decrypt --all of decrypted keys: %v, %q, want nothing done", err, out)
	}

	// key encrypt encrypts the keys of the CA of --ca-dir alone.
	out, err = captureStdout(t, "key", "encrypt", "--ca-dir", servers)
	wantOut = fmt.Sprintf("Encrypted %q\nEncrypted %q\n", filepath.Join(root, files[1]), filepath.Join(root, files[2]))
	if err != nil || out != wantOut {
		t.Errorf("key encrypt: %v\n%s\nwant\n%s", err, out, wantOut)
	}
	want("key encrypt of the issuing CA", plain, encrypted, encrypted)

	// A key that cannot be read fails, and the other keys are converted.
	bad := filepath.Join(root, "bad_key.pem")
	if err := os.WriteFile(bad, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := captureStdout(t, "key", "encrypt", "--ca-dir", root, "--all"); err == nil ||
		out != fmt.Sprintf("Encrypted %q\n", filepath.Join(root, files[0])) {
		t.Errorf("key encrypt --all with a bad key: %v, %q, want an error and ca_key.pem encrypted", err, out)
	}
	want("key encrypt --all with a bad key", encrypted, encrypted, encrypted)
	if err := run([]string{"key", "encrypt", "--ca-dir", filepath.Join(root, "nosuch")}); err == nil {
		t.Error("key encrypt of a directory without a CA succeeded, want an error")
	}

	entries, err := simpleca.ReadAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	var records []string
	for _, e := range entries {
		if strings.HasPrefix(e.Event, "key.") {
			var files string
			for _, f := range e.Fields {
				if f[0] == "files" {
					files = f[1]
				}
			}
			records = append(records, e.Event+" "+e.CA+" "+files)
		}
	}
	wantRecords := []string{"key.decrypt  ca_key.pem", "key.decrypt servers ca_key.pem,web_key.pem",
		"key.encrypt servers ca_key.pem,web_key.pem", "key.encrypt  ca_key.pem"}
	if fmt.Sprint(records) != fmt.Sprint(wantRecords) {
		t.Errorf("audit records %q, want %q", records, wantRecords)
	}
}
