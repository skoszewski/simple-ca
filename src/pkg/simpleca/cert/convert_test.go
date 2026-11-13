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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
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
	cmd.Env = append(os.Environ(), "SIMPLE_CA_TEST_CHILD="+name, "SIMPLE_CA_KEY_PASSWORD=convert-secret",
		"SIMPLE_CA_KEY_PASSWORD_FILE=", simpleca.PrivateGroupWriteEnv+"=")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+name) {
		t.Fatalf("%s in a new process: %v\n%s", name, err, out)
	}
	return false
}

// pemType returns the type of the first PEM block of the file path.
func pemType(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s has no PEM block", path)
	}
	return block.Type
}

func TestConvertKey(t *testing.T) {
	if !inChild(t, "TestConvertKey") {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "web_key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	sameKey := func(step string) {
		t.Helper()
		loaded, err := simpleca.LoadKey(path)
		if err != nil || !key.Public().(*ecdsa.PublicKey).Equal(loaded.Public()) {
			t.Fatalf("%s: the key loads as %v, %v, want the key written", step, loaded, err)
		}
		if info, err := os.Stat(path); runtime.GOOS != "windows" && (err != nil || info.Mode().Perm() != simpleca.PrivateMode()) {
			t.Errorf("%s: mode %v, %v, want %v", step, info.Mode().Perm(), err, simpleca.PrivateMode())
		}
	}

	for _, step := range []struct {
		encrypt bool
		want    bool
		typ     string
	}{
		{false, false, "PRIVATE KEY"},
		{true, true, "ENCRYPTED PRIVATE KEY"},
		{true, false, "ENCRYPTED PRIVATE KEY"},
		{false, true, "PRIVATE KEY"},
	} {
		converted, err := ConvertKey(path, step.encrypt)
		if err != nil || converted != step.want || pemType(t, path) != step.typ {
			t.Fatalf("ConvertKey encrypt=%v: %v, %v, %s, want %v, %s", step.encrypt, converted, err, pemType(t, path), step.want, step.typ)
		}
		if step.want {
			sameKey(fmt.Sprintf("ConvertKey encrypt=%v", step.encrypt))
		}
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, ".key-*")); len(entries) != 0 {
		t.Errorf("temporary files are left: %v", entries)
	}

	// A file that is no key is left as it is.
	bad := filepath.Join(dir, "bad_key.pem")
	content := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	if err := os.WriteFile(bad, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if converted, err := ConvertKey(bad, true); err == nil || converted {
		t.Errorf("ConvertKey of a file that is no key: %v, %v, want an error", converted, err)
	}
	if b, _ := os.ReadFile(bad); string(b) != string(content) {
		t.Errorf("the file that is no key was changed to %q", b)
	}
	if converted, err := ConvertKey(filepath.Join(dir, "missing_key.pem"), true); err == nil || converted {
		t.Errorf("ConvertKey of a missing file: %v, %v, want an error", converted, err)
	}
}
