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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

func TestMakeCRLAll(t *testing.T) {
	caDir := t.TempDir()

	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	for _, name := range []string{"servers", "users"} {
		if err := cert.MakeCA(caDir, name+" CA", 0, name, "", "rsa"); err != nil {
			t.Fatalf("makeCA %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(caDir, "other"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := run([]string{"crl", "create", "--ca-dir", filepath.Join(caDir, "users"), "--all"}); err != nil {
		t.Fatalf("crl create --all: %v", err)
	}
	for _, dir := range []string{caDir, filepath.Join(caDir, "servers"), filepath.Join(caDir, "users")} {
		if b, err := os.ReadFile(filepath.Join(dir, cert.CRLNumberFile)); err != nil || strings.TrimSpace(string(b)) != "03" {
			t.Fatalf("crlnumber of %s is %q, %v, want 03 after the second CRL", dir, b, err)
		}
	}
	if simpleca.FileExists(filepath.Join(caDir, "other", "crl.pem")) {
		t.Fatal("crl create --all wrote a CRL in a directory without a CA")
	}
	if err := run([]string{"crl", "create", "--ca-dir", filepath.Join(caDir, "servers")}); err != nil {
		t.Fatalf("crl create: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(caDir, "users", cert.CRLNumberFile)); err != nil || strings.TrimSpace(string(b)) != "03" {
		t.Fatalf("crl create without --all changed the crlnumber of another CA: %q, %v", b, err)
	}
}
