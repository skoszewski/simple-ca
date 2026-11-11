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

package simpleca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocateCA(t *testing.T) {
	root := newRoot(t, "rsa")
	issuing := newIssuing(t, root, "issuing-ca", "ec")
	rootDir, name, err := LocateCA(issuing.dir)
	if err != nil || name != "issuing-ca" || rootDir != root.dir {
		t.Fatalf("LocateCA(%s) = %q, %q, %v, want %s and issuing-ca", issuing.dir, rootDir, name, err, root.dir)
	}
	if rootDir, name, err := LocateCA(root.dir); err != nil || name != "" || rootDir != root.dir {
		t.Fatalf("LocateCA(%s) = %q, %q, %v, want the root CA", root.dir, rootDir, name, err)
	}

	// A relative directory gives an absolute root CA directory.
	t.Chdir(root.dir)
	for _, c := range []struct{ dir, name string }{{".", ""}, {"issuing-ca", "issuing-ca"}} {
		if rootDir, name, err := LocateCA(c.dir); err != nil || name != c.name || !filepath.IsAbs(rootDir) ||
			filepath.Base(rootDir) != filepath.Base(root.dir) {
			t.Errorf("LocateCA(%q) = %q, %q, %v, want the absolute root CA directory", c.dir, rootDir, name, err)
		}
	}

	empty := t.TempDir()
	if _, _, err := LocateCA(empty); err == nil || !strings.Contains(err.Error(), "CA certificate not found") {
		t.Errorf("LocateCA of a directory without ca_cert.pem: %v, want an error", err)
	}
	if err := os.WriteFile(filepath.Join(empty, "ca_cert.pem"), []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LocateCA(empty); err == nil {
		t.Error("LocateCA of a ca_cert.pem without a certificate succeeded, want an error")
	}
}

func TestLoadCert(t *testing.T) {
	root := newRoot(t, "ec")
	cert, err := LoadCert(filepath.Join(root.dir, "ca_cert.pem"))
	if err != nil || !cert.Equal(root.cert) {
		t.Fatalf("LoadCert: %v, want the CA certificate", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "text.pem"), []byte("text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "bad.pem"), "CERTIFICATE", []byte{1, 2, 3})
	for _, path := range []string{
		filepath.Join(root.dir, "ca_key.pem"), filepath.Join(dir, "text.pem"), filepath.Join(dir, "bad.pem"),
		filepath.Join(dir, "missing.pem"),
	} {
		if _, err := LoadCert(path); err == nil {
			t.Errorf("LoadCert(%s) succeeded, want an error", path)
		}
	}
}

func TestFileExists(t *testing.T) {
	root := newRoot(t, "ec")
	for path, want := range map[string]bool{
		filepath.Join(root.dir, "ca_cert.pem"): true,
		root.dir:                               false,
		filepath.Join(root.dir, "missing.pem"): false,
	} {
		if got := FileExists(path); got != want {
			t.Errorf("FileExists(%s) = %v, want %v", path, got, want)
		}
	}
}
