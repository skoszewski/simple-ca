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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// writeConfig writes the JSON settings to simple-ca.json of dir.
func writeConfig(t *testing.T, dir, settings string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, simpleca.ConfigFile), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// verifyCert verifies the certificate cert against the CA bundle with openssl.
func verifyCert(t *testing.T, bundle, cert string) {
	t.Helper()
	out, err := exec.Command("openssl", "verify", "-CAfile", bundle, cert).CombinedOutput()
	if err != nil {
		t.Fatalf("certificate verification failed for %s:\n%s", cert, out)
	}
}

// assertEKU checks that openssl lists the extended key usage eku of the certificate cert.
func assertEKU(t *testing.T, cert, eku string) {
	t.Helper()
	out, err := exec.Command("openssl", "x509", "-in", cert, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 failed: %v", err)
	}
	if !strings.Contains(string(out), eku) {
		t.Fatalf("EKU %q not found in %s", eku, cert)
	}
}
