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
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestPrivateFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no group modes")
	}
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", "")
	for _, tt := range []struct {
		env       string
		file, dir os.FileMode
	}{{"", 0o600, 0o750}, {"1", 0o660, 0o770}} {
		t.Setenv(simpleca.PrivateGroupWriteEnv, tt.env)
		caDir, certDir := t.TempDir(), t.TempDir()
		if err := MakeCA(caDir, "Test CA", 3650, "", "", "ec"); err != nil {
			t.Fatal(err)
		}
		if err := MakeCA(caDir, "Servers CA", 0, "servers", "", "ec"); err != nil {
			t.Fatal(err)
		}
		issuingDir := filepath.Join(caDir, "servers")
		if _, err := MakeCert("web.example.com", nil, issuingDir, certDir, "server", 30, nil, nil, ""); err != nil {
			t.Fatal(err)
		}
		if err := MakePFX(filepath.Join(certDir, "web_cert.pem"), issuingDir, ""); err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]os.FileMode{
			filepath.Join(caDir, "ca_key.pem"):      tt.file,
			issuingDir:                              tt.dir,
			filepath.Join(issuingDir, "ca_key.pem"): tt.file,
			filepath.Join(certDir, "web_key.pem"):   tt.file,
			filepath.Join(certDir, "web.pfx"):       tt.file,
		} {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != want {
				t.Errorf("%s=%q: %s: %v, %v, want mode %o", simpleca.PrivateGroupWriteEnv, tt.env, path, info, err, want)
			}
		}
	}
}
