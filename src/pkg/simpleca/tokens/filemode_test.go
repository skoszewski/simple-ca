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

package tokens

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestSaveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no group modes")
	}
	for _, tt := range []struct {
		env  string
		want os.FileMode
	}{{"", 0o600}, {"1", 0o660}} {
		t.Setenv(simpleca.PrivateGroupWriteEnv, tt.env)
		dir := t.TempDir()
		stale := filepath.Join(dir, TokensFile+".tmp")
		if err := os.WriteFile(stale, []byte("stale"), 0o400); err != nil {
			t.Fatal(err)
		}
		db, err := LoadTokens(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Save(dir); err != nil {
			t.Fatalf("%s=%q: Save with a stale %s: %v", simpleca.PrivateGroupWriteEnv, tt.env, stale, err)
		}
		info, err := os.Stat(filepath.Join(dir, TokensFile))
		if err != nil || info.Mode().Perm() != tt.want {
			t.Errorf("%s=%q: %s %v, %v, want mode %o", simpleca.PrivateGroupWriteEnv, tt.env, TokensFile, info, err, tt.want)
		}
		if simpleca.FileExists(stale) {
			t.Errorf("%s=%q: %s is left", simpleca.PrivateGroupWriteEnv, tt.env, stale)
		}
	}
}
