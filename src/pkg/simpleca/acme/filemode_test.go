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

package acme

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
	t.Setenv(simpleca.PrivateGroupWriteEnv, "1")
	dir := t.TempDir()
	stale := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(stale, []byte("stale"), 0o400); err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	if _, err := s.state(dir); err != nil {
		t.Fatal(err)
	}
	if err := s.save(dir); err != nil {
		t.Fatalf("save with a stale %s: %v", stale, err)
	}
	if info, err := os.Stat(filepath.Join(dir, stateFile)); err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("%s: %v, %v, want mode 660", stateFile, info, err)
	}
	if simpleca.FileExists(stale) {
		t.Errorf("%s is left", stale)
	}
}
