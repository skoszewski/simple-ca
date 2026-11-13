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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileModes(t *testing.T) {
	t.Setenv(PrivateGroupWriteEnv, "")
	if PrivateMode() != 0o600 || DirMode() != 0o750 {
		t.Errorf("unset: %o, %o", PrivateMode(), DirMode())
	}
	t.Setenv(PrivateGroupWriteEnv, "1")
	if PrivateMode() != 0o660 || DirMode() != 0o770 {
		t.Errorf("set: %o, %o", PrivateMode(), DirMode())
	}
}

func TestWritePrivateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no group modes")
	}
	t.Setenv(PrivateGroupWriteEnv, "1")
	dir := t.TempDir()
	path := filepath.Join(dir, "new.json")
	if err := WritePrivateFile(path, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o660 {
		t.Errorf("new file mode %o", info.Mode().Perm())
	}

	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(existing, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(existing)
	if b, _ := os.ReadFile(existing); string(b) != "new" || info.Mode().Perm() != 0o640 {
		t.Errorf("existing file %q, mode %o", b, info.Mode().Perm())
	}

	if _, err := CreatePrivateFile(existing, os.O_WRONLY|os.O_EXCL); !errors.Is(err, os.ErrExist) {
		t.Errorf("O_EXCL of an existing file: %v", err)
	}
}

func TestAuditAndLockModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no group modes")
	}
	t.Setenv(PrivateGroupWriteEnv, "1")
	dir := t.TempDir()
	if err := writeAuditFile(dir, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, AuditFile)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o660 {
		t.Fatalf("new audit log: %v, %v, want mode 660", info, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeAuditFile(dir, []byte("second\n")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if b, _ := os.ReadFile(path); string(b) != "first\nsecond\n" || info.Mode().Perm() != 0o640 {
		t.Errorf("audit log appended %q, mode %o, want both lines and mode 640", b, info.Mode().Perm())
	}

	unlock, err := LockFile(filepath.Join(dir, "tokens-db.json"))
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(dir, "tokens-db.json.lock"))
	unlock()
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("lock file: %v, %v, want mode 660", info, err)
	}
}

func TestMkdirAll(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no group modes")
	}
	for _, tt := range []struct {
		env  string
		want os.FileMode
	}{{"", 0o750}, {"1", 0o770}} {
		t.Setenv(PrivateGroupWriteEnv, tt.env)
		path := filepath.Join(t.TempDir(), "a", "b")
		if err := MkdirAll(path); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != tt.want {
			t.Errorf("%s=%q: mode %o, want %o", PrivateGroupWriteEnv, tt.env, info.Mode().Perm(), tt.want)
		}
	}
}
