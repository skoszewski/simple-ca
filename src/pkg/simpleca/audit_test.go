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
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// field returns the value of key in the record e, empty without it.
func field(e AuditEntry, key string) string {
	for _, p := range e.Fields {
		if p[0] == key {
			return p[1]
		}
	}
	return ""
}

// readAll returns the records of the audit log of the root CA in rootDir.
func readAll(t *testing.T, rootDir string) []AuditEntry {
	t.Helper()
	entries, err := ReadAudit(rootDir)
	if err != nil {
		t.Fatalf("ReadAudit: %v", err)
	}
	return entries
}

// streamTo makes LogStream append its lines, pairs and levels to the slices given, until the test
// ends.
func streamTo(t *testing.T, lines *[]string, pairs *[][][2]string, levels *[]slog.Level) {
	t.Helper()
	LogStream = func(line string, p [][2]string, level slog.Level) error {
		*lines, *pairs, *levels = append(*lines, line), append(*pairs, p), append(*levels, level)
		return nil
	}
	t.Cleanup(func() { LogStream = nil })
}

func TestAudit(t *testing.T) {
	root := newRoot(t, "rsa")
	servers := newIssuing(t, root, "servers", "ec")
	var lines []string
	var pairs [][][2]string
	var levels []slog.Level
	streamTo(t, &lines, &pairs, &levels)

	// The reader reads back what TextHandler wrote, quoted or not, and the stream gets the same.
	odd := []string{"two words", `a "quote"`, "k=v", "", `back\slash`, "line\nbreak"}
	Audit(servers.dir, "test.event", "a", odd[0], "b", odd[1], "c", odd[2], "d", odd[3], "e", odd[4], "f", odd[5], "n", 42)
	entries := readAll(t, root.dir)
	if len(entries) != 1 {
		t.Fatalf("%d records, want 1", len(entries))
	}
	e := entries[0]
	if e.Event != "test.event" || e.CA != "servers" || time.Since(e.Time) > time.Minute || e.Time.Location() != time.UTC {
		t.Errorf("record %+v, want test.event of servers, now", e)
	}
	for i, key := range []string{"a", "b", "c", "d", "e", "f"} {
		if got := field(e, key); got != odd[i] {
			t.Errorf("%s = %q, want %q", key, got, odd[i])
		}
	}
	if field(e, "n") != "42" || !strings.HasPrefix(e.Line, "time=") || strings.Contains(e.Line, "level=") ||
		strings.Contains(e.Line, "\n") {
		t.Errorf("line %q, want time first, n=42, no level and one line", e.Line)
	}
	if len(lines) != 1 || strings.TrimSuffix(lines[0], "\n") != e.Line || levels[0] != slog.LevelInfo {
		t.Errorf("stream %q %v, want the line of the file at the level info", lines, levels)
	}
	if len(pairs) != 1 || len(pairs[0]) != 9 || pairs[0][0] != [2]string{"event", "test.event"} ||
		pairs[0][1] != [2]string{"ca", "servers"} || pairs[0][8] != [2]string{"n", "42"} {
		t.Errorf("stream pairs %q, want the event, the CA and the pairs given", pairs)
	}
	info, err := os.Stat(filepath.Join(root.dir, AuditFile))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("%s: %v, want mode 0600", AuditFile, err)
	}

	// A record of the root CA has an empty CA, and a stream that fails leaves the file written.
	LogStream = func(string, [][2]string, slog.Level) error { return errors.New("stream down") }
	Audit(root.dir, "root.event", "name", "x")
	if entries := readAll(t, root.dir); len(entries) != 2 || entries[1].Event != "root.event" || entries[1].CA != "" ||
		field(entries[1], "name") != "x" {
		t.Errorf("records %+v, want root.event of the root CA last", entries)
	}
	LogStream = nil

	// A directory that is no CA gets no record.
	other := t.TempDir()
	Audit(other, "lost.event")
	if FileExists(filepath.Join(other, AuditFile)) || len(readAll(t, root.dir)) != 2 {
		t.Error("a record of a directory that is no CA was written")
	}
}

func TestAuditFileSetting(t *testing.T) {
	root := newRoot(t, "ec")
	servers := newIssuing(t, root, "servers", "ec")
	moved := filepath.Join(t.TempDir(), "moved.log")
	writeConfig(t, root.dir, `{"audit": {"file": "`+filepath.ToSlash(moved)+`"}}`)
	Audit(servers.dir, "test.moved")
	if b, err := os.ReadFile(moved); err != nil || !strings.Contains(string(b), "event=test.moved") {
		t.Errorf("audit.file: %q, %v, want the record in %s", b, err, moved)
	}
	if entries := readAll(t, root.dir); len(entries) != 1 || entries[0].Event != "test.moved" {
		t.Errorf("ReadAudit of audit.file: %+v", entries)
	}
	if FileExists(filepath.Join(root.dir, AuditFile)) {
		t.Errorf("%s written with audit.file set", AuditFile)
	}

	// A relative audit.file is in the root CA directory.
	writeConfig(t, root.dir, `{"audit": {"file": "custom.log"}}`)
	Audit(servers.dir, "test.relative")
	if b, err := os.ReadFile(filepath.Join(root.dir, "custom.log")); err != nil || !strings.Contains(string(b), "ca=servers") {
		t.Errorf("a relative audit.file: %q, %v", b, err)
	}
	writeConfig(t, root.dir, `{"audit": {"path": "x.log"}}`)
	if _, err := ReadAudit(root.dir); err == nil {
		t.Error("ReadAudit with a bad simple-ca.json succeeded, want an error")
	}
}

func TestReadAudit(t *testing.T) {
	root := newRoot(t, "ec")
	if entries, err := ReadAudit(root.dir); err != nil || entries != nil {
		t.Fatalf("ReadAudit without a log: %v, %v, want none", entries, err)
	}
	log := strings.Join([]string{
		"not a record",
		"",
		"time=2026-11-11T10:00:00.000Z event=cert.issue ca=servers serial=01 name=\"two words\"\r",
		`time=2026-11-11T10:00:01.000Z event=bad value="unterminated`,
		"a b=c",
		"=value",
		"time=2026-11-11T10:00:02.250Z event=crl.write ca=\"\"",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(root.dir, AuditFile), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := readAll(t, root.dir)
	if len(entries) != 2 {
		t.Fatalf("records %+v, want the two lines that are records", entries)
	}
	first, second := entries[0], entries[1]
	if !first.Time.Equal(time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)) || first.Event != "cert.issue" || first.CA != "servers" ||
		field(first, "serial") != "01" || field(first, "name") != "two words" || len(first.Fields) != 5 ||
		strings.HasSuffix(first.Line, "\r") {
		t.Errorf("the first record %+v", first)
	}
	if !second.Time.Equal(time.Date(2026, 11, 11, 10, 0, 2, 250e6, time.UTC)) || second.Event != "crl.write" || second.CA != "" {
		t.Errorf("the second record %+v", second)
	}
}

func TestFormatRecord(t *testing.T) {
	at := time.Date(2026, 11, 11, 11, 0, 0, 123e6, time.FixedZone("CET", 3600))
	r := slog.NewRecord(at, slog.LevelWarn, "token.create", 0)
	r.Add("ca", "", "name", "web deploy", "n", 3)
	line, pairs, err := FormatRecord(r)
	if err != nil || line != "time=2026-11-11T10:00:00.123Z event=token.create ca=\"\" name=\"web deploy\" n=3\n" {
		t.Errorf("FormatRecord line %q, %v", line, err)
	}
	if !slices.Equal(pairs, [][2]string{{"event", "token.create"}, {"ca", ""}, {"name", "web deploy"}, {"n", "3"}}) {
		t.Errorf("FormatRecord pairs %q", pairs)
	}
}

func TestCLIActor(t *testing.T) {
	want := strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		want = u.Username
	}
	if got := CLIActor(); got == "" || got != want {
		t.Errorf("CLIActor() = %q, want %q", got, want)
	}
}
