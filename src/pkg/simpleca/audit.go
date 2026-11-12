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
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// AuditFile is the audit log of the root CA directory, unless audit.file names another.
	AuditFile = "audit.log"
	// auditTimeFormat is the format of the time of a record, in UTC.
	auditTimeFormat = "2006-01-02T15:04:05.000Z07:00"
)

// LogStream is the stream serve writes its records to, its log and its audit records, given each
// line, its event and pairs, and its level: the systemd journal, or stderr; nil for the commands,
// whose audit records go to the file alone.
var LogStream func(line string, pairs [][2]string, level slog.Level) error

// FormatRecord returns the line of r, as TextHandler with auditOptions writes it, and its event
// and pairs.
func FormatRecord(r slog.Record) (string, [][2]string, error) {
	var line bytes.Buffer
	if err := slog.NewTextHandler(&line, auditOptions).Handle(context.Background(), r); err != nil {
		return "", nil, err
	}
	pairs := [][2]string{{"event", r.Message}}
	r.Attrs(func(a slog.Attr) bool {
		pairs = append(pairs, [2]string{a.Key, a.Value.String()})
		return true
	})
	return line.String(), pairs, nil
}

// auditOptions make TextHandler write the time in UTC first, without the level, and the message
// as the event.
var auditOptions = &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
	switch {
	case len(groups) > 0:
	case a.Key == slog.TimeKey:
		return slog.String(slog.TimeKey, a.Value.Time().UTC().Format(auditTimeFormat))
	case a.Key == slog.LevelKey:
		return slog.Attr{}
	case a.Key == slog.MessageKey:
		a.Key = "event"
	}
	return a
}}

// Audit records the event of the CA in caDir, with the key and value pairs of args, in the audit
// log of its root CA and in LogStream; a record that cannot be written is reported on stderr.
func Audit(caDir, event string, args ...any) {
	rootDir, ca, err := LocateCA(caDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return
	}
	record := slog.NewRecord(time.Now(), slog.LevelInfo, event, 0)
	record.Add(append([]any{"ca", ca}, args...)...)
	line, pairs, err := FormatRecord(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return
	}
	if err := writeAuditFile(rootDir, []byte(line)); err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
	}
	if LogStream == nil {
		return
	}
	if err := LogStream(line, pairs, slog.LevelInfo); err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
	}
}

// auditPath returns the audit log of the root CA in rootDir: audit.file of its simple-ca.json,
// relative to rootDir, or AuditFile.
func auditPath(rootDir string) (string, error) {
	cfg, err := LoadConfig(rootDir)
	if err != nil {
		return "", err
	}
	path := cfg.Audit.File
	if path == "" {
		path = AuditFile
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(rootDir, path)
	}
	return path, nil
}

// writeAuditFile appends line to the audit log of the root CA in rootDir, opened for it alone, so
// a log moved by a rotation is not written further.
func writeAuditFile(rootDir string, line []byte) error {
	path, err := auditPath(rootDir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(line)
	if err := cmp.Or(err, f.Close()); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// CLIActor returns the user running a command, for the actor of its records.
func CLIActor() string {
	u, err := user.Current()
	if err != nil {
		return strconv.Itoa(os.Getuid())
	}
	return u.Username
}

// AuditEntry is a record of the audit log: its time, event and CA, its pairs in their order, and
// its line.
type AuditEntry struct {
	Time   time.Time   `json:"time"`
	Event  string      `json:"event"`
	CA     string      `json:"ca"`
	Fields [][2]string `json:"fields"`
	Line   string      `json:"line"`
}

// ReadAudit returns the records of the audit log of the root CA in rootDir in the order of the
// file, none without it, leaving out the lines that are no records.
func ReadAudit(rootDir string) ([]AuditEntry, error) {
	path, err := auditPath(rootDir)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []AuditEntry
	for line := range strings.Lines(string(b)) {
		pairs, err := parseAuditLine(line)
		if err != nil || len(pairs) == 0 {
			continue
		}
		e := AuditEntry{Fields: pairs, Line: strings.TrimRight(line, "\r\n")}
		for _, p := range pairs {
			switch p[0] {
			case slog.TimeKey:
				e.Time, _ = time.Parse(auditTimeFormat, p[1])
			case "event":
				e.Event = p[1]
			case "ca":
				e.CA = p[1]
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// parseAuditLine returns the key and value pairs of a record of the audit log, as TextHandler
// writes them: key=value, a value quoted as a Go string when it needs it.
func parseAuditLine(line string) ([][2]string, error) {
	var pairs [][2]string
	rest := strings.TrimRight(line, "\r\n")
	for rest = strings.TrimLeft(rest, " "); rest != ""; rest = strings.TrimLeft(rest, " ") {
		key, value, ok := strings.Cut(rest, "=")
		if !ok || key == "" || strings.Contains(key, " ") {
			return nil, fmt.Errorf("'%s' is not a key=value pair", rest)
		}
		rest = value
		if strings.HasPrefix(rest, `"`) {
			quoted, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return nil, fmt.Errorf("the value of %s is not a quoted string", key)
			}
			if value, err = strconv.Unquote(quoted); err != nil {
				return nil, fmt.Errorf("the value of %s is not a quoted string", key)
			}
			rest = rest[len(quoted):]
		} else {
			value, rest, _ = strings.Cut(rest, " ")
			rest = " " + rest
		}
		pairs = append(pairs, [2]string{key, value})
	}
	return pairs, nil
}
