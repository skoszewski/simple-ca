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

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// ---- audit log --------------------------------------------------------------

// requestLog makes serve log each request it serves.
var requestLog bool

// streamHandler is the slog handler of serve, which writes each record as simpleca.FormatRecord
// formats it to simpleca.LogStream, or to stderr without it; groups are not used.
type streamHandler struct {
	attrs []slog.Attr
}

func (h streamHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h streamHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return streamHandler{append(slices.Clip(h.attrs), attrs...)}
}

func (h streamHandler) WithGroup(string) slog.Handler { return h }

func (h streamHandler) Handle(_ context.Context, r slog.Record) error {
	r.AddAttrs(h.attrs...)
	line, pairs, err := simpleca.FormatRecord(r)
	if err != nil {
		return err
	}
	if simpleca.LogStream == nil {
		return streamStderr(line, pairs, r.Level)
	}
	return simpleca.LogStream(line, pairs, r.Level)
}

// logWriter turns each line the log package writes, such as an error of net/http, into a record
// log of serve, its text the message.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	slog.Info("log", "message", strings.TrimSpace(string(p)))
	return len(p), nil
}

// streamStderr writes line to stderr, the stream of serve outside the systemd journal.
func streamStderr(line string, _ [][2]string, _ slog.Level) error {
	_, err := os.Stderr.WriteString(line)
	return err
}

// streamJournal sends the record to the systemd journal, and to stderr when the journal refuses it.
func streamJournal(line string, pairs [][2]string, level slog.Level) error {
	if err := sendJournal(line, pairs, level); err != nil {
		return errors.Join(err, streamStderr(line, pairs, level))
	}
	return nil
}
