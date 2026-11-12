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

//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ---- systemd journal --------------------------------------------------------

// journalSocket is the socket of the native protocol of the systemd journal.
const journalSocket = "/run/systemd/journal/socket"

// journalConnected reports whether stderr is the stream systemd connected to the journal, the
// device and inode $JOURNAL_STREAM names.
func journalConnected() bool {
	dev, ino, ok := strings.Cut(os.Getenv("JOURNAL_STREAM"), ":")
	if !ok {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && strconv.FormatUint(uint64(st.Dev), 10) == dev && strconv.FormatUint(uint64(st.Ino), 10) == ino
}

// sendJournal sends the record, its line, its pairs and its level, to the systemd journal as one
// entry.
func sendJournal(line string, pairs [][2]string, level slog.Level) error {
	conn, err := net.Dial("unixgram", journalSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(journalEntry(line, pairs, level))
	return err
}

// journalEntry returns the datagram of the native protocol of a record: MESSAGE, the line,
// PRIORITY, the syslog priority of its level, SYSLOG_IDENTIFIER, and a field SIMPLE_CA_KEY of
// each pair.
func journalEntry(line string, pairs [][2]string, level slog.Level) []byte {
	var b bytes.Buffer
	add := func(key, value string) {
		b.WriteString(key)
		if strings.Contains(value, "\n") {
			b.WriteByte('\n')
			binary.Write(&b, binary.LittleEndian, uint64(len(value)))
		} else {
			b.WriteByte('=')
		}
		b.WriteString(value)
		b.WriteByte('\n')
	}
	priority := "6"
	switch {
	case level >= slog.LevelError:
		priority = "3"
	case level >= slog.LevelWarn:
		priority = "4"
	}
	add("MESSAGE", strings.TrimSuffix(line, "\n"))
	add("PRIORITY", priority)
	add("SYSLOG_IDENTIFIER", "simple-ca")
	for _, p := range pairs {
		add("SIMPLE_CA_"+strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z':
				return r - 'a' + 'A'
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				return r
			}
			return '_'
		}, p[0]), p[1])
	}
	return b.Bytes()
}
