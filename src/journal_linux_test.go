//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"testing"
)

func TestJournalEntry(t *testing.T) {
	line := "time=2026-11-03T20:39:18.913Z event=cert.issue ca=servers\n"
	got := journalEntry(line, [][2]string{{"event", "cert.issue"}, {"ca", "servers"}, {"client_addr", "192.0.2.1"},
		{"note", "two\nlines"}}, slog.LevelInfo)
	var want bytes.Buffer
	want.WriteString("MESSAGE=time=2026-11-03T20:39:18.913Z event=cert.issue ca=servers\n")
	want.WriteString("PRIORITY=6\nSYSLOG_IDENTIFIER=simple-ca\n")
	want.WriteString("SIMPLE_CA_EVENT=cert.issue\nSIMPLE_CA_CA=servers\nSIMPLE_CA_CLIENT_ADDR=192.0.2.1\n")
	want.WriteString("SIMPLE_CA_NOTE\n")
	binary.Write(&want, binary.LittleEndian, uint64(len("two\nlines")))
	want.WriteString("two\nlines\n")
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("journalEntry:\n%q\nwant\n%q", got, want.Bytes())
	}
	if got := journalEntry(line, nil, slog.LevelError); !bytes.Contains(got, []byte("\nPRIORITY=3\n")) {
		t.Errorf("journalEntry of an error: %q, want PRIORITY=3", got)
	}
	t.Setenv("JOURNAL_STREAM", "")
	if journalConnected() {
		t.Error("journalConnected without JOURNAL_STREAM, want false")
	}
	t.Setenv("JOURNAL_STREAM", "1:2")
	if journalConnected() {
		t.Error("journalConnected with the device and inode of another stream, want false")
	}
}
