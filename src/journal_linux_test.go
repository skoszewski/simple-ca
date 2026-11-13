//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
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
	fi, err := os.Stderr.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	t.Setenv("JOURNAL_STREAM", strconv.FormatUint(uint64(st.Dev), 10)+":"+strconv.FormatUint(uint64(st.Ino), 10))
	if !journalConnected() {
		t.Error("journalConnected with the device and inode of stderr, want true")
	}
}

func TestSendJournal(t *testing.T) {
	saved := journalSocket
	t.Cleanup(func() { journalSocket = saved })
	journalSocket = filepath.Join(t.TempDir(), "socket")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: journalSocket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pairs := [][2]string{{"event", "serve.start"}}
	if err := streamJournal("event=serve.start\n", pairs, slog.LevelWarn); err != nil {
		t.Fatalf("streamJournal: %v", err)
	}
	b := make([]byte, 65536)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if want := journalEntry("event=serve.start\n", pairs, slog.LevelWarn); !bytes.Equal(b[:n], want) {
		t.Errorf("datagram %q, want %q", b[:n], want)
	}

	journalSocket = filepath.Join(t.TempDir(), "missing")
	stderr := srvCaptureStderr(t)
	if err := streamJournal("a line\n", nil, slog.LevelInfo); err == nil {
		t.Error("streamJournal without the journal, want its error")
	}
	srvWaitFor(t, stderr, "a line\n")
}
