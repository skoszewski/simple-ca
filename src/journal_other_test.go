//go:build !linux

package main

import (
	"log/slog"
	"testing"
)

func TestJournalOther(t *testing.T) {
	t.Setenv("JOURNAL_STREAM", "1:2")
	if journalConnected() {
		t.Error("journalConnected outside Linux, want false")
	}
	if err := sendJournal("a line\n", nil, slog.LevelInfo); err == nil {
		t.Error("sendJournal outside Linux, want an error")
	}
	stderr := srvCaptureStderr(t)
	if err := streamJournal("a line\n", nil, slog.LevelInfo); err == nil {
		t.Error("streamJournal outside Linux, want the error of the journal")
	}
	srvWaitFor(t, stderr, "a line\n")
}
