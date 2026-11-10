//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// followTerminalSize gives t the size of the terminal each time the terminal is resized, also
// while a line is edited.
func followTerminalSize(t *term.Terminal) {
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)
	go func() {
		for range resized {
			if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
				t.SetSize(width, height)
			}
		}
	}()
}
