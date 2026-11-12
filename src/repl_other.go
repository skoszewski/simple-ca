//go:build !unix

package main

import "golang.org/x/term"

// followTerminalSize does nothing where the system signals no resize; the size is taken at each
// prompt.
func followTerminalSize(t *term.Terminal) {}
