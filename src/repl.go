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
	"bufio"
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"golang.org/x/term"
)

// sessionRoot is the root CA directory of the hierarchy of the REPL, empty without one, and
// sessionCA the issuing CA of its active context, empty for the root CA.
var sessionRoot, sessionCA string

// errReported reports a failure whose message was already written.
var errReported = errors.New("reported")

// historyLimit is the number of lines the history file keeps.
const historyLimit = 500

// contextGroup is the group of the REPL alone, of the CAs of the hierarchy and their option values.
var contextGroup = cli.Command{Name: "context", Summary: "Switch the CA of the session and keep option values for each CA.",
	Sub: []cli.Command{
		{Name: "list", Summary: "List the CAs of the hierarchy, the active one marked.", Run: runContextList},
		{Name: "use", Summary: "Make an issuing CA, or the root CA, the CA of the commands.", Run: runContextUse},
		{Name: "set", Summary: "Set the values of an option in the active context.", Run: runContextSet},
		{Name: "add", Summary: "Add values to an option in the active context.", Run: runContextAdd},
		{Name: "delete", Summary: "Delete values, or an option, from the active context.", Run: runContextDelete},
		{Name: "show", Summary: "Show the option values of the active context.", Run: runContextShow},
	}}

// runREPL runs the commands of a session on a terminal, else the lines of stdin as a script.
func runREPL() error {
	placeCA(cli.ResolveCADir(""))
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return runInteractive()
	}
	cli.Input = strings.NewReader("")
	return runScript(os.Stdin)
}

// placeCA makes the CA in dir the active context, in the hierarchy of its root CA.
func placeCA(dir string) error {
	rootDir, caID, err := findCA(dir)
	if err != nil {
		return err
	}
	sessionRoot, sessionCA = rootDir, caID
	return nil
}

// isCADir reports whether dir holds an initialized CA: its certificate, its key and its index.txt,
// not a copy of a CA certificate alone.
func isCADir(dir string) bool {
	return simpleca.FileExists(filepath.Join(dir, "ca_cert.pem")) && simpleca.FileExists(filepath.Join(dir, "ca_key.pem")) &&
		simpleca.FileExists(filepath.Join(dir, "index.txt"))
}

// findCA returns the root CA directory and the issuing CA name of the initialized CA in dir.
func findCA(dir string) (string, string, error) {
	if !isCADir(dir) {
		return "", "", fmt.Errorf("%s is not a CA directory: it has no ca_cert.pem, ca_key.pem and index.txt", dir)
	}
	return simpleca.LocateCA(dir)
}

// sessionCAs returns the IDs of the CAs of the hierarchy of the session, empty for the root CA.
func sessionCAs() []string {
	return slices.DeleteFunc(simpleca.CAIDs(sessionRoot), func(id string) bool {
		return !isCADir(filepath.Join(sessionRoot, id))
	})
}

// prompt returns the prompt of the session, which names the CA of the active context.
func prompt() string {
	if sessionRoot == "" {
		return "simple-ca> "
	}
	return "simple-ca:" + cmp.Or(sessionCA, "root") + "> "
}

// runInteractive reads the commands from the terminal with line editing, history and completion,
// until exit, quit, Ctrl-D or Ctrl-C.
func runInteractive() error {
	fd := int(os.Stdin.Fd())
	t := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}, prompt())
	t.History = loadHistory()
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			return "", 0, false
		}
		return complete(t, line, pos)
	}
	followTerminalSize(t)
	for {
		// The terminal is raw while a line is edited, and as usual while a command runs.
		state, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		// The line is edited in the width of the terminal at the time of the prompt.
		if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			t.SetSize(width, height)
		}
		t.SetPrompt(prompt())
		line, err := t.ReadLine()
		term.Restore(fd, state)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		args, err := splitLine(line)
		if err == nil {
			if isExit(args) {
				return nil
			}
			err = runLine(args)
		}
		switch {
		case err == nil, errors.Is(err, flag.ErrHelp), errors.Is(err, cli.ErrUsage):
		default:
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		}
	}
}

// runScript runs the lines of r as commands, skipping blank lines and # comments, and stops at the
// first failing one, naming its line.
func runScript(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		args, err := splitLine(line)
		if err == nil {
			if isExit(args) {
				return nil
			}
			err = runLine(args)
		}
		switch {
		case err == nil, errors.Is(err, flag.ErrHelp):
		case errors.Is(err, cli.ErrUsage):
			fmt.Fprintf(os.Stderr, "line %d: invalid command line\n", n)
			return cli.ErrUsage
		default:
			fmt.Fprintf(os.Stderr, "line %d: ERROR: %v\n", n, err)
			return errReported
		}
	}
	return scanner.Err()
}

// isExit reports whether args end the session.
func isExit(args []string) bool {
	return len(args) == 1 && (args[0] == "exit" || args[0] == "quit")
}

// runLine runs one command of the session: the context group, help, or a command of the command
// line but serve; a leading simple-ca is dropped.
func runLine(args []string) error {
	if len(args) > 0 && args[0] == "simple-ca" {
		args = args[1:]
	}
	if len(args) == 0 {
		return nil
	}
	var err error
	switch args[0] {
	case "serve":
		return errors.New("serve is not run in the REPL; run simple-ca serve")
	case "context":
		err = runGroup(&contextGroup, args[1:])
	case "-h", "-help", "--help", "help":
		cli.PrintUsage(os.Stdout, commands, nil)
		fmt.Printf("\nIn a session:\n  %-8s %s\n  %-8s %s\n", contextGroup.Name, contextGroup.Summary,
			"exit", "End the session; quit, Ctrl-D and Ctrl-C too.")
	default:
		err = run(args)
	}
	// A session started outside a CA works on the root CA ca create made.
	if sessionRoot == "" {
		placeCA(cli.ResolveCADir(""))
	}
	return err
}

// runGroup runs the command of the group g that args name, or prints its usage.
func runGroup(g *cli.Command, args []string) error {
	if len(args) == 0 {
		cli.PrintUsage(os.Stderr, commands, g)
		return cli.ErrUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		cli.PrintUsage(os.Stdout, commands, g)
		return nil
	}
	i := slices.IndexFunc(g.Sub, func(c cli.Command) bool { return c.Name == args[0] })
	if i < 0 {
		fmt.Fprintf(os.Stderr, "simple-ca %s: unknown command %q\n\n", g.Name, args[0])
		cli.PrintUsage(os.Stderr, commands, g)
		return cli.ErrUsage
	}
	return g.Sub[i].Run(args[1:])
}

// splitLine splits a line into arguments as a shell does, with '...' and "..." quotes and \
// escapes, and no expansion.
func splitLine(line string) ([]string, error) {
	var args []string
	var arg strings.Builder
	inArg, quote := false, rune(0)
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				arg.WriteRune(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\'):
				i++
				arg.WriteRune(runes[i])
			default:
				arg.WriteRune(c)
			}
		case c == ' ' || c == '\t':
			if inArg {
				args = append(args, arg.String())
				arg.Reset()
				inArg = false
			}
		case c == '\'' || c == '"':
			quote, inArg = c, true
		case c == '\\':
			if i+1 == len(runes) {
				return nil, errors.New("the line ends with a backslash")
			}
			i++
			arg.WriteRune(runes[i])
			inArg = true
		default:
			arg.WriteRune(c)
			inArg = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("the line has an unclosed %c quote", quote)
	}
	if inArg {
		args = append(args, arg.String())
	}
	return args, nil
}

// complete completes the word before pos in line: a group or command name, an issuing CA after
// context use, or an option of the active context after context set, add and delete.
func complete(t *term.Terminal, line string, pos int) (string, int, bool) {
	before := line[:pos]
	words := strings.Fields(before)
	partial := ""
	if len(words) > 0 && !strings.HasSuffix(before, " ") {
		partial, words = words[len(words)-1], words[:len(words)-1]
	}
	groups := append(slices.Clone(commands), contextGroup)
	var candidates []string
	switch {
	case len(words) == 0:
		for _, g := range groups {
			candidates = append(candidates, g.Name)
		}
		candidates = append(candidates, "help", "exit", "quit")
	case len(words) == 1:
		if i := slices.IndexFunc(groups, func(c cli.Command) bool { return c.Name == words[0] }); i >= 0 {
			for _, c := range groups[i].Sub {
				candidates = append(candidates, c.Name)
			}
		}
	case len(words) == 2 && words[0] == "context" && words[1] == "use" && sessionRoot != "":
		candidates = slices.DeleteFunc(sessionCAs(), func(id string) bool { return id == "" })
	case len(words) == 2 && words[0] == "context" && slices.Contains([]string{"set", "add", "delete"}, words[1]) &&
		sessionRoot != "":
		if cfg, err := simpleca.LoadConfig(sessionRoot); err == nil {
			for key := range cfg.ContextValues(sessionCA) {
				candidates = append(candidates, strings.ReplaceAll(key, "_", "-"))
			}
		}
	}
	candidates = slices.DeleteFunc(candidates, func(c string) bool { return !strings.HasPrefix(c, partial) })
	slices.Sort(candidates)
	if len(candidates) == 0 {
		return "", 0, false
	}
	word := candidates[0]
	if len(candidates) == 1 {
		word += " "
	} else {
		for _, c := range candidates[1:] {
			for !strings.HasPrefix(c, word) {
				word = word[:len(word)-1]
			}
		}
		if word == partial {
			fmt.Fprintf(t, "%s\n", strings.Join(candidates, "  "))
			return "", 0, false
		}
	}
	head := before[:len(before)-len(partial)] + word
	return head + line[pos:], len(head), true
}

// requireHierarchy fails when the session has no CA hierarchy.
func requireHierarchy() error {
	if sessionRoot == "" {
		return errors.New("the session has no CA: run ca create, or context use --ca-dir DIR")
	}
	return nil
}

func runContextList(args []string) error {
	fs := cli.NewFlagSet("context list", "",
		"Lists the CAs of the hierarchy of the session, the root CA first, the active one marked with *.")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	if err := requireHierarchy(); err != nil {
		return err
	}
	for _, id := range sessionCAs() {
		mark := " "
		if id == sessionCA {
			mark = "*"
		}
		fmt.Printf("%s %-16s %s\n", mark, cmp.Or(id, "root"), filepath.Join(sessionRoot, id))
	}
	return nil
}

func runContextUse(args []string) error {
	fs := cli.NewFlagSet("context use", "[NAME]",
		"Makes the issuing CA NAME, or the root CA without NAME, the CA the commands of the session work\n"+
			"on; with --ca-dir, in the hierarchy of that CA directory.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA, of another hierarchy")
	rest, _, err := cli.ParseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	root, ca := sessionRoot, ""
	if *caDir != "" {
		if root, ca, err = findCA(*caDir); err != nil {
			return err
		}
	} else if err := requireHierarchy(); err != nil {
		return err
	}
	if len(rest) == 1 {
		if ca = rest[0]; ca == "" || !simpleca.KebabCaseRE.MatchString(ca) || !isCADir(filepath.Join(root, ca)) {
			return fmt.Errorf("%s has no issuing CA '%s'", root, rest[0])
		}
	}
	sessionRoot, sessionCA = root, ca
	return nil
}

// optionKey returns the key of simple-ca.json of the option name, or why it is refused.
func optionKey(name string) (string, error) {
	switch {
	case !simpleca.KebabCaseRE.MatchString(name):
		return "", fmt.Errorf("option name '%s' is not a kebab-case name without dashes, such as valid or otc-valid", name)
	case name == "ca-dir":
		return "", errors.New("ca-dir is the CA of the context itself; switch it with context use")
	}
	return strings.ReplaceAll(name, "-", "_"), nil
}

// editContext changes the option values of the active context with edit and saves simple-ca.json.
func editContext(edit func(values map[string][]string) error) error {
	if err := requireHierarchy(); err != nil {
		return err
	}
	cfg, err := simpleca.LoadConfig(sessionRoot)
	if err != nil {
		return err
	}
	values := maps.Clone(cfg.ContextValues(sessionCA))
	if values == nil {
		values = map[string][]string{}
	}
	if err := edit(values); err != nil {
		return err
	}
	cfg.SetContextValues(sessionCA, values)
	return cfg.Save()
}

func runContextSet(args []string) error {
	fs := cli.NewFlagSet("context set", "NAME VALUE...",
		"Sets the values of the option --NAME in the active context, replacing those it held.")
	rest, _, err := cli.ParseArgs(fs, args, 2, -1)
	if err != nil {
		return err
	}
	key, err := optionKey(rest[0])
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		values[key] = rest[1:]
		return nil
	})
}

func runContextAdd(args []string) error {
	fs := cli.NewFlagSet("context add", "NAME VALUE...",
		"Adds values to the option --NAME in the active context, for an option given several times.")
	rest, _, err := cli.ParseArgs(fs, args, 2, -1)
	if err != nil {
		return err
	}
	key, err := optionKey(rest[0])
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		values[key] = append(values[key], rest[1:]...)
		return nil
	})
}

func runContextDelete(args []string) error {
	fs := cli.NewFlagSet("context delete", "NAME [VALUE...]",
		"Deletes the values given from the option --NAME in the active context, or the option without them.")
	rest, _, err := cli.ParseArgs(fs, args, 1, -1)
	if err != nil {
		return err
	}
	key, err := optionKey(rest[0])
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		held, ok := values[key]
		if !ok {
			return fmt.Errorf("the context of %s has no option '%s'", cmp.Or(sessionCA, "root"), rest[0])
		}
		for _, v := range rest[1:] {
			i := slices.Index(held, v)
			if i < 0 {
				return fmt.Errorf("the option '%s' of the context of %s has no value '%s'", rest[0], cmp.Or(sessionCA, "root"), v)
			}
			held = slices.Delete(held, i, i+1)
		}
		if len(rest) == 1 || len(held) == 0 {
			delete(values, key)
		} else {
			values[key] = held
		}
		return nil
	})
}

func runContextShow(args []string) error {
	fs := cli.NewFlagSet("context show", "", "Shows the option values of the active context, as the options the commands take.")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	if err := requireHierarchy(); err != nil {
		return err
	}
	cfg, err := simpleca.LoadConfig(sessionRoot)
	if err != nil {
		return err
	}
	values := cfg.ContextValues(sessionCA)
	for _, key := range slices.Sorted(maps.Keys(values)) {
		for _, v := range values[key] {
			fmt.Printf("--%s %s\n", strings.ReplaceAll(key, "_", "-"), v)
		}
	}
	return nil
}

// fileHistory is the history of the session, oldest line first, kept in its file.
type fileHistory struct {
	path    string
	entries []string
}

// historyPath returns the file of the history: $SIMPLE_CA_HISTORY, else ~/.simple-ca_history.
func historyPath() string {
	if path := os.Getenv("SIMPLE_CA_HISTORY"); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".simple-ca_history")
}

// loadHistory reads the history file, keeping its last historyLimit lines; a file that cannot be
// read is warned about, and the session keeps its history in memory.
func loadHistory() *fileHistory {
	h := &fileHistory{path: historyPath()}
	if h.path == "" {
		return h
	}
	b, err := os.ReadFile(h.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		h.warn(err)
		return h
	}
	h.entries = strings.FieldsFunc(string(b), func(r rune) bool { return r == '\n' || r == '\r' })
	if len(h.entries) > historyLimit {
		h.entries = h.entries[len(h.entries)-historyLimit:]
		if err := os.WriteFile(h.path, []byte(strings.Join(h.entries, "\n")+"\n"), 0o600); err != nil {
			h.warn(err)
		}
	}
	return h
}

// warn reports a history file that cannot be used, once, and keeps the history in memory.
func (h *fileHistory) warn(err error) {
	fmt.Fprintf(os.Stderr, "warning: history: %v; the history of this session is not kept\n", err)
	h.path = ""
}

// Add appends a line to the history and to its file, but a blank line or one equal to the last.
func (h *fileHistory) Add(entry string) {
	entry = strings.TrimRight(entry, " \t")
	if strings.TrimSpace(entry) == "" || (len(h.entries) > 0 && h.entries[len(h.entries)-1] == entry) {
		return
	}
	h.entries = append(h.entries, entry)
	if len(h.entries) > historyLimit {
		h.entries = h.entries[1:]
	}
	if h.path == "" {
		return
	}
	f, err := os.OpenFile(h.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		_, err = f.WriteString(entry + "\n")
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		h.warn(err)
	}
}

// Len returns the number of lines of the history.
func (h *fileHistory) Len() int { return len(h.entries) }

// At returns a line of the history, 0 the newest.
func (h *fileHistory) At(idx int) string { return h.entries[len(h.entries)-1-idx] }

// init lets the commands work on the CA of the active context of the REPL.
func init() {
	cli.SessionCADir = func() string {
		if sessionRoot == "" {
			return ""
		}
		return filepath.Join(sessionRoot, sessionCA)
	}
}
