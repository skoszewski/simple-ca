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
	"unicode"

	"github.com/skoszewski/simple-ca/src/pkg/replline"
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
	cli.Session = true
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
	return setContext(rootDir, caID)
}

// setContext makes the CA caID of the hierarchy of the root CA in root, the root CA for "", the
// active context, and its directory the working directory.
func setContext(root, caID string) error {
	if err := os.Chdir(filepath.Join(root, caID)); err != nil {
		return err
	}
	sessionRoot, sessionCA = root, caID
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
		args, err := lineArgs(line)
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
		args, err := lineArgs(line)
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

// runLine runs one command of the session, the args of lineArgs: the context group, help, or a
// command of the command line but serve.
func runLine(args []string) error {
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

// lineArgs returns the args of a line of the session, parsed by replline, a leading simple-ca
// dropped: the words naming the group and its command, then, when the line has more, -h for the
// word help alone, else its assignments as --NAME=VALUE, --, and its words.
func lineArgs(line string) ([]string, error) {
	elements, err := replline.Parse(line)
	if err != nil {
		return nil, err
	}
	if len(elements) > 0 && elements[0] == (replline.Element{Value: "simple-ca"}) {
		elements = elements[1:]
	}
	if len(elements) == 0 {
		return nil, nil
	}
	n := 1
	groups := append(slices.Clone(commands), contextGroup)
	if i := slices.IndexFunc(groups, func(c cli.Command) bool { return c.Name == elements[0].Value }); i >= 0 &&
		groups[i].Sub != nil && len(elements) > 1 {
		n = 2
	}
	var args []string
	for _, e := range elements[:n] {
		if e.Name != "" {
			return nil, fmt.Errorf("%s=%s comes after the command it is an option of", e.Name, e.Value)
		}
		args = append(args, e.Value)
	}
	if rest := elements[n:]; len(rest) == 1 && rest[0] == (replline.Element{Value: "help"}) {
		return append(args, "-h"), nil
	} else if len(rest) == 0 {
		return args, nil
	}
	var words []string
	for _, e := range elements[n:] {
		switch {
		case e.Name != "":
			args = append(args, "--"+e.Name+"="+e.Value)
		case strings.HasPrefix(e.Value, "-"):
			return nil, fmt.Errorf("'%s': the options of a session are NAME=VALUE, such as days=30", e.Value)
		default:
			words = append(words, e.Value)
		}
	}
	return append(append(args, "--"), words...), nil
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
				name := strings.ReplaceAll(key, "_", "-")
				if words[1] != "delete" {
					name += "="
				}
				candidates = append(candidates, name)
			}
		}
	}
	candidates = slices.DeleteFunc(candidates, func(c string) bool { return !strings.HasPrefix(c, partial) })
	slices.Sort(candidates)
	if len(candidates) == 0 {
		return "", 0, false
	}
	word := candidates[0]
	if len(candidates) == 1 && !strings.HasSuffix(word, "=") {
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
		return errors.New("the session has no CA: run ca create, or context use DIR")
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
	fs := cli.NewFlagSet("context use", "[NAME | DIR]",
		"Makes the issuing CA NAME of the hierarchy, the root CA without an argument, or the CA in the\n"+
			"directory DIR, with its hierarchy, the CA the commands of the session work on; its directory\n"+
			"becomes the working directory.")
	rest, _, err := cli.ParseArgs(fs, args, 0, 1)
	if err != nil {
		return err
	}
	switch {
	case len(rest) == 0:
		if err := requireHierarchy(); err != nil {
			return err
		}
		return setContext(sessionRoot, "")
	case sessionRoot != "" && rest[0] != "" && simpleca.KebabCaseRE.MatchString(rest[0]) &&
		isCADir(filepath.Join(sessionRoot, rest[0])):
		return setContext(sessionRoot, rest[0])
	case isCADir(rest[0]):
		return placeCA(rest[0])
	case sessionRoot != "":
		return fmt.Errorf("'%s' is neither an issuing CA of %s nor a CA directory", rest[0], sessionRoot)
	}
	return fmt.Errorf("'%s' is not a CA directory", rest[0])
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

// contextArgs returns the NAME=VALUE pairs and the words of the args lineArgs built for a context
// command, printing the usage of fs for -h, without any, and for words unless words is true.
func contextArgs(fs *flag.FlagSet, args []string, words bool) ([][2]string, []string, error) {
	if slices.Equal(args, []string{"-h"}) {
		fs.Usage()
		return nil, nil, flag.ErrHelp
	}
	end := slices.Index(args, "--")
	if end < 0 {
		end = len(args)
	}
	var pairs [][2]string
	for _, arg := range args[:end] {
		name, value, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		pairs = append(pairs, [2]string{name, value})
	}
	rest := args[min(end+1, len(args)):]
	switch {
	case len(pairs)+len(rest) == 0:
		fmt.Fprintf(fs.Output(), "%s: wrong number of arguments\n", fs.Name())
	case len(rest) > 0 && !words:
		fmt.Fprintf(fs.Output(), "%s: '%s' is not NAME=VALUE\n", fs.Name(), rest[0])
	default:
		return pairs, rest, nil
	}
	fs.Usage()
	return nil, nil, cli.ErrUsage
}

func runContextSet(args []string) error {
	fs := cli.NewFlagSet("context set", "NAME=VALUE...",
		"Sets the values of the options NAME in the active context, replacing those they held; an option\n"+
			"named twice gets both values.")
	pairs, _, err := contextArgs(fs, args, false)
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		replaced := map[string]bool{}
		for _, p := range pairs {
			key, err := optionKey(p[0])
			if err != nil {
				return err
			}
			if !replaced[key] {
				values[key], replaced[key] = nil, true
			}
			values[key] = append(values[key], p[1])
		}
		return nil
	})
}

func runContextAdd(args []string) error {
	fs := cli.NewFlagSet("context add", "NAME=VALUE...",
		"Adds values to the options NAME in the active context, for an option given several times.")
	pairs, _, err := contextArgs(fs, args, false)
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		for _, p := range pairs {
			key, err := optionKey(p[0])
			if err != nil {
				return err
			}
			values[key] = append(values[key], p[1])
		}
		return nil
	})
}

func runContextDelete(args []string) error {
	fs := cli.NewFlagSet("context delete", "NAME... | NAME=VALUE...",
		"Deletes the options NAME, or with NAME=VALUE the value VALUE of the option NAME, from the active\n"+
			"context.")
	pairs, names, err := contextArgs(fs, args, true)
	if err != nil {
		return err
	}
	return editContext(func(values map[string][]string) error {
		ca := cmp.Or(sessionCA, "root")
		for _, name := range names {
			key, err := optionKey(name)
			if err != nil {
				return err
			}
			if _, ok := values[key]; !ok {
				return fmt.Errorf("the context of %s has no option '%s'", ca, name)
			}
			delete(values, key)
		}
		for _, p := range pairs {
			key, err := optionKey(p[0])
			if err != nil {
				return err
			}
			i := slices.Index(values[key], p[1])
			if i < 0 {
				return fmt.Errorf("the option '%s' of the context of %s has no value '%s'", p[0], ca, p[1])
			}
			if values[key] = slices.Delete(values[key], i, i+1); len(values[key]) == 0 {
				delete(values, key)
			}
		}
		return nil
	})
}

func runContextShow(args []string) error {
	fs := cli.NewFlagSet("context show", "", "Shows the option values of the active context, as NAME=VALUE.")
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
			// A value a word does not hold is quoted, with ' when it holds ", joining parts of both
			// kinds when it holds both quotes.
			switch {
			case v != "" && !strings.ContainsAny(v, "\"'=") && !strings.ContainsFunc(v, unicode.IsSpace):
			case !strings.Contains(v, `"`):
				v = `"` + v + `"`
			case !strings.Contains(v, "'"):
				v = "'" + v + "'"
			default:
				v = `"` + strings.ReplaceAll(v, `"`, `"'"'"`) + `"`
			}
			fmt.Printf("%s=%s\n", strings.ReplaceAll(key, "_", "-"), v)
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
