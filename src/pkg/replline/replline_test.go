package replline

import (
	"errors"
	"slices"
	"testing"
)

// w is a word, a an assignment.
func w(v string) Element    { return Element{Value: v} }
func a(n, v string) Element { return Element{Name: n, Value: v} }

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []Element
	}{
		// Words.
		{"empty line", "", nil},
		{"blank line", " \t ", nil},
		{"one word", "cert", []Element{w("cert")}},
		{"several words", "cert pfx web.example.com", []Element{w("cert"), w("pfx"), w("web.example.com")}},
		{"tabs and runs of spaces", "cert \t  pfx\t\tweb", []Element{w("cert"), w("pfx"), w("web")}},
		{"leading and trailing space", "  cert pfx  ", []Element{w("cert"), w("pfx")}},
		{"bare punctuation", "10.0.0.0/8 cert:create a-b_c", []Element{w("10.0.0.0/8"), w("cert:create"), w("a-b_c")}},

		// Assignments.
		{"assignment", "days=90", []Element{a("days", "90")}},
		{"repeated names", "san=a san=b", []Element{a("san", "a"), a("san", "b")}},
		{"words and assignments in order", "cert create web days=90 extra",
			[]Element{w("cert"), w("create"), w("web"), a("days", "90"), w("extra")}},

		// Quoting.
		{"quoted word", `"my host"`, []Element{w("my host")}},
		{"single-quoted word", `'my host'`, []Element{w("my host")}},
		{"double quotes hold a single quote", `note="it's"`, []Element{a("note", "it's")}},
		{"single quotes hold a double quote", `note='say "hi"'`, []Element{a("note", `say "hi"`)}},
		{"= and spaces inside quotes", `subject="CN=My Host, O=Example"`, []Element{a("subject", "CN=My Host, O=Example")}},
		{"quoted word holding = and spaces", `"a = b"`, []Element{w("a = b")}},
		{"empty double-quoted value", `password=""`, []Element{a("password", "")}},
		{"empty single-quoted value", `password=''`, []Element{a("password", "")}},
		{"empty quoted word", `x "" y`, []Element{w("x"), w(""), w("y")}},
		{"joined parts of a word", `ab"c d"e`, []Element{w("abc de")}},
		{"joined quotes of both kinds", `"it's"' a "test"'`, []Element{w(`it's a "test"`)}},
		{"joined parts of a value", `note=a"b c"'d'`, []Element{a("note", "ab cd")}},
		{"literal backslash", `out=C:\certs\web.pfx`, []Element{a("out", `C:\certs\web.pfx`)}},
		{"literal backslash in quotes", `out="C:\new dir\x"`, []Element{a("out", `C:\new dir\x`)}},
		{"non-ASCII runes", "note=\"za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105\"",
			[]Element{a("note", "za\u017c\u00f3\u0142\u0107 g\u0119\u015bl\u0105")}},
		{"tab inside quotes", "note=\"a\tb\"", []Element{a("note", "a\tb")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.line)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.line, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Parse(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		column int
	}{
		{"spaces around =", `days = 90`, 6},
		{"space after =", `days= 90`, 5},
		{"space before =", `days =90`, 6},
		{"tab before =", "days\t=90", 6},
		{"= twice with spaces", `a = = b`, 3},
		{"space after = at the end", `a= `, 2},
		{"double quote not closed", `note="abc`, 6},
		{"single quote not closed", `x 'abc`, 3},
		{"a single quote inside single quotes", `note='it's'`, 11},
		{"no name", `=x`, 1},
		{"quoted name", `"a"=x`, 1},
		{"partly quoted name", `a"b"=x`, 1},
		{"no value at the end", `a=`, 2},
		{"space after = after a word", `cert a= b`, 7},
		{"second = in a value", `a=b=c`, 4},
		{"non-ASCII column", "\u017c\u00f3\u0142w=", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.line)
			var perr *Error
			if !errors.As(err, &perr) {
				t.Fatalf("Parse(%q) = %q, %v; want an *Error", tt.line, got, err)
			}
			if perr.Column != tt.column {
				t.Errorf("Parse(%q): %v; want column %d", tt.line, err, tt.column)
			}
		})
	}
}
