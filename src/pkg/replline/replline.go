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

// Package replline splits a REPL line into words and NAME=VALUE assignments.
//
// Outside quotes, white space separates the elements of a line, an element holding '=' is an
// assignment, and white space next to that '=' is an error. A double-quoted part holds any rune
// but a double quote, a single-quoted part any rune but a single quote; nothing is escaped, and
// quoted and bare parts next to each other join into one.
package replline

import (
	"fmt"
	"strings"
	"unicode"
)

// Element is a word of a line, Name empty, or an assignment NAME=VALUE.
type Element struct {
	Name, Value string
}

// Error is a parse error at column Column of the line, counted in runes from 1.
type Error struct {
	Column int
	Msg    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("column %d: %s", e.Column, e.Msg)
}

// Parse splits line into its words and assignments, in the order given.
func Parse(line string) ([]Element, error) {
	runes := []rune(line)
	var elements []Element
	var buf strings.Builder

	// The element being read: its first column, 0 before it starts, the column of its '=', 0
	// without one, whether its name has a quote, and whether its value has started.
	var start, eq int
	var nameQuoted, valueStarted bool

	var quote rune
	var quoteCol int

	// end closes the element being read, if any.
	end := func() error {
		if start == 0 {
			return nil
		}
		if eq != 0 && !valueStarted {
			return &Error{eq, "the assignment needs a value; \"\" for an empty one"}
		}
		if eq == 0 {
			elements = append(elements, Element{Value: buf.String()})
		} else {
			elements[len(elements)-1].Value = buf.String()
		}
		buf.Reset()
		start, eq, nameQuoted, valueStarted = 0, 0, false, false
		return nil
	}

	for i := 0; i < len(runes); i++ {
		r, col := runes[i], i+1
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				buf.WriteRune(r)
			}

		case unicode.IsSpace(r):
			if err := end(); err != nil {
				return nil, err
			}

		case r == '=':
			switch {
			case i > 0 && unicode.IsSpace(runes[i-1]), i+1 < len(runes) && unicode.IsSpace(runes[i+1]):
				return nil, &Error{col, "no white space around '='"}
			case start == 0:
				return nil, &Error{col, "the assignment needs a name"}
			case eq != 0:
				return nil, &Error{col, "a value with '=' is quoted"}
			case nameQuoted:
				return nil, &Error{start, "the name of an assignment is not quoted"}
			}
			elements = append(elements, Element{Name: buf.String()})
			buf.Reset()
			eq = col

		default:
			if start == 0 {
				start = col
			}
			if eq != 0 {
				valueStarted = true
			}
			if r == '"' || r == '\'' {
				quote, quoteCol = r, col
				if eq == 0 {
					nameQuoted = true
				}
				continue
			}
			buf.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, &Error{quoteCol, fmt.Sprintf("the %c quote is not closed", quote)}
	}
	if err := end(); err != nil {
		return nil, err
	}
	return elements, nil
}
