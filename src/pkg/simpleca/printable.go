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

package simpleca

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Printable returns s for a listing, without quotes: each rune that is not printable, such as a
// line end, a tab, an escape or an invalid byte, is written as Go writes it in a quoted string,
// such as \n, \x1b or \u200b; the other runes, a backslash too, are kept.
func Printable(s string) string {
	var b strings.Builder
	for i, r := range s {
		var q string
		switch {
		case r == utf8.RuneError && !strings.HasPrefix(s[i:], string(utf8.RuneError)):
			q = strconv.Quote(s[i : i+1])
		case unicode.IsPrint(r):
			b.WriteRune(r)
			continue
		default:
			q = strconv.QuoteRune(r)
		}
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}
