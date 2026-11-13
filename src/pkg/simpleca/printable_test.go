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

import "testing"

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"CN=web.example.com, O=Lab":               "CN=web.example.com, O=Lab",
		"\u0141\u00f3d\u017a \"quoted\" 'single'": "\u0141\u00f3d\u017a \"quoted\" 'single'",
		"a\nb\tc\rd":         `a\nb\tc\rd`,
		"red\x1b[31m":        `red\x1b[31m`,
		"zero\u200bwidth":    `zero\u200bwidth`,
		"bad\xffbyte":        `bad\xffbyte`,
		`C:\Users\ca`:        `C:\Users\ca`,
		"\uFFFD replacement": "\uFFFD replacement",
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %q, want %q", in, got, want)
		}
	}
}
