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

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestCAURLOption(t *testing.T) {
	for _, option := range []string{"--ca-url", "--ca-publish-base-url"} {
		caDir := t.TempDir()
		if err := run([]string{"ca", "create", "--ca-dir", caDir, option, "http://pki.example.com", "Test CA"}); err != nil {
			t.Fatalf("ca create %s: %v", option, err)
		}
		cfg, err := simpleca.LoadConfig(caDir)
		if err != nil || cfg.CAPublishBaseURL != "http://pki.example.com" {
			t.Fatalf("ca_publish_base_url after ca create %s: %q, %v", option, cfg.CAPublishBaseURL, err)
		}
	}

	// The usage lists --ca-url and leaves out its former name.
	fs := NewFlagSet("ca create", "CA_NAME", "Create a root or issuing CA.")
	url := fs.String("ca-url", "", "base `URL`")
	fs.StringVar(url, "ca-publish-base-url", "", "former name of --ca-url")
	fs.Int("days", 3650, "validity period in `days`")
	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()
	if !strings.Contains(out.String(), "-ca-url URL") || strings.Contains(out.String(), "publish") ||
		!strings.Contains(out.String(), "(default 3650)") {
		t.Fatalf("usage:\n%s\nwant --ca-url and the defaults, without --ca-publish-base-url", out.String())
	}
}
