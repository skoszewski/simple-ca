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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/cli"
)

// ---- audit commands ---------------------------------------------------------

// runAuditList runs audit list.
func runAuditList(args []string) error {
	fs := cli.NewFlagSet("audit list", "",
		"Print the records of the audit log of the root CA of the CA in --ca-dir, in the order they\n"+
			"were written, those of the filters given alone.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	event := fs.String("event", "", "`event`, such as cert.issue, or the start of events, such as token.")
	ca := fs.String("ca", "", "issuing CA `name`; empty for the root CA")
	actor := fs.String("actor", "", "`actor`: an OS user, a token name, an OIDC user or an ACME account")
	since := fs.String("since", "", "records from this `time` on: RFC 3339, such as 2026-11-03T21:00:00Z, or a date")
	until := fs.String("until", "", "records before this `time`: RFC 3339 or a date")
	_, given, err := cli.ParseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	parse := func(option, value string) (time.Time, error) {
		for _, layout := range []string{time.RFC3339, time.DateOnly} {
			if t, err := time.Parse(layout, value); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("--%s '%s' is not an RFC 3339 time or a date such as 2026-11-03", option, value)
	}
	var from, to time.Time
	if *since != "" {
		if from, err = parse("since", *since); err != nil {
			return err
		}
	}
	if *until != "" {
		if to, err = parse("until", *until); err != nil {
			return err
		}
	}
	rootDir, _, err := simpleca.LocateCA(cli.ResolveCADir(*caDir))
	if err != nil {
		return err
	}
	entries, err := simpleca.ReadAudit(rootDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch {
		case *event != "" && e.Event != *event && !(strings.HasSuffix(*event, ".") && strings.HasPrefix(e.Event, *event)):
		case given["ca"] && e.CA != *ca:
		case *actor != "" && !slices.Contains(e.Fields, [2]string{"actor", *actor}):
		case !from.IsZero() && e.Time.Before(from):
		case !to.IsZero() && !e.Time.Before(to):
		default:
			fmt.Println(e.Line)
		}
	}
	return nil
}
