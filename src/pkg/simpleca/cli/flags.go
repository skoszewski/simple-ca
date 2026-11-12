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
	"cmp"
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// HiddenFlags are the former names of options, accepted as aliases and left out of the usage, by
// subcommand, those of every subcommand under "".
var HiddenFlags = map[string][]string{"": {"ca-publish-base-url"}}

// NewFlagSet returns the flag set of the subcommand name, whose usage names its arguments and
// summary, and its options without its HiddenFlags.
func NewFlagSet(name, arguments, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(Program+" "+name, flag.ContinueOnError)
	fs.Usage = func() {
		line := strings.TrimSpace(Program + " " + name + " [options] " + arguments)
		fmt.Fprintf(fs.Output(), "Usage: %s\n\n%s\n\nOptions:\n", line, summary)
		shown := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
		shown.SetOutput(fs.Output())
		fs.VisitAll(func(f *flag.Flag) {
			if !slices.Contains(HiddenFlags[""], f.Name) && !slices.Contains(HiddenFlags[name], f.Name) {
				shown.Var(f.Value, f.Name, f.Usage)
				shown.Lookup(f.Name).DefValue = f.DefValue
			}
		})
		shown.PrintDefaults()
	}
	return fs
}

// ParseArgs parses the options of a subcommand, which come before its arguments, and checks that
// it was given from minArgs to maxArgs arguments, maxArgs -1 for any number. An option not given
// takes the values of the context of its CA in simple-ca.json. It returns the arguments and the
// names of the options given or taken from the context.
func ParseArgs(fs *flag.FlagSet, args []string, minArgs, maxArgs int) ([]string, map[string]bool, error) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil, err
		}
		return nil, nil, ErrUsage
	}
	if fs.NArg() < minArgs || (maxArgs >= 0 && fs.NArg() > maxArgs) {
		fmt.Fprintf(fs.Output(), "%s: wrong number of arguments\n", fs.Name())
		fs.Usage()
		return nil, nil, ErrUsage
	}
	if err := applyContext(fs); err != nil {
		return nil, nil, err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	return fs.Args(), given, nil
}

// applyContext sets each option of fs not given that the context of its CA holds, the CA of its
// --ca-dir, once for each value; a command without --ca-dir, or outside a CA, takes none.
func applyContext(fs *flag.FlagSet) error {
	caDirFlag := fs.Lookup("ca-dir")
	if caDirFlag == nil {
		return nil
	}
	rootDir, caID, err := simpleca.LocateCA(ResolveCADir(caDirFlag.Value.String()))
	if err != nil {
		return nil
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return err
	}
	values := cfg.ContextValues(caID)
	if len(values) == 0 {
		return nil
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, key := range slices.Sorted(maps.Keys(values)) {
		name := strings.ReplaceAll(key, "_", "-")
		if name == "ca-dir" || given[name] || fs.Lookup(name) == nil {
			continue
		}
		for _, value := range values[key] {
			if err := fs.Set(name, value); err != nil {
				return fmt.Errorf("context value '%s' of the option '%s' of %s: %w", value, name, cmp.Or(caID, "root"), err)
			}
		}
	}
	return nil
}

// durationFlag is a flag.Value of a duration in the form simpleca.ParseDuration reads.
type durationFlag time.Duration

func (f *durationFlag) String() string { return simpleca.DurationText(time.Duration(*f)) }

func (f *durationFlag) Set(s string) error {
	d, err := simpleca.ParseDuration(s)
	if err == nil {
		*f = durationFlag(d)
	}
	return err
}

// DurationVar defines the duration flag name of fs, with the default value, and returns where
// it is stored.
func DurationVar(fs *flag.FlagSet, name string, value time.Duration, usage string) *time.Duration {
	fs.Var((*durationFlag)(&value), name, usage)
	return &value
}

// usageFlags defines the --eku and --ku options of fs and returns the extended key usages and
// key usages they are given.
func usageFlags(fs *flag.FlagSet) (ekus, kus *[]string) {
	ekus, kus = new([]string), new([]string)
	fs.Func("eku", "extended key `usage` added to those of the type, a name such as clientAuth or a\n"+
		"numeric OID; may be specified multiple times", func(s string) error {
		*ekus = append(*ekus, s)
		return nil
	})
	fs.Func("ku", "comma-separated key `usages` added to those of the type, such as\n"+
		"digitalSignature,keyEncipherment; may be specified multiple times", func(s string) error {
		for _, ku := range strings.Split(s, ",") {
			ku = strings.TrimSpace(ku)
			if ku == "" {
				return fmt.Errorf("empty key usage in '%s'", s)
			}
			*kus = append(*kus, ku)
		}
		return nil
	})
	return ekus, kus
}
