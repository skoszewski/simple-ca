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
	"embed"
	"io/fs"
	"net/http"

	"github.com/skoszewski/serve-markdown/v3/render"
)

// ---- help and docs ----------------------------------------------------------

// helpPath is the route serve shows its help for the clients of the signing API under, and
// docsPath the route serve --docs shows the guides under.
const (
	helpPath = "/help/"
	docsPath = "/docs/"
)

// helpPages is the help serve shows: how a client requests a certificate.
//
//go:embed help
var helpPages embed.FS

// docsPages are the guides of docs/, with the walkthroughs of docs/workload-identity/, which serve
// --docs shows.
//
//go:embed docs/*.md docs/workload-identity/*.md
var docsPages embed.FS

// docsMenu is the menu of the guides, in the order of the README.
var docsMenu = []render.MenuEntry{{Path: "usage.md"}, {Path: "directory-layout.md"},
	{Path: "configuration.md"}, {Path: "serve.md"}, {Path: "acme.md"}, {Path: "signing-api.md"},
	{Path: "oidc.md"}, {Label: "Workload identity federation", Entries: []render.MenuEntry{
		{Label: "Overview", Path: "workload-identity.md"}, {Label: "Google Cloud", Path: "workload-identity/google.md"},
		{Label: "Microsoft Entra ID", Path: "workload-identity/entra.md"}}}, {Path: "audit.md"}, {Path: "examples.md"}, {Path: "trust.md"}, {Path: "systemd.md"}, {Path: "docker.md"}, {Path: "simple-ca-mini.md"},
	{Path: "development.md"}}

// markdownAssets holds the browser files of serve-markdown's page, which ./build.mjs assets
// unpacks from the serve-markdown release in go.mod; without them it holds .gitkeep alone.
//
//go:embed all:assets/markdown
var markdownAssets embed.FS

// newPages returns the handler drawing the Markdown documents of directory in files under
// prefix with serve-markdown's render package, as options say, or nil
// for an executable built without the page's browser files.
func newPages(files embed.FS, directory, prefix string, options render.Options) http.Handler {
	assets, err := fs.Sub(markdownAssets, "assets/markdown")
	if err != nil {
		panic(err)
	}
	if _, err := fs.Stat(assets, "page.js"); err != nil {
		return nil
	}
	pages, err := fs.Sub(files, directory)
	if err != nil {
		panic(err)
	}
	options.Prefix, options.Assets, options.Banner = prefix, assets, "simple-ca "+version()
	return render.New(pages, options)
}

// helpSite is the handler of helpPath, and docsSite of docsPath; each is nil for an executable
// built without the page's browser files.
var (
	helpSite = newPages(helpPages, "help", helpPath, render.Options{Search: render.IndexSearch{"index.md"},
		Outline: render.DefaultOutline})
	docsSite = newPages(docsPages, "docs", docsPath, render.Options{Search: render.IndexSearch{"usage.md"},
		Menu: docsMenu, List: render.DefaultList, Outline: render.DefaultOutline})
)
