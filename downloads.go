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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// downloadsPath is the route of the downloads page, and aptPath the route of the apt repository.
const (
	downloadsPath = "/downloads/"
	aptPath       = "/apt/"
)

// downloadsDir is the directory of serve --downloads, and packagesDir the apt repository of
// serve --packages; each is empty when it is not served.
var downloadsDir, packagesDir string

// sumSuffix ends the name of the file holding the SHA-256 of a download.
const sumSuffix = ".sha256"

// download is a file of the downloads page: its name, its size and its SHA-256.
type download struct {
	Name, Size, SHA256 string
}

// sumCheck is the outcome of checking a download against its sum file, valid while the size and
// modification time of both stay the same; digest is empty when the check failed.
type sumCheck struct {
	size, sumSize   int64
	modTime, sumMod time.Time
	digest          string
}

// sumChecks are the checks of the downloads by path, guarded by sumChecksMu.
var (
	sumChecksMu sync.Mutex
	sumChecks   = map[string]sumCheck{}
)

// checkDownload returns the SHA-256 and the size of the file name of root when the line of
// NAME.sha256, as sha256sum writes it, names the file with its SHA-256, and false otherwise.
func checkDownload(root *os.Root, name string) (string, int64, bool) {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, sumSuffix) || strings.ContainsAny(name, `/\`) {
		return "", 0, false
	}
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, false
	}
	sumInfo, err := root.Stat(name + sumSuffix)
	if err != nil || !sumInfo.Mode().IsRegular() {
		return "", 0, false
	}
	sumChecksMu.Lock()
	defer sumChecksMu.Unlock()
	key := filepath.Join(root.Name(), name)
	if c, ok := sumChecks[key]; ok && c.size == info.Size() && c.modTime.Equal(info.ModTime()) &&
		c.sumSize == sumInfo.Size() && c.sumMod.Equal(sumInfo.ModTime()) {
		return c.digest, c.size, c.digest != ""
	}
	c := sumCheck{size: info.Size(), modTime: info.ModTime(), sumSize: sumInfo.Size(), sumMod: sumInfo.ModTime()}
	digest, problem := "", ""
	b, err := root.ReadFile(name + sumSuffix)
	line := strings.TrimSuffix(string(b), "\n")
	switch {
	case err != nil:
		problem = err.Error()
	case len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') || strings.Contains(line, "\n"):
		problem = "the sum file is not one line of sha256sum"
	case line[66:] != name:
		problem = "the sum file names " + line[66:]
	default:
		f, err := root.Open(name)
		if err != nil {
			problem = err.Error()
			break
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			problem = err.Error()
		} else if digest = hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(digest, line[:64]) {
			digest, problem = "", "the SHA-256 of the file does not match the sum file"
		}
	}
	if problem != "" {
		slog.Warn("serve.warning", "message", "the download is not listed", "file", key,
			"error", problem)
	}
	c.digest = digest
	sumChecks[key] = c
	return digest, c.size, digest != ""
}

// downloadsPage writes the page of the files of downloadsDir that match their sum files.
func downloadsPage(w http.ResponseWriter, r *http.Request, rootDir string) {
	root, err := os.OpenRoot(downloadsDir)
	var entries []fs.DirEntry
	if err == nil {
		defer root.Close()
		entries, err = fs.ReadDir(root.FS(), ".")
	}
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the downloads", http.StatusInternalServerError)
		return
	}
	var files []download
	for _, e := range entries {
		digest, size, ok := checkDownload(root, e.Name())
		if !ok {
			continue
		}
		sizeText := fmt.Sprintf("%d B", size)
		for i, unit := range []string{"KiB", "MiB", "GiB"} {
			if size < 1<<(10*(i+1)) {
				break
			}
			sizeText = fmt.Sprintf("%.1f %s", float64(size)/float64(int64(1)<<(10*(i+1))), unit)
		}
		files = append(files, download{Name: e.Name(), Size: sizeText, SHA256: digest})
	}
	title := ""
	if caCert, err := simpleca.LoadCert(filepath.Join(rootDir, "ca_cert.pem")); err == nil {
		title = caCert.Subject.CommonName
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplates.ExecuteTemplate(w, "downloads.html", struct {
		Title, Script, Path string
		Theme               template.CSS
		Files               []download
	}{title, tailwindPath, downloadsPath, pageTheme(rootDir), files}); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// serveDownload sends the file of downloadsDir that the path value file names when it is listed
// on the downloads page, or the sum file of a listed file.
func serveDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	root, err := os.OpenRoot(downloadsDir)
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the downloads", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	if _, _, ok := checkDownload(root, strings.TrimSuffix(name, sumSuffix)); !ok {
		http.NotFound(w, r)
		return
	}
	f, err := root.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the file", http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(name, sumSuffix) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	}
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// aptPage writes the page telling the admin of a Debian or Ubuntu machine how to set up the apt
// repository of packagesDir, with the origin of the request and the packages of its Packages.
func aptPage(w http.ResponseWriter, r *http.Request, rootDir string) {
	root, err := os.OpenRoot(packagesDir)
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the packages", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	var packages []string
	index, _ := root.ReadFile("Packages")
	for line := range strings.Lines(string(index)) {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "Package: "); ok && !slices.Contains(packages, name) {
			packages = append(packages, name)
		}
	}
	slices.Sort(packages)
	_, keyErr := root.Stat("key.asc")
	origin := requestOrigin(r)
	commands := "BASE_URL=" + origin + "\n\n" +
		"sudo install -d -m 0755 /etc/apt/keyrings\n" +
		"sudo curl -fsSL -o /etc/apt/keyrings/simple-ca.asc \"$BASE_URL" + aptPath + "key.asc\"\n" +
		"echo \"deb [signed-by=/etc/apt/keyrings/simple-ca.asc] $BASE_URL" + strings.TrimSuffix(aptPath, "/") + " ./\" |\n" +
		"  sudo tee /etc/apt/sources.list.d/simple-ca.list\n" +
		"sudo apt-get update\n"
	if len(packages) > 0 {
		commands += "sudo apt-get install " + strings.Join(packages, " ") + "\n"
	}
	title := ""
	if caCert, err := simpleca.LoadCert(filepath.Join(rootDir, "ca_cert.pem")); err == nil {
		title = caCert.Subject.CommonName
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplates.ExecuteTemplate(w, "apt.html", struct {
		Title, Script, Commands string
		Theme                   template.CSS
		Packages                []string
		NoKey, PlainHTTP        bool
	}{title, tailwindPath, commands, pageTheme(rootDir), packages, keyErr != nil, strings.HasPrefix(origin, "http://")}); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}

// aptHandler serves the files and directories of packagesDir, opened on each request, below
// aptPath.
var aptHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot(packagesDir)
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the packages", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	http.StripPrefix(strings.TrimSuffix(aptPath, "/"), http.FileServerFS(root.FS())).ServeHTTP(w, r)
})
