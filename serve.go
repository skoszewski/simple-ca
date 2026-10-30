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
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---- serve ------------------------------------------------------------------

// servedFiles are the files served for each CA, by URL name: the file of the CA directory they
// are read from, their content type, and whether they are served as the DER of its PEM block.
var servedFiles = map[string]struct {
	source, contentType string
	der                 bool
}{
	"ca_cert.crt": {"ca_cert.pem", "application/pkix-cert", true},
	"ca_cert.pem": {"ca_cert.pem", "application/x-pem-file", false},
	"crl.crl":     {"crl.pem", "application/pkix-crl", true},
	"crl.pem":     {"crl.pem", "application/x-pem-file", false},
}

var (
	oidPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// tailwindPath is the URL of the browser build of Tailwind CSS, tailwindJS, which the index page
// loads; it is dist/index.global.js of the npm package @tailwindcss/browser, under the MIT licence
// of assets/tailwindcss-browser-LICENSE.
const tailwindPath = "/assets/tailwindcss-browser-4.3.3.js"

//go:embed assets/tailwindcss-browser-4.3.3.js
var tailwindJS []byte

// indexTemplate is the index page, a list of the CAs of indexCA with links to their files, in the
// style of Tailwind CSS from its browser build.
var indexTemplate = template.Must(template.New("index").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{.Title}} - simple-ca</title>
    <script src="{{.Script}}"></script>
  </head>
  <body class="min-h-screen bg-slate-100 text-slate-900">
    <div class="mx-auto max-w-3xl px-4 py-10 sm:py-16">
      <div class="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-lg">
        <div class="bg-slate-900 px-6 py-4 text-slate-100">
          <h1 class="text-xl font-semibold">{{.Title}}</h1>
          <p class="mt-1 text-sm text-slate-300">CA certificates and certificate revocation lists, served by simple-ca</p>
        </div>
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-sky-200 bg-sky-50 px-6 py-4">
          <div>
            <h2 class="text-base font-semibold text-sky-950">CA bundle</h2>
            <p class="text-sm text-sky-900">The root CA and all its issuing CAs in one file, to install or trust as a whole</p>
          </div>
          <div class="flex flex-wrap gap-2">
            <a class="rounded-lg bg-sky-700 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-sky-600" href="/ca_bundle.p7b">CA bundle (P7B)</a>
            <a class="rounded-lg bg-sky-700 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-sky-600" href="/ca_bundle.pem">CA bundle (PEM)</a>
          </div>
        </div>
        <main class="divide-y divide-slate-200">
          {{- range .CAs}}
          <section class="space-y-2 px-6 py-5">
            <div class="flex flex-wrap items-baseline justify-between gap-2">
              <h2 class="text-lg font-semibold">{{.Subject}}</h2>
              <span class="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">{{.Role}}</span>
            </div>
            <dl class="grid grid-cols-1 gap-x-4 gap-y-1 text-sm sm:grid-cols-[9rem_1fr]">
              <dt class="text-slate-500">Issuer</dt>
              <dd>{{.Issuer}}</dd>
              <dt class="text-slate-500">Serial number</dt>
              <dd class="font-mono text-xs break-all sm:text-sm">{{.Serial}}</dd>
              <dt class="text-slate-500">Valid from</dt>
              <dd>{{.NotBefore}}</dd>
              <dt class="text-slate-500">Valid until</dt>
              <dd>{{.NotAfter}}
                <span class="ml-1 rounded-full px-2 py-0.5 text-xs font-medium {{if eq .Expiry "expired"}}bg-red-100 text-red-700{{else if .ExpiresSoon}}bg-amber-100 text-amber-800{{else}}bg-emerald-100 text-emerald-700{{end}}">{{.Expiry}}</span>
              </dd>
              <dt class="text-slate-500">Key</dt>
              <dd>{{.Key}}</dd>
              <dt class="text-slate-500">SHA-256</dt>
              <dd class="grid grid-cols-1 font-mono text-xs sm:grid-cols-[repeat(2,max-content)]">
                {{- range $i, $group := .Fingerprint}}<span class="whitespace-nowrap">{{$group}}{{if lt $i 3}}:{{end}}</span>{{end -}}
              </dd>
              <dt class="text-slate-500">CRL</dt>
              <dd>{{if .CRL}}{{.CRL}}{{else}}none yet{{end}}</dd>
            </dl>
            <div class="flex flex-wrap gap-2 pt-1">
              <a class="rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700" href="{{.Path}}ca_cert.crt">Certificate (DER)</a>
              <a class="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-100" href="{{.Path}}ca_cert.pem">Certificate (PEM)</a>
              {{- if .CRL}}
              <a class="rounded-lg bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700" href="{{.Path}}crl.crl">CRL (DER)</a>
              <a class="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-100" href="{{.Path}}crl.pem">CRL (PEM)</a>
              {{- end}}
            </div>
          </section>
          {{- end}}
        </main>
      </div>
    </div>
  </body>
</html>
`))

// indexCA is a CA of the index page: the fields of its certificate, its expiry as "expired" or the
// days left, whether fewer than 30 days are left, its SHA-256 fingerprint in four groups of eight
// bytes, its CRL, and the URL path of its files.
type indexCA struct {
	Subject, Role, Issuer, Serial, NotBefore, NotAfter, Expiry, Key, CRL, Path string
	ExpiresSoon                                                                bool
	Fingerprint                                                                []string
}

// newServeMux returns the handler serving an index page at /, the files of servedFiles of the
// root CA in rootDir at /NAME, those of each of its issuing CAs at /CA/NAME, and ca_bundle.pem of
// the root CA, also as the PKCS#7 file ca_bundle.p7b. The files are read on each request.
func newServeMux(rootDir string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		var cas []indexCA
		var title string
		dirs := []string{""}
		entries, _ := os.ReadDir(rootDir)
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && fileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
				dirs = append(dirs, e.Name())
			}
		}
		for _, name := range dirs {
			dir := filepath.Join(rootDir, name)
			cert, err := loadCert(filepath.Join(dir, "ca_cert.pem"))
			if err != nil {
				log.Printf("%s: %v", r.URL.Path, err)
				http.Error(w, "could not read the CA certificates", http.StatusInternalServerError)
				return
			}
			fingerprint := sha256.Sum256(cert.Raw)
			ca := indexCA{
				Subject:   nameString(cert.Subject),
				Role:      "root CA",
				Issuer:    nameString(cert.Issuer),
				Serial:    serialHex(cert.SerialNumber),
				NotBefore: cert.NotBefore.UTC().Format(displayTimeFormat),
				NotAfter:  cert.NotAfter.UTC().Format(displayTimeFormat),
				Expiry:    "expired",
				Key:       keyDescription(cert),
				Fingerprint: []string{colonHex(fingerprint[:8]), colonHex(fingerprint[8:16]),
					colonHex(fingerprint[16:24]), colonHex(fingerprint[24:])},
				Path: "/",
			}
			if left := time.Until(cert.NotAfter); left > 0 {
				days := int(math.Ceil(left.Hours() / 24))
				ca.Expiry = fmt.Sprintf("%d days left", days)
				if days == 1 {
					ca.Expiry = "1 day left"
				}
				ca.ExpiresSoon = days < 30
			}
			if name == "" {
				title = cert.Subject.CommonName
			} else {
				ca.Role, ca.Path = "issuing CA "+name, "/"+name+"/"
			}
			if b, err := os.ReadFile(filepath.Join(dir, "crl.pem")); err == nil {
				ca.CRL = "unreadable"
				if block, _ := pem.Decode(b); block != nil {
					if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
						ca.CRL = fmt.Sprintf("number %s, %d revoked, next update %s", crl.Number,
							len(crl.RevokedCertificateEntries), crl.NextUpdate.UTC().Format(displayTimeFormat))
						if time.Now().After(crl.NextUpdate) {
							ca.CRL += " (overdue)"
						}
					}
				}
			}
			cas = append(cas, ca)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := indexTemplate.Execute(w, struct {
			Title, Script string
			CAs           []indexCA
		}{title, tailwindPath, cas}); err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
		}
	})
	mux.HandleFunc("GET "+tailwindPath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Write(tailwindJS)
	})
	serve := func(w http.ResponseWriter, r *http.Request, dir, name string) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		f, ok := servedFiles[name]
		if !ok {
			f.source, f.contentType = name, "application/x-pem-file"
		}
		b, err := os.ReadFile(filepath.Join(dir, f.source))
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
			http.Error(w, "could not read the file", http.StatusInternalServerError)
			return
		}
		if f.der {
			block, _ := pem.Decode(b)
			if block == nil {
				log.Printf("%s: no PEM block in %s", r.URL.Path, filepath.Join(dir, f.source))
				http.Error(w, "could not read the file", http.StatusInternalServerError)
				return
			}
			b = block.Bytes
		}
		w.Header().Set("Content-Type", f.contentType)
		w.Write(b)
	}

	mux.HandleFunc("GET /ca_bundle.pem", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, rootDir, "ca_bundle.pem")
	})
	mux.HandleFunc("GET /ca_bundle.p7b", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		b, err := os.ReadFile(filepath.Join(rootDir, "ca_bundle.pem"))
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
			http.Error(w, "could not read the file", http.StatusInternalServerError)
			return
		}
		var certs []byte
		for rest := b; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certs = append(certs, block.Bytes...)
			}
		}

		// The certificates of ca_bundle.pem as a degenerate PKCS#7 SignedData of RFC 2315, with no
		// content and no signers.
		emptySet := asn1.RawValue{Tag: asn1.TagSet, IsCompound: true}
		signedData, err := asn1.Marshal(struct {
			Version          int
			DigestAlgorithms asn1.RawValue
			ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
			Certificates     asn1.RawValue
			SignerInfos      asn1.RawValue
		}{
			Version:          1,
			DigestAlgorithms: emptySet,
			ContentInfo:      struct{ ContentType asn1.ObjectIdentifier }{oidPKCS7Data},
			Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
			SignerInfos:      emptySet,
		})
		if err == nil {
			b, err = asn1.Marshal(struct {
				ContentType asn1.ObjectIdentifier
				Content     asn1.RawValue
			}{oidPKCS7SignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signedData}})
		}
		if err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
			http.Error(w, "could not build the file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pkcs7-certificates")
		w.Write(b)
	})
	for name := range servedFiles {
		mux.HandleFunc("GET /"+name, func(w http.ResponseWriter, r *http.Request) {
			serve(w, r, rootDir, name)
		})
		mux.HandleFunc("GET /{ca}/"+name, func(w http.ResponseWriter, r *http.Request) {
			ca := r.PathValue("ca")
			if strings.HasPrefix(ca, ".") || !fileExists(filepath.Join(rootDir, ca, "ca_cert.pem")) {
				log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
				http.NotFound(w, r)
				return
			}
			serve(w, r, filepath.Join(rootDir, ca), name)
		})
	}
	return mux
}
