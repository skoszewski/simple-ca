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
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

// tailwindHandler serves tailwindJS at tailwindPath, where the pages of serve and of the webuis
// load it from.
var tailwindHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(tailwindJS)
})

// runHTTPServer serves handler on the TCP port of address, over HTTPS with the certificate chain
// in the PEM file tlsCert and its key in tlsKey when they are given, logging each request, until
// it fails; listening is called with the origin of the server, such as http://127.0.0.1:8080, once
// it listens.
func runHTTPServer(handler http.Handler, address string, port int, tlsCert, tlsKey string, listening func(origin string)) error {
	if address == "" {
		return errors.New("--address must not be empty; 0.0.0.0 is all interfaces")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("--port must be from 1 to 65535, got %d", port)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
			handler.ServeHTTP(w, r)
		})}
	if tlsCert != "" {
		listening("https://" + listener.Addr().String())
		return server.ServeTLS(listener, tlsCert, tlsKey)
	}
	listening("http://" + listener.Addr().String())
	return server.Serve(listener)
}

// templateFiles are the pages of serve, token webui and cert webui, in the style of Tailwind CSS
// from its browser build: index.html, the list of the CAs; sign.html, the signing form;
// tokens.html and certs.html, the tokens and the certificates of the CAs, with the parts they
// share in webui-common.html; and theme.html, the colours all of them share.
//
//go:embed templates/*.html
var templateFiles embed.FS

// pageTemplates are templateFiles parsed, each named after its file.
var pageTemplates = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

// indexCA is a CA of the index page: its name, the CN of its subject or else the whole subject,
// the attributes of its subject, each a type and a value, the fields of its certificate, its role,
// Root CA or Subordinate CA, its expiry as "expired" or the days left, whether fewer than 30 days
// are left, its SHA-256 fingerprint in four groups of eight bytes, its CRL, the URL path of its
// files, the URLs of its ACME directory and signing API, and the ID of its row, the name of an
// issuing CA.
type indexCA struct {
	Name, Subject, Role, Issuer, Serial, NotBefore, NotAfter, Expiry, Key, CRL, Path, ACME, API, ID string
	SubjectAttributes                                                                               [][2]string
	ExpiresSoon                                                                                     bool
	Fingerprint                                                                                     []string
}

// newServeMux returns the handler serving an index page at /, the files of servedFiles of the
// root CA in rootDir at /NAME, those of each of its issuing CAs at /CA/NAME, and ca_bundle.pem of
// the root CA, also as the PKCS#7 file ca_bundle.p7b. The files are read on each request. With
// acme.domains in simple-ca.json, it also serves the ACME server of each CA whose key is there.
// The signing API and form take the client of a request from the X-Forwarded-For header of the
// trusted proxies. An executable built with serve-markdown's page assets shows the help of the
// signing API at /help/ and, with docs, the guides at /docs/.
func newServeMux(rootDir string, trusted []netip.Prefix, docs bool) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		var cas []indexCA
		var title string
		cfg, err := loadConfig(rootDir)
		if err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
			http.Error(w, "could not read the configuration", http.StatusInternalServerError)
			return
		}
		origin := "http://" + r.Host
		if r.TLS != nil {
			origin = "https://" + r.Host
		}
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
				Name:      cmp.Or(cert.Subject.CommonName, nameString(cert.Subject)),
				Subject:   nameString(cert.Subject),
				Role:      "Root CA",
				Issuer:    nameString(cert.Issuer),
				Serial:    serialHex(cert.SerialNumber),
				NotBefore: cert.NotBefore.UTC().Format(displayTimeFormat),
				NotAfter:  cert.NotAfter.UTC().Format(displayTimeFormat),
				Expiry:    "expired",
				Key:       keyDescription(cert),
				Fingerprint: []string{colonHex(fingerprint[:8]), colonHex(fingerprint[8:16]),
					colonHex(fingerprint[16:24]), colonHex(fingerprint[24:])},
				Path:              "/",
				SubjectAttributes: subjectAttributes(cert.Subject),
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
				ca.Role, ca.Path, ca.ID = "Subordinate CA", "/"+name+"/", name
			}
			if len(cfg.ACME.Domains) > 0 && fileExists(filepath.Join(dir, "ca_key.pem")) {
				ca.ACME = origin + ca.Path + "acme/directory"
			}
			if fileExists(filepath.Join(dir, tokensFile)) && fileExists(filepath.Join(dir, "ca_key.pem")) {
				ca.API = origin + ca.Path + "api/sign"
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
		help, guides := "", ""
		if helpSite != nil {
			help = helpPath
		}
		if docs && docsSite != nil {
			guides = docsPath
		}
		if err := pageTemplates.ExecuteTemplate(w, "index.html", struct {
			Title, Script, Help, Docs string
			CAs                       []indexCA
		}{title, tailwindPath, help, guides, cas}); err != nil {
			log.Printf("%s: %v", r.URL.Path, err)
		}
	})
	mux.Handle("GET "+tailwindPath, tailwindHandler)
	mux.Handle("GET /assets/webui/{file}", webuiScriptHandler)
	serve := func(w http.ResponseWriter, r *http.Request, dir, name string) {
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
				http.NotFound(w, r)
				return
			}
			serve(w, r, filepath.Join(rootDir, ca), name)
		})
	}

	// The ACME server of the root CA at /acme/ and of each issuing CA at /CA/acme/.
	acme := newACMEServer()
	for _, p := range []string{"directory", "new-nonce", "new-account", "new-order", "revoke-cert", "acct/{id}",
		"acct/{id}/orders", "order/{id}", "order/{id}/finalize", "authz/{id}", "chall/{id}/{type}", "cert/{id}"} {
		mux.HandleFunc("/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			acme.handle(w, r, rootDir, rootDir, "/acme", strings.TrimPrefix(r.URL.Path, "/acme/"))
		})
		mux.HandleFunc("/{ca}/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			ca := r.PathValue("ca")
			if strings.HasPrefix(ca, ".") || !fileExists(filepath.Join(rootDir, ca, "ca_cert.pem")) {
				http.NotFound(w, r)
				return
			}
			prefix := "/" + ca + "/acme"
			acme.handle(w, r, rootDir, filepath.Join(rootDir, ca), prefix, strings.TrimPrefix(r.URL.Path, prefix+"/"))
		})
	}

	// The signing API of the root CA at /api/sign and of each issuing CA at /CA/api/sign, under
	// the lock of the ACME server.
	mux.HandleFunc("POST /api/sign", func(w http.ResponseWriter, r *http.Request) {
		apiSign(w, r, rootDir, trusted, &acme.mu)
	})
	mux.HandleFunc("GET /api/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("POST /{ca}/api/sign", func(w http.ResponseWriter, r *http.Request) {
		ca := r.PathValue("ca")
		if strings.HasPrefix(ca, ".") || !fileExists(filepath.Join(rootDir, ca, "ca_cert.pem")) {
			http.NotFound(w, r)
			return
		}
		apiSign(w, r, filepath.Join(rootDir, ca), trusted, &acme.mu)
	})

	// /CA and /CA/ of an issuing CA redirect to its section of the index page.
	for _, pattern := range []string{"GET /{ca}", "GET /{ca}/{$}"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			ca := r.PathValue("ca")
			if strings.HasPrefix(ca, ".") || !fileExists(filepath.Join(rootDir, ca, "ca_cert.pem")) {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, (&url.URL{Path: "/", Fragment: ca}).String(), http.StatusFound)
		})
	}

	// The signing form of the root CA at /sign and of each issuing CA at /CA/sign.
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /sign", func(w http.ResponseWriter, r *http.Request) {
			signPage(w, r, rootDir, "/sign", trusted, &acme.mu)
		})
		mux.HandleFunc(method+" /{ca}/sign", func(w http.ResponseWriter, r *http.Request) {
			ca := r.PathValue("ca")
			if strings.HasPrefix(ca, ".") || !fileExists(filepath.Join(rootDir, ca, "ca_cert.pem")) {
				http.NotFound(w, r)
				return
			}
			signPage(w, r, filepath.Join(rootDir, ca), "/"+ca+"/sign", trusted, &acme.mu)
		})
	}

	// The help at /help/ and the guides at /docs/ are served by a mux in front of the routes of
	// the CAs.
	if helpSite == nil {
		return mux
	}
	top := http.NewServeMux()
	top.Handle(helpPath, helpSite)
	if docs && docsSite != nil {
		top.Handle(docsPath, docsSite)
	}
	top.Handle("/", mux)
	return top
}
