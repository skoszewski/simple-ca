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
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/acme"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/oidc"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
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

// statusWriter is a ResponseWriter keeping the status of the answer, for the request log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// runHTTPServer serves handler on the TCP port of address, over HTTPS with the certificate chain
// in the PEM file tlsCert and its key in tlsKey when they are given, logging each request with
// requestLog, until it fails; listening is called with the origin of the server, such as
// http://127.0.0.1:8080, once it listens.
func runHTTPServer(handler http.Handler, address string, port int, tlsCert, tlsKey string, listening func(origin string)) error {
	if address == "" {
		return errors.New("--address must not be empty; 0.0.0.0 is all interfaces")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("--port must be from 1 to 65535, got %d", port)
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "same-origin")
			if !requestLog {
				handler.ServeHTTP(w, r)
				return
			}
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			handler.ServeHTTP(sw, r)
			slog.Info("http.request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
				"client", clientAddr(r).String())
		})}
	if tlsCert != "" {
		chain, err := os.ReadFile(tlsCert)
		if err != nil {
			return err
		}
		var certificate tls.Certificate
		for block, rest := pem.Decode(chain); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == "CERTIFICATE" {
				certificate.Certificate = append(certificate.Certificate, block.Bytes)
			}
		}
		if len(certificate.Certificate) == 0 {
			return fmt.Errorf("no CERTIFICATE PEM block in %q", tlsCert)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return fmt.Errorf("%q: %w", tlsCert, err)
		}
		key, err := simpleca.LoadKey(tlsKey)
		if err != nil {
			return err
		}
		if !key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(leaf.PublicKey) {
			return fmt.Errorf("the key in %q does not match the certificate in %q", tlsKey, tlsCert)
		}
		certificate.PrivateKey = key
		server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}}
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	if server.TLSConfig != nil {
		listening("https://" + listener.Addr().String())
		return server.ServeTLS(listener, "", "")
	}
	listening("http://" + listener.Addr().String())
	return server.Serve(listener)
}

// templateFiles are the pages of serve, in the style of Tailwind CSS from its browser build:
// index.html, the list of the CAs; sign.html, the signing form; tokens.html and certs.html, the
// tokens and the certificates of the CAs, with the parts they share in webui-common.html;
// token-setup.html, the setup code page; token-describe.html, the page describing a token;
// downloads.html, the downloads page; apt.html, the apt page; oidc-callback.html, the page the OIDC provider sends the
// browser back to; and theme.html, the colours all of them share and the version line below each
// of them.
//
//go:embed templates/*.html
var templateFiles embed.FS

// pageTemplates are templateFiles parsed, each named after its file, with the functions json,
// which writes a value as JSON, version, the version of simple-ca, helpLink, the route of the
// help page, empty for an executable without it, docsLink, the route of the guides, empty
// unless they are served, downloadsLink, the route of the downloads page, and aptLink, the route
// of the apt page, each empty unless it is served.
var pageTemplates = template.Must(template.New("").Funcs(template.FuncMap{"json": func(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}, "version": version, "helpLink": func() string {
	if helpSite == nil {
		return ""
	}
	return helpPath
}, "docsLink": func() string {
	if !docsServed {
		return ""
	}
	return docsPath
}, "downloadsLink": func() string {
	if downloadsDir == "" {
		return ""
	}
	return downloadsPath
}, "aptLink": func() string {
	if packagesDir == "" {
		return ""
	}
	return aptPath
}}).ParseFS(templateFiles, "templates/*.html"))

// docsServed tells that serve shows the guides at docsPath.
var docsServed bool

// pageTheme returns the CSS of the colours of theme.json of the CA in caDir for its pages, empty
// without the file, or when it does not read, which is logged.
func pageTheme(caDir string) template.CSS {
	theme, err := loadTheme(caDir)
	if err != nil {
		slog.Error("serve.error", "dir", caDir, "error", err.Error())
	}
	css, _ := theme.css(filepath.Join(caDir, themeFile))
	return css
}

// indexCA is a CA of the index page: its subject, the fields of its certificate, its role,
// Root CA or Subordinate CA, its expiry as "expired" or the days left, whether fewer than 30 days
// are left, its SHA-256 fingerprint in four groups of eight bytes, its CRL, the URL path of its
// files, the URLs of its ACME directory and signing API, and the ID of its row, the name of an
// issuing CA.
type indexCA struct {
	cert.SubjectView
	Role, Issuer, Serial, NotBefore, NotAfter, Expiry, Key, CRL, Path, ACME, API, SignForm, ID string
	ExpiresSoon                                                                                bool
	Fingerprint                                                                                []string
}

// issuingCADir returns the directory of the issuing CA the path value ca of r names, and false
// when it names none.
func issuingCADir(rootDir string, r *http.Request) (string, bool) {
	ca := r.PathValue("ca")
	if !simpleca.IssuingCAExists(rootDir, ca) {
		return "", false
	}
	return filepath.Join(rootDir, ca), true
}

// newServeMux returns the handler serving an index page at /, the files of servedFiles of the
// root CA in rootDir at /NAME, those of each of its issuing CAs at /CA/NAME, and ca_bundle.pem of
// the root CA, also as the PKCS#7 file ca_bundle.p7b. The files are read on each request. With
// acme.domains in simple-ca.json, it also serves the ACME server of each CA whose key is there.
// The signing API and form take the client of a request from the X-Forwarded-For header of
// trustedProxies. An executable built with serve-markdown's page assets shows the help of the
// signing API at /help/ and, with docs, the guides at /docs/. With webui, it serves the token
// page at tokensPath and the certificate page at certsPath. The setup codes of the tokens are
// exchanged for them at /api/token-setup and on the page /token-setup, and with oidc in
// simple-ca.json, the ID tokens of the OIDC sign-in at /api/oidc-token. With downloadsDir, it
// serves the downloads page at downloadsPath, and with packagesDir the apt repository at aptPath.
func newServeMux(rootDir string, docs, webui bool) *http.ServeMux {
	docsServed = docs && docsSite != nil
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		var cas []indexCA
		var title string
		cfg, err := simpleca.LoadConfig(rootDir)
		if err != nil {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			http.Error(w, "could not read the configuration", http.StatusInternalServerError)
			return
		}
		origin := requestOrigin(r)
		dirs := []string{""}
		entries, _ := os.ReadDir(rootDir)
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && simpleca.FileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
				dirs = append(dirs, e.Name())
			}
		}
		for _, name := range dirs {
			dir := filepath.Join(rootDir, name)
			crt, err := simpleca.LoadCert(filepath.Join(dir, "ca_cert.pem"))
			if err != nil {
				slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
				http.Error(w, "could not read the CA certificates", http.StatusInternalServerError)
				return
			}
			fingerprint := sha256.Sum256(crt.Raw)
			ca := indexCA{
				SubjectView: cert.NewSubjectView(cert.NameString(crt.Subject)),
				Role:        "Root CA",
				Issuer:      cert.NameString(crt.Issuer),
				Serial:      cert.SerialHex(crt.SerialNumber),
				NotBefore:   crt.NotBefore.UTC().Format(cert.DisplayTimeFormat),
				NotAfter:    crt.NotAfter.UTC().Format(cert.DisplayTimeFormat),
				Expiry:      "expired",
				Key:         cert.KeyOf(crt).String(),
				Fingerprint: []string{cert.ColonHex(fingerprint[:8]), cert.ColonHex(fingerprint[8:16]),
					cert.ColonHex(fingerprint[16:24]), cert.ColonHex(fingerprint[24:])},
				Path: "/",
			}
			if left := time.Until(crt.NotAfter); left > 0 {
				days := int(math.Ceil(left.Hours() / 24))
				ca.Expiry = fmt.Sprintf("%d days left", days)
				if days == 1 {
					ca.Expiry = "1 day left"
				}
				ca.ExpiresSoon = days < 30
			}
			if name == "" {
				title = crt.Subject.CommonName
			} else {
				ca.Role, ca.Path, ca.ID = "Subordinate CA", "/"+name+"/", name
			}
			if len(cfg.ACME.Domains) > 0 && simpleca.FileExists(filepath.Join(dir, "ca_key.pem")) {
				ca.ACME = origin + ca.Path + "acme/directory"
			}
			if simpleca.FileExists(filepath.Join(dir, tokens.TokensFile)) && simpleca.FileExists(filepath.Join(dir, "ca_key.pem")) {
				ca.API = origin + ca.Path + "api/sign"
			}
			if simpleca.FileExists(filepath.Join(dir, "ca_key.pem")) {
				ca.SignForm = origin + ca.Path + "sign"
			}
			if b, err := os.ReadFile(filepath.Join(dir, "crl.pem")); err == nil {
				ca.CRL = "unreadable"
				if block, _ := pem.Decode(b); block != nil {
					if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
						ca.CRL = fmt.Sprintf("number %s, %d revoked, next update %s", crl.Number,
							len(crl.RevokedCertificateEntries), crl.NextUpdate.UTC().Format(cert.DisplayTimeFormat))
						if time.Now().After(crl.NextUpdate) {
							ca.CRL += " (overdue)"
						}
					}
				}
			}
			cas = append(cas, ca)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplates.ExecuteTemplate(w, "index.html", struct {
			Title, Script string
			WebUI         bool
			Theme         template.CSS
			CAs           []indexCA
		}{title, tailwindPath, webui, pageTheme(rootDir), cas}); err != nil {
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
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
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			http.Error(w, "could not read the file", http.StatusInternalServerError)
			return
		}
		if f.der {
			block, _ := pem.Decode(b)
			if block == nil {
				slog.Error("serve.error", "path", r.URL.Path, "error", "no PEM block in "+filepath.Join(dir, f.source))
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
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
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
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
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
			dir, ok := issuingCADir(rootDir, r)
			if !ok {
				http.NotFound(w, r)
				return
			}
			serve(w, r, dir, name)
		})
	}

	// The ACME server of the root CA at /acme/ and of each issuing CA at /CA/acme/.
	acmeServer := acme.NewServer()
	for _, p := range []string{"directory", "new-nonce", "new-account", "new-order", "revoke-cert", "acct/{id}",
		"acct/{id}/orders", "order/{id}", "order/{id}/finalize", "authz/{id}", "chall/{id}/{type}", "cert/{id}"} {
		mux.HandleFunc("/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			acmeServer.Handle(w, r, rootDir, rootDir, "/acme", strings.TrimPrefix(r.URL.Path, "/acme/"))
		})
		mux.HandleFunc("/{ca}/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			dir, ok := issuingCADir(rootDir, r)
			if !ok {
				http.NotFound(w, r)
				return
			}
			prefix := "/" + r.PathValue("ca") + "/acme"
			acmeServer.Handle(w, r, rootDir, dir, prefix, strings.TrimPrefix(r.URL.Path, prefix+"/"))
		})
	}

	// The exchange of the setup codes of the tokens of all the CAs at /api/token-setup, and on the
	// page /token-setup.
	mux.HandleFunc("POST /api/token-setup", func(w http.ResponseWriter, r *http.Request) {
		apiTokenSetup(w, r, rootDir)
	})
	mux.HandleFunc("GET /token-setup", func(w http.ResponseWriter, r *http.Request) {
		tokenSetupPage(w, r, rootDir)
	})
	mux.HandleFunc("POST /token-setup", func(w http.ResponseWriter, r *http.Request) {
		tokenSetupPage(w, r, rootDir)
	})

	// The links of the index page, by the token of the request.
	mux.HandleFunc("GET /api/links", func(w http.ResponseWriter, r *http.Request) {
		apiLinks(w, r, rootDir, webui)
	})

	// The OpenID Connect discovery document and the keys of the tokens of the root CA, and of each
	// issuing CA below /CA.
	for path, discovery := range map[string]bool{".well-known/openid-configuration": true, "jwks.json": false} {
		mux.HandleFunc("GET /"+path, func(w http.ResponseWriter, r *http.Request) {
			serveTokenIssuer(w, r, rootDir, "", discovery)
		})
		mux.HandleFunc("GET /{ca}/"+path, func(w http.ResponseWriter, r *http.Request) {
			serveTokenIssuer(w, r, rootDir, r.PathValue("ca"), discovery)
		})
	}

	// The page describing a token of any of the CAs, as token describe does.
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /token-describe", func(w http.ResponseWriter, r *http.Request) {
			tokenDescribePage(w, r, rootDir)
		})
	}

	// The OIDC sign-in.
	oidcClient := oidc.NewClient(rootDir)
	mux.HandleFunc("GET /api/oidc", oidcClient.APISettings)
	mux.HandleFunc("POST /api/oidc-token", oidcClient.APIToken)
	mux.HandleFunc("GET "+oidc.CallbackPath, oidcClient.CallbackPage)

	// The JWTs of the token types for the tokens of the root CA at /api/federation-token and of each
	// issuing CA at /CA/api/federation-token.
	mux.HandleFunc("POST /api/federation-token", func(w http.ResponseWriter, r *http.Request) {
		apiFederationToken(w, r, rootDir)
	})
	mux.HandleFunc("POST /{ca}/api/federation-token", func(w http.ResponseWriter, r *http.Request) {
		dir, ok := issuingCADir(rootDir, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		apiFederationToken(w, r, dir)
	})

	// The signing API of the root CA at /api/sign and of each issuing CA at /CA/api/sign.
	mux.HandleFunc("POST /api/sign", func(w http.ResponseWriter, r *http.Request) {
		apiSign(w, r, rootDir)
	})
	mux.HandleFunc("GET /api/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	mux.HandleFunc("POST /{ca}/api/sign", func(w http.ResponseWriter, r *http.Request) {
		dir, ok := issuingCADir(rootDir, r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		apiSign(w, r, dir)
	})
	mux.HandleFunc("GET /{ca}/api/sign", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := issuingCADir(rootDir, r); !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// /CA and /CA/ of an issuing CA redirect to its section of the index page.
	for _, pattern := range []string{"GET /{ca}", "GET /{ca}/{$}"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := issuingCADir(rootDir, r); !ok {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, (&url.URL{Path: "/", Fragment: r.PathValue("ca")}).String(), http.StatusFound)
		})
	}

	// The signing form of the root CA at /sign and of each issuing CA at /CA/sign.
	for _, method := range []string{"GET", "POST"} {
		mux.HandleFunc(method+" /sign", func(w http.ResponseWriter, r *http.Request) {
			signPage(w, r, rootDir, "/sign")
		})
		mux.HandleFunc(method+" /{ca}/sign", func(w http.ResponseWriter, r *http.Request) {
			dir, ok := issuingCADir(rootDir, r)
			if !ok {
				http.NotFound(w, r)
				return
			}
			signPage(w, r, dir, "/"+r.PathValue("ca")+"/sign")
		})
	}

	// The help at /help/, the guides at /docs/ and the token and certificate pages are served by a
	// mux in front of the routes of the CAs.
	top := http.NewServeMux()
	if helpSite != nil {
		top.Handle(helpPath, helpSite)
	}
	if docsServed {
		top.Handle(docsPath, docsSite)
	}
	if downloadsDir != "" {
		top.HandleFunc("GET "+downloadsPath+"{$}", func(w http.ResponseWriter, r *http.Request) {
			downloadsPage(w, r, rootDir)
		})
		top.HandleFunc("GET "+downloadsPath+"{file}", serveDownload)
		top.Handle("GET "+strings.TrimSuffix(downloadsPath, "/"), http.RedirectHandler(downloadsPath, http.StatusTemporaryRedirect))
	}
	if packagesDir != "" {
		top.Handle("GET "+aptPath, aptHandler)
		top.HandleFunc("GET "+aptPath+"{$}", func(w http.ResponseWriter, r *http.Request) {
			aptPage(w, r, rootDir)
		})
	}
	if webui {
		for path, scope := range map[string]string{tokensPath: "tokens", certsPath: "certs", auditPagePath: "audit"} {
			top.Handle(path, http.StripPrefix(strings.TrimSuffix(path, "/"), (&webuiServer{rootDir: rootDir, scope: scope}).mux()))
		}
	}
	top.Handle("/", mux)
	return top
}

// init sets the hooks of the ACME server and the OIDC sign-in.
func init() {
	acme.ClientAddr = clientAddr
	acme.Origin = requestOrigin
	oidc.ClientAddr = clientAddr
	oidc.StatusError = func(status int, format string, args ...any) error { return apiErr(status, format, args...) }
	oidc.ErrorStatus = func(err error) (int, string, bool) {
		var e *apiError
		if errors.As(err, &e) {
			return e.status, e.msg, true
		}
		return 0, "", false
	}
	oidc.Reply = webuiReply
	oidc.Fail = webuiFail
	oidc.Attempt = func(w http.ResponseWriter, r *http.Request, dir string, try func() error) error {
		return guard.attempt(w, r, dir, try)
	}
	oidc.Page = func(w io.Writer, rootDir, title string) error {
		return pageTemplates.ExecuteTemplate(w, "oidc-callback.html", struct {
			Title, Script string
			Theme         template.CSS
		}{title, tailwindPath, pageTheme(rootDir)})
	}
}
