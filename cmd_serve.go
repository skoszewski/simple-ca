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
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// ---- serve ------------------------------------------------------------------

// runServe runs serve until it fails or is interrupted.
func runServe(args []string) error {
	fs := newFlagSet("serve", "", "Serve the certificates and CRLs of the root CA of the CA in --ca-dir, and of its\n"+
		"issuing CAs, over HTTP.\n\n"+
		"With --webui, it also serves the token page at /tokens/, the certificate page at\n"+
		"/certificates/ and the audit page at /audit/. Sign in with a token that has the scope\n"+
		"tokens, certs or audit; a root CA token opens every CA, an issuing CA token only its own CA.\n\n"+
		"It logs in records of key=value pairs, as its audit records, to the systemd journal when\n"+
		"it runs under systemd, else to the standard error; the audit records also go to the\n"+
		"audit log. --request-log adds a record of each request.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	address := fs.String("address", "127.0.0.1", "`address` of the interface to listen on; 0.0.0.0 for all interfaces")
	port := fs.Int("port", 8080, "TCP `port` to listen on")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with the certificate chain in this PEM `file` (default: $SIMPLE_CA_TLS_CERT)")
	tlsKey := fs.String("tls-key", "", "private key of --tls-cert, a PEM `file` (default: $SIMPLE_CA_TLS_KEY)")
	docs := fs.Bool("docs", false, "serve the guides of simple-ca at /docs/")
	logRequests := fs.Bool("request-log", false, "log each request (default: serve.request_log of simple-ca.json)")
	webui := fs.Bool("webui", false, "serve the token page at /tokens/, the certificate page at /certificates/ and the\n"+
		"audit page at /audit/")
	var proxies []string
	fs.Func("trusted-proxy", "`address` or prefix of a proxy trusted to name the client in X-Forwarded-For; may be\n"+
		"specified multiple times (default: serve.trusted_proxies of simple-ca.json)", func(s string) error {
		proxies = append(proxies, s)
		return nil
	})
	_, given, err := parseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	if *address == "" {
		fmt.Fprintf(fs.Output(), "%s: --address must not be empty; 0.0.0.0 is all interfaces\n", fs.Name())
		fs.Usage()
		return errUsage
	}
	if *tlsCert, *tlsKey, err = resolveTLS(*tlsCert, *tlsKey); err != nil {
		return err
	}
	if *docs && docsSite == nil {
		return errors.New("--docs needs the browser files of serve-markdown's page, which this executable " +
			"was built without; see docs/development.md")
	}
	rootDir, _, err := locateCA(resolveCADir(*caDir))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(rootDir)
	if err != nil {
		return err
	}
	var keys []string
	if *tlsKey != "" {
		keys = append(keys, *tlsKey)
	}
	for _, id := range caIDs(rootDir) {
		if _, err := loadTheme(filepath.Join(rootDir, id)); err != nil {
			return err
		}
		keys = append(keys, filepath.Join(rootDir, id, "ca_key.pem"))
	}
	if err := readKeyPassphrase(keys...); err != nil {
		return err
	}
	if err := checkOIDC(rootDir, cfg); err != nil {
		return err
	}
	option := "--trusted-proxy"
	if !given["trusted-proxy"] {
		proxies, option = cfg.Serve.TrustedProxies, "serve.trusted_proxies of "+cfg.path
	}
	for _, s := range proxies {
		prefix, ok := parsePrefix(s)
		if !ok {
			return fmt.Errorf("%s: '%s' is not an IP address or a prefix such as 10.0.0.0/8", option, s)
		}
		trustedProxies = append(trustedProxies, prefix)
	}
	var kept time.Duration
	if cfg.Tokens.KeepExpired != "" {
		if kept, err = time.ParseDuration(cfg.Tokens.KeepExpired); err != nil || kept < 0 {
			return fmt.Errorf("tokens.keep_expired of %s: '%s' is not a duration such as 720h", cfg.path, cfg.Tokens.KeepExpired)
		}
	}
	requestLog = cfg.Serve.RequestLog
	if given["request-log"] {
		requestLog = *logRequests
	}

	// Every record of serve, of its log and the audit, goes to the systemd journal it runs under,
	// else to stderr, as the lines of TextHandler; so do the lines of the log package.
	logStream = streamStderr
	if journalConnected() {
		logStream = streamJournal
	}
	slog.SetDefault(slog.New(streamHandler{}))
	log.SetFlags(0)
	log.SetOutput(logWriter{})

	return runHTTPServer(newServeMux(rootDir, *docs, *webui), *address, *port, *tlsCert, *tlsKey, func(origin string) {
		slog.Info("serve.start", "version", version(), "root", rootDir, "origin", origin, "request_log", requestLog)
		pages := [][2]string{{"index", "/"}}
		if *webui {
			pages = append(pages, [2]string{"tokens", tokensPath}, [2]string{"certificates", certsPath},
				[2]string{"audit", auditPagePath})
		}
		if *docs && docsSite != nil {
			pages = append(pages, [2]string{"docs", docsPath})
		}
		if helpSite != nil {
			pages = append(pages, [2]string{"help", helpPath})
		}
		for _, p := range pages {
			slog.Info("serve.page", "page", p[0], "url", origin+p[1])
		}
		if *webui {
			if ip, err := netip.ParseAddr(*address); *tlsCert == "" && (err != nil || !ip.IsLoopback()) {
				slog.Warn("serve.warning", "message", "the pages are served over plain HTTP beyond this machine; "+
					"their tokens can be read on the network")
			}
		}

		// With tokens.keep_expired, the tokens of the root CA and its issuing CAs expired for
		// longer are removed on start and every tokensPurgeInterval.
		if cfg.Tokens.KeepExpired == "" {
			return
		}
		go func() {
			for {
				dirs := []string{rootDir}
				entries, _ := os.ReadDir(rootDir)
				for _, e := range entries {
					if e.IsDir() && fileExists(filepath.Join(rootDir, e.Name(), "ca_cert.pem")) {
						dirs = append(dirs, filepath.Join(rootDir, e.Name()))
					}
				}
				for _, d := range dirs {
					n, err := purgeTokens(d, kept)
					if err != nil {
						slog.Error("serve.error", "message", "could not remove the expired tokens", "dir", d, "error", err.Error())
					} else if n > 0 {
						audit(d, "token.purge", "count", n, "via", "serve")
					}
				}
				time.Sleep(tokensPurgeInterval)
			}
		}()
	})
}
