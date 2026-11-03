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
		"With --webui, it also serves the token page at /tokens/ and the certificate page at\n"+
		"/certificates/. Sign in with a token that has the scope tokens or certs; a root CA token\n"+
		"opens every CA, an issuing CA token only its own CA.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	address := fs.String("address", "127.0.0.1", "`address` of the interface to listen on; 0.0.0.0 for all interfaces")
	port := fs.Int("port", 8080, "TCP `port` to listen on")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with the certificate chain in this PEM `file` (default: $SIMPLE_CA_TLS_CERT)")
	tlsKey := fs.String("tls-key", "", "private key of --tls-cert, a PEM `file` (default: $SIMPLE_CA_TLS_KEY)")
	docs := fs.Bool("docs", false, "serve the guides of simple-ca at /docs/")
	webui := fs.Bool("webui", false, "serve the token page at /tokens/ and the certificate page at /certificates/")
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
	for _, id := range caIDs(rootDir) {
		if _, err := loadTheme(filepath.Join(rootDir, id)); err != nil {
			return err
		}
	}
	option := "--trusted-proxy"
	if !given["trusted-proxy"] {
		proxies, option = cfg.Serve.TrustedProxies, "serve.trusted_proxies of "+cfg.path
	}
	var trusted []netip.Prefix
	for _, s := range proxies {
		prefix, ok := parsePrefix(s)
		if !ok {
			return fmt.Errorf("%s: '%s' is not an IP address or a prefix such as 10.0.0.0/8", option, s)
		}
		trusted = append(trusted, prefix)
	}
	var kept time.Duration
	if cfg.Tokens.KeepExpired != "" {
		if kept, err = time.ParseDuration(cfg.Tokens.KeepExpired); err != nil || kept < 0 {
			return fmt.Errorf("tokens.keep_expired of %s: '%s' is not a duration such as 720h", cfg.path, cfg.Tokens.KeepExpired)
		}
	}
	return runHTTPServer(newServeMux(rootDir, trusted, *docs, *webui), *address, *port, *tlsCert, *tlsKey, func(origin string) {
		fmt.Printf("simple-ca %s serving the CAs of %s\n", version(), rootDir)
		// The URLs of the pages start at one column, after the longest label.
		pages := [][2]string{{"Index page:", "/"}}
		if *webui {
			pages = append(pages, [2]string{"Token page:", tokensPath}, [2]string{"Certificate page:", certsPath})
		}
		for _, p := range pages {
			fmt.Printf("%-18s%s%s\n", p[0], origin, p[1])
		}
		if *webui {
			if ip, err := netip.ParseAddr(*address); *tlsCert == "" && (err != nil || !ip.IsLoopback()) {
				fmt.Fprintln(os.Stderr, "warning: the token and certificate pages are served over plain HTTP beyond "+
					"this machine; their tokens can be read on the network")
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
						log.Printf("purging the tokens of %s: %v", d, err)
					} else if n > 0 {
						log.Printf("%d tokens of %s expired for longer than %s removed", n, d, cfg.Tokens.KeepExpired)
					}
				}
				time.Sleep(tokensPurgeInterval)
			}
		}()
	})
}
