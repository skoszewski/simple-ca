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
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ---- serve ------------------------------------------------------------------

// runServe runs serve until it fails or is interrupted.
func runServe(args []string) error {
	fs := newFlagSet("serve", "", "Serve the certificates and CRLs of the root CA of the CA in --ca-dir, and of its\n"+
		"issuing CAs, over HTTP.")
	caDir := fs.String("ca-dir", "", "`directory` of the root CA or of one of its issuing CAs")
	address := fs.String("address", "127.0.0.1", "`address` of the interface to listen on; 0.0.0.0 for all interfaces")
	port := fs.Int("port", 8080, "TCP `port` to listen on")
	tlsCert := fs.String("tls-cert", "", "serve HTTPS with the certificate chain in this PEM `file`")
	tlsKey := fs.String("tls-key", "", "private key of --tls-cert, a PEM `file`")
	var proxies []string
	fs.Func("trusted-proxy", "`address` or prefix of a proxy whose X-Forwarded-For names the client of the\n"+
		"signing API; repeated for more (default: serve.trusted_proxies of simple-ca.json)", func(s string) error {
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
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("--port must be from 1 to 65535, got %d", *port)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be given together")
	}
	rootDir, _, err := locateCA(resolveCADir(*caDir))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(rootDir)
	if err != nil {
		return err
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
	listener, err := net.Listen("tcp", net.JoinHostPort(*address, strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	server := &http.Server{Handler: newServeMux(rootDir, trusted), ReadHeaderTimeout: 10 * time.Second}

	// The expired tokens of the root CA and its issuing CAs are removed on start and every
	// tokensPurgeInterval.
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
				n, err := purgeTokens(d)
				if err != nil {
					log.Printf("purging the tokens of %s: %v", d, err)
				} else if n > 0 {
					log.Printf("%d expired tokens of %s removed", n, d)
				}
			}
			time.Sleep(tokensPurgeInterval)
		}
	}()
	if *tlsCert != "" {
		fmt.Printf("Serving the CAs of %s on https://%s/\n", rootDir, listener.Addr())
		return server.ServeTLS(listener, *tlsCert, *tlsKey)
	}
	fmt.Printf("Serving the CAs of %s on http://%s/\n", rootDir, listener.Addr())
	return server.Serve(listener)
}
