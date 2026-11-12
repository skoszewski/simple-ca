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

package acme

import (
	"crypto/x509"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// init sets ClientAddr and Origin, which the program serving ACME sets, to the address of the
// peer and the origin of the connection.
func init() {
	ClientAddr = func(r *http.Request) netip.Addr {
		ap, _ := netip.ParseAddrPort(r.RemoteAddr)
		return ap.Addr()
	}
	Origin = func(r *http.Request) string {
		if r.TLS != nil {
			return "https://" + r.Host
		}
		return "http://" + r.Host
	}
}

// testMux serves the ACME server of the root CA in rootDir at /acme/ and of its issuing CAs at
// /CA/acme/, as serve does.
func testMux(rootDir string) http.Handler {
	s := NewServer()
	mux := http.NewServeMux()
	for _, p := range []string{"directory", "new-nonce", "new-account", "new-order", "revoke-cert", "acct/{id}",
		"acct/{id}/orders", "order/{id}", "order/{id}/finalize", "authz/{id}", "chall/{id}/{type}", "cert/{id}"} {
		mux.HandleFunc("/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			s.Handle(w, r, rootDir, rootDir, "/acme", strings.TrimPrefix(r.URL.Path, "/acme/"))
		})
		mux.HandleFunc("/{ca}/acme/"+p, func(w http.ResponseWriter, r *http.Request) {
			prefix := "/" + r.PathValue("ca") + "/acme"
			s.Handle(w, r, rootDir, filepath.Join(rootDir, r.PathValue("ca")), prefix, strings.TrimPrefix(r.URL.Path, prefix+"/"))
		})
	}
	return mux
}

// rootPool returns a pool of the certificate of the root CA in caDir.
func rootPool(t *testing.T, caDir string) *x509.CertPool {
	t.Helper()
	root, err := simpleca.LoadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}

// verifyCert verifies the certificate cert against the CA bundle with openssl.
func verifyCert(t *testing.T, bundle, cert string) {
	t.Helper()
	out, err := exec.Command("openssl", "verify", "-CAfile", bundle, cert).CombinedOutput()
	if err != nil {
		t.Fatalf("certificate verification failed for %s:\n%s", cert, out)
	}
}
