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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

func TestACME(t *testing.T) {
	if _, err := exec.LookPath("lego"); err != nil {
		t.Skip("lego is not installed")
	}
	caDir := t.TempDir()
	tlsDir := t.TempDir()
	legoDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, simpleca.ConfigFile), []byte(`{"days": {"cert": 400}, "acme": {"domains": ["localhost"]}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", simpleca.ConfigFile, err)
	}
	if err := cert.MakeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := cert.MakeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := cert.MakeCert("localhost", nil, caDir, tlsDir, "server", 30, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: testMux(caDir), ErrorLog: log.New(io.Discard, "", 0)}
	go server.ServeTLS(listener, filepath.Join(tlsDir, "localhost_cert.pem"), filepath.Join(tlsDir, "localhost_key.pem"))
	defer server.Close()

	// The http-01 challenges are validated on a free port, where lego answers them.
	free, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	defer func(port int) { httpPort = port }(httpPort)
	httpPort = freePort

	directory := fmt.Sprintf("https://localhost:%d/servers/acme/directory", listener.Addr().(*net.TCPAddr).Port)
	lego := func(args ...string) (string, error) {
		cmd := exec.Command("lego", args...)
		cmd.Env = append(os.Environ(), "LEGO_CA_CERTIFICATES="+filepath.Join(caDir, "ca_cert.pem"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	common := []string{"--server", directory, "--path", legoDir, "--email", "test@example.com"}

	out, err := lego(append([]string{"run", "--accept-tos", "--domains", "localhost", "--http",
		"--http.address", fmt.Sprintf(":%d", freePort)}, common...)...)
	if err != nil {
		t.Fatalf("lego run: %v\n%s", err, out)
	}
	var certPath string
	filepath.WalkDir(legoDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Base(path) == "localhost.crt" {
			certPath = path
		}
		return nil
	})
	if certPath == "" {
		t.Fatalf("lego wrote no localhost.crt to %s:\n%s", legoDir, out)
	}
	verifyCert(t, filepath.Join(caDir, "ca_bundle.pem"), certPath)
	crt, err := simpleca.LoadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if crt.Subject.CommonName != "localhost" || !slices.Equal(crt.DNSNames, []string{"localhost"}) ||
		crt.Issuer.CommonName != "Servers CA" {
		t.Fatalf("certificate of %v %v by %v, want localhost by Servers CA", crt.Subject, crt.DNSNames, crt.Issuer)
	}
	if !slices.Contains(crt.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("extended key usage %v, want that of the server type", crt.ExtKeyUsage)
	}
	if days := crt.NotAfter.Sub(crt.NotBefore).Hours() / 24; days != 90 {
		t.Fatalf("the ACME certificate is valid for %v days, want the ACME default, 90, not days.cert", days)
	}
	entries, err := cert.ReadIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].Serial != cert.SerialHex(crt.SerialNumber) {
		t.Fatalf("index.txt of the issuing CA: %+v, %v, want the ACME certificate", entries, err)
	}
	if !simpleca.FileExists(filepath.Join(caDir, "servers", stateFile)) {
		t.Fatalf("no %s in the issuing CA directory", stateFile)
	}

	out, err = lego(append([]string{"run", "--accept-tos", "--domains", "www.example.org", "--http",
		"--http.address", fmt.Sprintf(":%d", freePort)}, common...)...)
	if err == nil || !strings.Contains(out, "rejectedIdentifier") {
		t.Fatalf("lego run for a name outside acme.domains: %v, want rejectedIdentifier:\n%s", err, out)
	}

	out, err = lego(append([]string{"certificates", "revoke", "--cert.name", "localhost", "--reason", "4"}, common...)...)
	if err != nil {
		t.Fatalf("lego certificates revoke: %v\n%s", err, out)
	}
	entries, err = cert.ReadIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].Status != "R" || !strings.HasSuffix(entries[0].Revoked, ",superseded") {
		t.Fatalf("index.txt after lego revoked: %+v, %v, want revoked, superseded", entries, err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(t, caDir)}}}
	origin := strings.TrimSuffix(directory, "/servers/acme/directory")
	resp, err := client.Get(origin + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"newOrder":"`+origin+`/acme/new-order"`) {
		t.Fatalf("GET /acme/directory of the root CA: %d\n%s", resp.StatusCode, body)
	}
}
