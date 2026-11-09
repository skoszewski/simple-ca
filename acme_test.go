package main

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
)

func TestACME(t *testing.T) {
	if _, err := exec.LookPath("lego"); err != nil {
		t.Skip("lego is not installed")
	}
	caDir := t.TempDir()
	tlsDir := t.TempDir()
	legoDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(caDir, configFile), []byte(`{"days": {"cert": 400}, "acme": {"domains": ["localhost"]}}`), 0o644); err != nil {
		t.Fatalf("write %s: %v", configFile, err)
	}
	if err := makeCA(caDir, "Test CA", 3650, "", "", "rsa"); err != nil {
		t.Fatalf("makeCA: %v", err)
	}
	if err := makeCA(caDir, "Servers CA", 0, "servers", "", "rsa"); err != nil {
		t.Fatalf("makeCA issuing: %v", err)
	}
	if _, err := makeCert("localhost", nil, caDir, tlsDir, "server", 30, nil, nil, ""); err != nil {
		t.Fatalf("makeCert: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: newServeMux(caDir, false, false), ErrorLog: log.New(io.Discard, "", 0)}
	go server.ServeTLS(listener, filepath.Join(tlsDir, "localhost_cert.pem"), filepath.Join(tlsDir, "localhost_key.pem"))
	defer server.Close()

	// The http-01 challenges are validated on a free port, where lego answers them.
	free, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpPort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	defer func(port int) { acmeHTTPPort = port }(acmeHTTPPort)
	acmeHTTPPort = httpPort

	directory := fmt.Sprintf("https://localhost:%d/servers/acme/directory", listener.Addr().(*net.TCPAddr).Port)
	lego := func(args ...string) (string, error) {
		cmd := exec.Command("lego", args...)
		cmd.Env = append(os.Environ(), "LEGO_CA_CERTIFICATES="+filepath.Join(caDir, "ca_cert.pem"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	common := []string{"--server", directory, "--path", legoDir, "--email", "test@example.com"}

	out, err := lego(append([]string{"run", "--accept-tos", "--domains", "localhost", "--http",
		"--http.address", fmt.Sprintf(":%d", httpPort)}, common...)...)
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
	cert, err := loadCert(certPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if cert.Subject.CommonName != "localhost" || !slices.Equal(cert.DNSNames, []string{"localhost"}) ||
		cert.Issuer.CommonName != "Servers CA" {
		t.Fatalf("certificate of %v %v by %v, want localhost by Servers CA", cert.Subject, cert.DNSNames, cert.Issuer)
	}
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatalf("extended key usage %v, want that of the server type", cert.ExtKeyUsage)
	}
	if days := cert.NotAfter.Sub(cert.NotBefore).Hours() / 24; days != 90 {
		t.Fatalf("the ACME certificate is valid for %v days, want the ACME default, 90, not days.cert", days)
	}
	entries, err := readIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].serial != serialHex(cert.SerialNumber) {
		t.Fatalf("index.txt of the issuing CA: %+v, %v, want the ACME certificate", entries, err)
	}
	if !fileExists(filepath.Join(caDir, "servers", acmeStateFile)) {
		t.Fatalf("no %s in the issuing CA directory", acmeStateFile)
	}

	out, err = lego(append([]string{"run", "--accept-tos", "--domains", "www.example.org", "--http",
		"--http.address", fmt.Sprintf(":%d", httpPort)}, common...)...)
	if err == nil || !strings.Contains(out, "rejectedIdentifier") {
		t.Fatalf("lego run for a name outside acme.domains: %v, want rejectedIdentifier:\n%s", err, out)
	}

	out, err = lego(append([]string{"certificates", "revoke", "--cert.name", "localhost", "--reason", "4"}, common...)...)
	if err != nil {
		t.Fatalf("lego certificates revoke: %v\n%s", err, out)
	}
	entries, err = readIndex(filepath.Join(caDir, "servers"))
	if err != nil || len(entries) != 1 || entries[0].status != "R" || !strings.HasSuffix(entries[0].revoked, ",superseded") {
		t.Fatalf("index.txt after lego revoked: %+v, %v, want revoked, superseded", entries, err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool(t, caDir)}}}
	origin := strings.TrimSuffix(directory, "/servers/acme/directory")
	resp, err := client.Get(origin + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), directory) || !strings.Contains(string(page), origin+"/acme/directory") {
		t.Fatalf("the index page lacks the ACME directories:\n%s", page)
	}
	resp, err = client.Get(origin + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"newOrder":"`+origin+`/acme/new-order"`) {
		t.Fatalf("GET /acme/directory of the root CA: %d\n%s", resp.StatusCode, body)
	}
}

func rootPool(t *testing.T, caDir string) *x509.CertPool {
	t.Helper()
	root, err := loadCert(filepath.Join(caDir, "ca_cert.pem"))
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}
