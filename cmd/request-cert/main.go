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

// Command request-cert requests a server certificate from the signing API of simple-ca serve.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

func run() error {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Usage:\n"+
			"  SIMPLE_CA_TOKEN=TOKEN request-cert [options] API_URL CN [DNS_NAME ...]\n"+
			"  request-cert --token-file FILE [options] API_URL CN [DNS_NAME ...]\n\n"+
			"Requests a server certificate for CN and the DNS names from the signing API of\n"+
			"simple-ca serve at API_URL, such as https://pki.example.com/servers/api/sign.\n\n"+
			"Options:\n")
		flag.PrintDefaults()
	}
	tokenFile := flag.String("token-file", os.Getenv("SIMPLE_CA_TOKEN_FILE"),
		"`file` holding the token, instead of SIMPLE_CA_TOKEN (default: SIMPLE_CA_TOKEN_FILE)")
	certType := flag.String("type", os.Getenv("SIMPLE_CA_TYPE"),
		"certificate `type` (default: SIMPLE_CA_TYPE, else the first type of the token)")
	outDir := flag.String("out-dir", ".", "`directory` the key, the certificate and the chain are written to")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		if version == "" {
			version = "dev"
		}
		fmt.Println("request-cert", version)
		return nil
	}
	if flag.NArg() < 2 {
		fmt.Fprintln(flag.CommandLine.Output(), "request-cert: API_URL and CN are required")
		flag.Usage()
		return errUsage
	}

	token := os.Getenv("SIMPLE_CA_TOKEN")
	switch {
	case token != "" && *tokenFile != "":
		return errors.New("give the token in SIMPLE_CA_TOKEN or in --token-file, not both")
	case *tokenFile != "":
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("--token-file: %w", err)
		}
		if token = strings.TrimSpace(string(b)); token == "" {
			return fmt.Errorf("--token-file: %s is empty", *tokenFile)
		}
	case token == "":
		return errors.New("no token: set SIMPLE_CA_TOKEN, or give --token-file or SIMPLE_CA_TOKEN_FILE")
	}

	url, cn := flag.Arg(0), flag.Arg(1)
	prefix := cn
	if rest, ok := strings.CutPrefix(cn, "*."); ok {
		prefix = "wildcard." + rest
	}
	prefix = filepath.Join(*outDir, prefix)
	keyPath, certPath, chainPath := prefix+"_key.pem", prefix+"_cert.pem", prefix+"_chain.pem"
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s exists", keyPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsNames := []string{cn}
	for _, n := range flag.Args()[2:] {
		if !slices.Contains(dnsNames, n) {
			dnsNames = append(dnsNames, n)
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dnsNames}, key)
	if err != nil {
		return err
	}

	request := map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}
	if *certType != "" {
		request["type"] = *certType
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var result struct{ Serial, Certificate, Chain, Error string }
	if resp.StatusCode != http.StatusOK {
		// The API answers with {"error": ...}; a URL that is not the API answers with text.
		message := strings.TrimSpace(string(answer))
		if json.Unmarshal(answer, &result) == nil && result.Error != "" {
			message = result.Error
		}
		return fmt.Errorf("%s: %d %s", url, resp.StatusCode, message)
	}
	if err := json.Unmarshal(answer, &result); err != nil {
		return err
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(result.Certificate), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(chainPath, []byte(result.Chain), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	fmt.Printf("Certificate %s written to %s, its chain to %s and its key to %s\n", result.Serial, certPath, chainPath, keyPath)
	return nil
}

func main() {
	if err := run(); errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "request-cert:", err)
		os.Exit(1)
	}
}
