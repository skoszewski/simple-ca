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
//
// Usage:
//
//	SIMPLE_CA_TOKEN=TOKEN request-cert API_URL CN [DNS_NAME ...]
//	SIMPLE_CA_TOKEN_FILE=FILE request-cert API_URL CN [DNS_NAME ...]
//
// It makes an EC P-256 key and a certificate signing request for the CN, with the CN and the DNS
// names as its DNS names, and sends it to API_URL, such as
// https://pki.example.com/servers/api/sign, with a token made by simple-ca token create, in
// SIMPLE_CA_TOKEN or in the file SIMPLE_CA_TOKEN_FILE names, and the certificate type in
// SIMPLE_CA_TYPE, the first type of the token when it is unset. The key, the certificate and the
// chain are written to CN_key.pem, CN_cert.pem and CN_chain.pem, a wildcard CN *.NAME as
// wildcard.NAME; the key only once the certificate is signed.
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
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
)

func run() error {
	token, tokenFile := os.Getenv("SIMPLE_CA_TOKEN"), os.Getenv("SIMPLE_CA_TOKEN_FILE")
	if len(os.Args) < 3 || token+tokenFile == "" {
		return errors.New("usage: SIMPLE_CA_TOKEN=TOKEN request-cert API_URL CN [DNS_NAME ...]\n" +
			"       SIMPLE_CA_TOKEN_FILE=FILE request-cert API_URL CN [DNS_NAME ...]")
	}
	if token != "" && tokenFile != "" {
		return errors.New("set SIMPLE_CA_TOKEN or SIMPLE_CA_TOKEN_FILE, not both")
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("SIMPLE_CA_TOKEN_FILE: %w", err)
		}
		if token = strings.TrimSpace(string(b)); token == "" {
			return fmt.Errorf("SIMPLE_CA_TOKEN_FILE: %s is empty", tokenFile)
		}
	}
	url, cn := os.Args[1], os.Args[2]
	prefix := cn
	if rest, ok := strings.CutPrefix(cn, "*."); ok {
		prefix = "wildcard." + rest
	}
	keyPath, certPath, chainPath := prefix+"_key.pem", prefix+"_cert.pem", prefix+"_chain.pem"
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s exists", keyPath)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	dnsNames := []string{cn}
	for _, n := range os.Args[3:] {
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
	if t := os.Getenv("SIMPLE_CA_TYPE"); t != "" {
		request["type"] = t
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
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
