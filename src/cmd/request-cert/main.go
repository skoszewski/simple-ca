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
	"cmp"
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
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/client"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

func run() error {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Usage:\n"+
			"  SIMPLE_CA_TOKEN=TOKEN request-cert [options] CA_URL CN [DNS_NAME ...]\n"+
			"  request-cert --token-file FILE [options] CA_URL CN [DNS_NAME ...]\n"+
			"  request-cert --setup-code CODE [--token-file NEW_FILE] [options] CA_URL CN [DNS_NAME ...]\n\n"+
			"Requests a server certificate for CN and the DNS names from the signing API of the CA\n"+
			"of simple-ca serve at CA_URL: https://pki.example.com for the root CA, or\n"+
			"https://pki.example.com/servers for the issuing CA servers.\n\n"+
			"With --setup-code, it exchanges the one-time setup code for the token at\n"+
			"/api/token-setup of the server of CA_URL first, and writes the token to --token-file,\n"+
			"a file that does not exist yet, when it is given.\n\n"+
			"Options:\n")
		flag.PrintDefaults()
	}
	tokenFile := flag.String("token-file", os.Getenv("SIMPLE_CA_TOKEN_FILE"),
		"`file` holding the token, instead of SIMPLE_CA_TOKEN, or the token of --setup-code is\n"+
			"written to (default: SIMPLE_CA_TOKEN_FILE)")
	setupCode := flag.String("setup-code", "", "one-time setup `code` exchanged for the token")
	certType := flag.String("type", cmp.Or(os.Getenv("SIMPLE_CA_TYPE"), "server"),
		"certificate `type` (default: SIMPLE_CA_TYPE, else server)")
	envDays := 365
	if v := os.Getenv("SIMPLE_CA_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("SIMPLE_CA_DAYS: '%s' is not a number of days", v)
		}
		envDays = n
	}
	days := flag.Int("days", envDays, "validity period in `days` (default: SIMPLE_CA_DAYS, else 365)")
	name := flag.String("name", "", "`name` of the certificate file of the CA directory, NAME_cert.pem\n"+
		"(default: the CN, as the files written here)")
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
		fmt.Fprintln(flag.CommandLine.Output(), "request-cert: CA_URL and CN are required")
		flag.Usage()
		return errUsage
	}

	token, code := os.Getenv("SIMPLE_CA_TOKEN"), strings.TrimSpace(*setupCode)
	switch {
	case token != "" && code != "":
		return errors.New("give the token in SIMPLE_CA_TOKEN or a setup code with --setup-code, not both")
	case token != "" && *tokenFile != "":
		return errors.New("give the token in SIMPLE_CA_TOKEN or in --token-file, not both")
	case code != "":
		// The token of the setup code is written to --token-file, a new file made before the code is
		// used, so a used code leaves no token behind by mistake.
		var file *os.File
		var err error
		if *tokenFile != "" {
			if file, err = os.OpenFile(*tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
				return fmt.Errorf("--token-file: %w; the token of --setup-code is written to a new file", err)
			}
		}
		if token, err = client.Exchange(flag.Arg(0), code); err != nil {
			if file != nil {
				file.Close()
				os.Remove(*tokenFile)
			}
			return err
		}
		if file != nil {
			_, err = file.WriteString(token + "\n")
			if err := cmp.Or(err, file.Close()); err != nil {
				return fmt.Errorf("--token-file: %w", err)
			}
			fmt.Printf("Token written to %s\n", *tokenFile)
		}
	case *tokenFile != "":
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("--token-file: %w", err)
		}
		if token = strings.TrimSpace(string(b)); token == "" {
			return fmt.Errorf("--token-file: %s is empty", *tokenFile)
		}
	case token == "":
		return errors.New("no token: set SIMPLE_CA_TOKEN, or give --token-file, SIMPLE_CA_TOKEN_FILE or --setup-code")
	}

	url, cn := strings.TrimSuffix(strings.TrimSuffix(flag.Arg(0), "/"), "/api/sign")+"/api/sign", flag.Arg(1)
	prefix := cn
	if rest, ok := strings.CutPrefix(cn, "*."); ok {
		prefix = "wildcard." + rest
	}
	fileName := cmp.Or(*name, prefix)
	prefix = filepath.Join(*outDir, prefix)
	keyPath, certPath, chainPath := prefix+"_key.pem", prefix+"_cert.pem", prefix+"_chain.pem"
	// The key file is made before the request, new and readable by its owner alone.
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		keyFile.Close()
		if !written {
			os.Remove(keyPath)
		}
	}()

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

	body, err := json.Marshal(map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		"type": *certType, "days": *days, "name": fileName})
	if err != nil {
		return err
	}
	var result struct{ Serial, Certificate, Chain string }
	if err := client.Post(url, "application/json", token, body, &result); err != nil {
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
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return err
	}
	written = true
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
