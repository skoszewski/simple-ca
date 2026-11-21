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

// Command request-cert requests a server certificate from the signing API of simple-ca serve, or
// the user certificate of an OIDC user signed in at the OIDC provider of serve.
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
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/skoszewski/simple-ca/src/pkg/client"
	"github.com/skoszewski/simple-ca/src/pkg/weburl"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

func run() error {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), `Usage: SIMPLE_CA_TOKEN=TOKEN request-cert [options] CA_URL CN [DNS_NAME ...]
       request-cert --token-file FILE [options] CA_URL CN [DNS_NAME ...]
       request-cert --setup-code CODE [--token-file NEW_FILE] [options] CA_URL CN [DNS_NAME ...]
       request-cert --oidc [--no-browser] [--type TYPE] [--name NAME] [--out-dir DIR] SERVE_URL
       request-cert --oidc-device [--type TYPE] [--name NAME] [--out-dir DIR] SERVE_URL

Requests a certificate for CN and the DNS names from the signing API of simple-ca serve at CA_URL,
with the token, or with the token the one-time setup code is exchanged for.

With --oidc or --oidc-device, signs in at the OIDC provider of serve at SERVE_URL and requests a
user certificate of the signed-in person, named by the ID token, of a type of the profile of the
user; --type chooses one when the profile offers several. Server certificates are requested with
a token or a setup code.

Options:
`)
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
			return fmt.Errorf("SIMPLE_CA_DAYS: %q is not a number of days", v)
		}
		envDays = n
	}
	days := flag.Int("days", envDays, "validity period in `days` (default: SIMPLE_CA_DAYS, else 365)")
	name := flag.String("name", "", "`name` of the certificate file of the CA directory, NAME_cert.pem\n"+
		"(default: the CN, as the files written here); with --oidc or --oidc-device, the name of\n"+
		"the files written here (default: the local part of the email address)")
	outDir := flag.String("out-dir", ".", "`directory` the key, the certificate and the chain are written to")
	loopback := flag.Bool("oidc", false, "sign in at the OIDC provider of serve in the browser, which comes back\n"+
		"to a port of 127.0.0.1")
	device := flag.Bool("oidc-device", false, "sign in at the OIDC provider of serve with a code entered on\n"+
		"any device")
	noBrowser := flag.Bool("no-browser", false, "with --oidc, print the sign-in URL without opening the browser")
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
	signIn := *loopback || *device
	var given []string
	typeGiven := false
	flag.Visit(func(f *flag.Flag) {
		if slices.Contains([]string{"token-file", "setup-code", "days"}, f.Name) {
			given = append(given, "--"+f.Name)
		}
		typeGiven = typeGiven || f.Name == "type"
	})
	switch {
	case *loopback && *device:
		return errors.New("give --oidc or --oidc-device, not both")
	case *noBrowser && !*loopback:
		return errors.New("--no-browser goes with --oidc")
	case signIn && len(given) > 0:
		return fmt.Errorf("%s does not go with --oidc or --oidc-device", strings.Join(given, " and "))
	case signIn && flag.NArg() != 1:
		fmt.Fprintln(flag.CommandLine.Output(), "request-cert: SERVE_URL is the one argument of --oidc and --oidc-device")
		flag.Usage()
		return errUsage
	case !signIn && flag.NArg() < 2:
		fmt.Fprintln(flag.CommandLine.Output(), "request-cert: CA_URL and CN are required")
		flag.Usage()
		return errUsage
	}
	srv, _, err := weburl.CA(flag.Arg(0))
	if err != nil {
		return fmt.Errorf("CA_URL: %w", err)
	}

	// The credential, the name of the files written here and the request: an ID token for a
	// request of the public key alone, or a token for the CN and the DNS names.
	var token, idToken, prefix, fileName string
	request := &x509.CertificateRequest{}
	if signIn {
		settings, err := signInSettings(srv)
		if err != nil {
			return err
		}
		if *loopback {
			idToken, err = loopbackSignIn(settings, *noBrowser)
		} else {
			idToken, err = deviceSignIn(settings)
		}
		if err != nil {
			return err
		}
		claims, err := idTokenClaims(idToken)
		if err != nil {
			return err
		}
		prefix = cmp.Or(*name, filePrefix(claims, settings.EmailClaim))
	} else {
		code := strings.TrimSpace(*setupCode)
		token = os.Getenv("SIMPLE_CA_TOKEN")
		switch {
		case token != "" && code != "":
			return errors.New("give the token in SIMPLE_CA_TOKEN or a setup code with --setup-code, not both")
		case token != "" && *tokenFile != "":
			return errors.New("give the token in SIMPLE_CA_TOKEN or in --token-file, not both")
		case code != "":
			// The token of the setup code is written to --token-file, a new file made before the code
			// is used, so a used code leaves no token behind by mistake.
			var file *os.File
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
				fmt.Printf("Token written to %q\n", *tokenFile)
			}
		case *tokenFile != "":
			b, err := os.ReadFile(*tokenFile)
			if err != nil {
				return fmt.Errorf("--token-file: %w", err)
			}
			if token = strings.TrimSpace(string(b)); token == "" {
				return fmt.Errorf("--token-file: %q is empty", *tokenFile)
			}
		case token == "":
			return errors.New("no token: set SIMPLE_CA_TOKEN, or give --token-file, SIMPLE_CA_TOKEN_FILE or --setup-code")
		}
		cn := flag.Arg(1)
		prefix = cn
		if rest, ok := strings.CutPrefix(cn, "*."); ok {
			prefix = "wildcard." + rest
		}
		fileName = cmp.Or(*name, prefix)
		request.Subject = pkix.Name{CommonName: cn}
		request.DNSNames = []string{cn}
		for _, n := range flag.Args()[2:] {
			if !slices.Contains(request.DNSNames, n) {
				request.DNSNames = append(request.DNSNames, n)
			}
		}
	}

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
	csr, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return err
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	var result struct{ Serial, Certificate, Chain string }
	if signIn {
		fields := map[string]any{"id_token": idToken, "csr": csrPEM}
		if typeGiven {
			fields["type"] = *certType
		}
		body, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		err = client.Post(srv+"/api/oidc-cert", "application/json", "", body, &result)
		if e, ok := errors.AsType[*client.StatusError](err); ok && e.Code == http.StatusConflict {
			return fmt.Errorf("%s with --type", e.Message)
		}
		if err != nil {
			return err
		}
	} else {
		body, err := json.Marshal(map[string]any{"csr": csrPEM, "type": *certType, "days": *days, "name": fileName})
		if err != nil {
			return err
		}
		if err := client.PostCA(flag.Arg(0), "/api/sign", token, body, &result); err != nil {
			return err
		}
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
	fmt.Printf("Certificate %q written to %q, its chain to %q and its key to %q\n", result.Serial, certPath, chainPath, keyPath)
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
