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

package cli

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// signCSR signs the request in csrPath as cert sign does, as cert.RequestCert, and writes it with
// cert.StoreCert to certDir, the CA directory when empty, as the file cert.CertFile gives the
// request file NAME.EXT, replacing an earlier certificate of the name, and returns it. The
// certificate is shown on stdout before it is written, and written when the answer read from
// confirm is y or yes, or without asking with force.
func signCSR(csrPath, caDir, certDir, certType string, days int, ekus, kus []string, force bool, confirm io.Reader) (*x509.Certificate, error) {
	if certDir == "" {
		certDir = caDir
	}
	if !cert.DirExists(certDir) {
		return nil, fmt.Errorf("certificate directory %s does not exist", certDir)
	}
	base := filepath.Base(csrPath)
	file, err := cert.CertFile(strings.TrimSuffix(base, filepath.Ext(base)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}
	certOut := filepath.Join(certDir, file)
	data, err := os.ReadFile(csrPath)
	if err != nil {
		return nil, err
	}
	crt, err := cert.RequestCert(caDir, data, certType, days, ekus, kus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", csrPath, err)
	}

	// The certificate is shown, and written only once it is approved or with force.
	fmt.Printf("The %s certificate for %s:\n\n", certType, csrPath)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	cert.WriteCertFields(tw, crt, time.Now())
	if err := tw.Flush(); err != nil {
		return nil, err
	}
	fmt.Println()
	if !force {
		fmt.Print("Sign this certificate? [y/N] ")
		answer, err := bufio.NewReader(confirm).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			if errors.Is(err, io.EOF) {
				fmt.Println()
			}
			return nil, errors.New("the certificate was not signed")
		}
	}
	if err := cert.StoreCert(caDir, certOut, crt); err != nil {
		return nil, err
	}
	fmt.Printf("Certificate written to %s\n", certOut)
	return crt, nil
}
