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

package cert

import (
	"crypto/x509"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

const opensslConfFile = "openssl.cnf"

// opensslExtKeyUsage names the extended key usages in an OpenSSL configuration, by the short
// name OpenSSL knows or else by OID.
var opensslExtKeyUsage = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "2.5.29.37.0",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
	x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCodeCom",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

// WriteOpenSSLConf writes openssl.cnf to the CA directory caDir, a configuration of "openssl ca"
// for its CA: its database and files, the defaults of simple-ca.json of its root CA, and an
// extensions section ext_TYPE for each certificate type, and ext_issuing_ca for a root CA. It
// returns the path of the file.
func WriteOpenSSLConf(caDir string) (string, error) {
	dir, err := filepath.Abs(caDir)
	if err != nil {
		return "", err
	}
	rootDir, issuingCA, err := simpleca.LocateCA(dir)
	if err != nil {
		return "", err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return "", err
	}
	types, err := Types(cfg)
	if err != nil {
		return "", err
	}
	certDays, crlDays := 365, 30
	if cfg.Days.Cert > 0 {
		certDays = cfg.Days.Cert
	}
	if cfg.Days.CRL > 0 {
		crlDays = cfg.Days.CRL
	}
	kind := "the root CA"
	publishURL := cfg.CAPublishBaseURL
	if issuingCA != "" {
		kind = fmt.Sprintf("the issuing CA '%s'", issuingCA)
		if publishURL != "" {
			publishURL += "/" + issuingCA
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Configuration of openssl ca for %s, written by simple-ca ca create --write-conf.\n", kind)
	fmt.Fprintf(&b, "# Sign a request with: openssl ca -config %s -extensions ext_TYPE -in REQ -out CERT\n\n",
		filepath.ToSlash(filepath.Join(dir, opensslConfFile)))
	fmt.Fprintf(&b, "[ ca ]\ndefault_ca = simple_ca\n\n")
	fmt.Fprintf(&b, "[ simple_ca ]\n")
	fmt.Fprintf(&b, "dir              = %s\n", filepath.ToSlash(dir))
	fmt.Fprintf(&b, "database         = $dir/%s\n", indexFile)
	fmt.Fprintf(&b, "new_certs_dir    = $dir\n")
	fmt.Fprintf(&b, "certificate      = $dir/ca_cert.pem\n")
	fmt.Fprintf(&b, "private_key      = $dir/ca_key.pem\n")
	fmt.Fprintf(&b, "crlnumber        = $dir/%s\n", CRLNumberFile)
	fmt.Fprintf(&b, "rand_serial      = yes\n")
	fmt.Fprintf(&b, "unique_subject   = no\n")
	fmt.Fprintf(&b, "default_md       = sha256\n")
	fmt.Fprintf(&b, "default_days     = %d\n", certDays)
	fmt.Fprintf(&b, "default_crl_days = %d\n", crlDays)
	fmt.Fprintf(&b, "policy           = policy_simple_ca\n")
	fmt.Fprintf(&b, "copy_extensions  = copy\n")
	fmt.Fprintf(&b, "x509_extensions  = ext_server\n\n")
	fmt.Fprintf(&b, "[ policy_simple_ca ]\ncommonName   = optional\nemailAddress = optional\n")

	// The key identifiers and the URLs of the CA, in every extensions section.
	writeCommon := func() {
		fmt.Fprintf(&b, "subjectKeyIdentifier   = hash\n")
		fmt.Fprintf(&b, "authorityKeyIdentifier = keyid\n")
		if publishURL != "" {
			fmt.Fprintf(&b, "authorityInfoAccess    = caIssuers;URI:%s/ca_cert.crt\n", publishURL)
			fmt.Fprintf(&b, "crlDistributionPoints  = URI:%s/crl.pem\n", publishURL)
		}
	}
	if issuingCA == "" {
		fmt.Fprintf(&b, "\n[ ext_issuing_ca ]\n")
		fmt.Fprintf(&b, "basicConstraints       = critical, CA:TRUE, pathlen:0\n")
		fmt.Fprintf(&b, "keyUsage               = critical, keyCertSign, cRLSign\n")
		writeCommon()
	}
	for _, name := range slices.Sorted(maps.Keys(types)) {
		def := types[name]
		keyUsage, extKeyUsages, extKeyUsageOIDs, err := ParseUsages(def.KeyUsage, def.ExtKeyUsage)
		if err != nil {
			return "", fmt.Errorf("type '%s': %w", name, err)
		}
		fmt.Fprintf(&b, "\n[ ext_%s ]\n", name)
		fmt.Fprintf(&b, "basicConstraints       = critical, CA:FALSE\n")
		var usages []string
		for _, u := range KeyUsageNames {
			if keyUsage&u.Usage != 0 {
				usages = append(usages, u.Name)
			}
		}
		if len(usages) > 0 {
			fmt.Fprintf(&b, "keyUsage               = critical, %s\n", strings.Join(usages, ", "))
		}
		var extUsages []string
		for _, u := range extKeyUsages {
			extUsages = append(extUsages, opensslExtKeyUsage[u])
		}
		for _, oid := range extKeyUsageOIDs {
			extUsages = append(extUsages, oid.String())
		}
		if len(extUsages) > 0 {
			fmt.Fprintf(&b, "extendedKeyUsage       = %s\n", strings.Join(extUsages, ", "))
		}
		writeCommon()
	}

	path := filepath.Join(dir, opensslConfFile)
	return path, os.WriteFile(path, []byte(b.String()), 0o644)
}
