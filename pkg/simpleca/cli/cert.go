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
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
)

// runCertCreate runs cert create.
func runCertCreate(args []string) error {
	fs := NewFlagSet("cert create", "CN|EMAIL [EMAIL|CN] [SAN ...]",
		"Create a certificate signed by the CA in --ca-dir, of the type server, user, none or a\n"+
			"type of simple-ca.json.\n\n"+
			"server, none: CN [SAN ...]; the CN is a hostname or FQDN, a SAN a hostname, FQDN, IPv4 or\n"+
			"IPv6 address, or numeric OID. A none certificate has no key usages of its own.\n"+
			"user: CN|EMAIL [EMAIL|CN] [SAN ...]; the CN, the emailAddress or both, in either order,\n"+
			"then email addresses or numeric OIDs, after both the CN and the emailAddress.")
	certDir := fs.String("cert-dir", "", "output `directory` (default: the CA directory)")
	caDir := fs.String("ca-dir", "", "`directory` of the signing CA, root or issuing CA")
	certType := fs.String("type", "server", "certificate `type`: server, user, none or a type of simple-ca.json")
	days := fs.Int("days", 365, "validity period in `days`")
	keyType := fs.String("key-type", "", "`type` of the certificate key: rsa (RSA 4096) or ec (ECDSA P-256), without\n"+
		"keyEncipherment (default: the type of the CA key)")
	ekus, kus := usageFlags(fs)
	rest, given, err := ParseArgs(fs, args, 1, -1)
	if err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.Cert > 0 {
		*days = cfg.Days.Cert
	}
	crt, err := cert.MakeCert(rest[0], rest[1:], dir, *certDir, *certType, *days, *ekus, *kus, *keyType)
	if err != nil {
		return err
	}
	out := cmp.Or(*certDir, dir)
	cert.AuditIssued(dir, crt, *certType, "via", "cli", "actor", simpleca.CLIActor())
	fmt.Printf("The %s certificate and its key, written to %s:\n\n", *certType, out)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	cert.WriteCertFields(tw, crt, time.Now())
	return tw.Flush()
}

// runCertSign runs cert sign.
func runCertSign(args []string) error {
	fs := NewFlagSet("cert sign", "CSR_FILE",
		"Sign the certificate signing request in CSR_FILE, PEM or DER, with the CA in --ca-dir.\n\n"+
			"Only the subject and the subject alternative names of the request are copied; the type\n"+
			"sets the key usages and extended key usages. The certificate of NAME.EXT is written as\n"+
			"NAME_cert.pem. It is shown first and signed after you answer y.")
	certDir := fs.String("cert-dir", "", "output `directory` (default: the CA directory)")
	caDir := fs.String("ca-dir", "", "`directory` of the signing CA, root or issuing CA")
	certType := fs.String("type", "server", "certificate `type`: server, user, none or a type of simple-ca.json")
	days := fs.Int("days", 365, "validity period in `days`")
	force := fs.Bool("force", false, "sign without asking")
	ekus, kus := usageFlags(fs)
	rest, given, err := ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}
	if !given["days"] && cfg.Days.Cert > 0 {
		*days = cfg.Days.Cert
	}
	crt, err := signCSR(rest[0], dir, *certDir, *certType, *days, *ekus, *kus, *force, Input)
	if crt != nil {
		cert.AuditIssued(dir, crt, *certType, "via", "cli", "actor", simpleca.CLIActor())
	}
	return err
}

// runCertPFX runs cert pfx.
func runCertPFX(args []string) error {
	fs := NewFlagSet("cert pfx", "CERT_PATH", "Create a PKCS#12 (PFX) bundle for a leaf certificate.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA that signed the certificate")
	password := fs.String("password", "", "PFX `password` (default: changeit)")
	rest, _, err := ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(strings.TrimSuffix(rest[0], "_cert.pem") + "_key.pem"); err != nil {
		return err
	}
	if err := cert.MakePFX(rest[0], dir, *password); err != nil {
		return err
	}
	simpleca.Audit(dir, "cert.pfx", "file", rest[0], "via", "cli", "actor", simpleca.CLIActor())
	return nil
}

// runCertRevoke runs cert revoke.
func runCertRevoke(args []string) error {
	fs := NewFlagSet("cert revoke", "CERT_PATH", "Revoke a certificate the CA in --ca-dir issued.")
	caDir := fs.String("ca-dir", "", "`directory` of the CA that signed the certificate")
	reason := fs.String("reason", "", "revocation `reason`: unspecified, keyCompromise, CACompromise, affiliationChanged,\n"+
		"superseded or cessationOfOperation (default: none)")
	rest, _, err := ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return cert.RevokeCert(rest[0], ResolveCADir(*caDir), *reason)
}

// runCertList runs cert list.
func runCertList(args []string) error {
	fs := NewFlagSet("cert list", "", "List the certificates the CA in --ca-dir issued; without a status option, all of them.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	valid := fs.Bool("valid", false, "list the valid certificates")
	revoked := fs.Bool("revoked", false, "list the revoked certificates")
	expired := fs.Bool("expired", false, "list the expired certificates")
	_, _, err := ParseArgs(fs, args, 0, 0)
	if err != nil {
		return err
	}
	dir := ResolveCADir(*caDir)
	var statuses []string
	if *valid {
		statuses = append(statuses, "valid")
	}
	if *revoked {
		statuses = append(statuses, "revoked")
	}
	if *expired {
		statuses = append(statuses, "expired")
	}
	return cert.ListCerts(os.Stdout, dir, statuses)
}

// runCertShow runs cert show.
func runCertShow(args []string) error {
	fs := NewFlagSet("cert show", "CERT_FILE", "Show the certificates in CERT_FILE, PEM or DER.")
	rest, _, err := ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	return cert.ShowCert(os.Stdout, rest[0])
}
