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

// Package cert is the certificate core of simple-ca: CAs, certificates and their types, CRLs,
// the database of a CA, PKCS#12 bundles and openssl.cnf.
package cert

import (
	"cmp"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

var (
	EmailRE    = regexp.MustCompile(`^[!-?A-~]+@[!-?A-~]+\.[!-?A-~]+$`)
	FileNameRE = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDEmailAddress   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// nameAttributes names the distinguished name attributes in the one-line form of OpenSSL.
var nameAttributes = map[string]string{
	"2.5.4.3":              "CN",
	"2.5.4.5":              "serialNumber",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "ST",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"1.2.840.113549.1.9.1": "emailAddress",
}

// NameString formats a parsed distinguished name in the one-line form of OpenSSL,
// /CN=.../emailAddress=..., an attribute without a short name by its OID.
func NameString(name pkix.Name) string {
	var b strings.Builder
	for _, attr := range name.Names {
		typ, ok := nameAttributes[attr.Type.String()]
		if !ok {
			typ = attr.Type.String()
		}
		fmt.Fprintf(&b, "/%s=%v", typ, attr.Value)
	}
	return b.String()
}

// nameStringRE matches the start of an attribute of the one-line form NameString writes: a
// slash, a type of nameAttributes or an OID, and an equals sign.
var nameStringRE = regexp.MustCompile(`/(CN|serialNumber|C|L|ST|O|OU|emailAddress|[0-9]+(?:\.[0-9]+)+)=`)

// SubjectView is a subject as the pages show it: its name, the CN or else the whole subject, the
// subject in the one-line form NameString writes, and the attributes of it, each a type and a
// value, which the pages show in a popup of the name.
type SubjectView struct {
	Name              string      `json:"name"`
	Subject           string      `json:"subject"`
	SubjectAttributes [][2]string `json:"subject_attributes"`
}

// NewSubjectView returns the view of subject, a name in the one-line form NameString writes.
func NewSubjectView(subject string) SubjectView {
	view := SubjectView{Name: subject, Subject: subject, SubjectAttributes: SubjectAttributes(subject)}
	for _, a := range view.SubjectAttributes {
		if a[0] == "CN" {
			view.Name = a[1]
			break
		}
	}
	return view
}

// SubjectAttributes returns the attributes of subject, a name in the one-line form NameString
// writes, each a type and a value, in their order in the name.
func SubjectAttributes(subject string) [][2]string {
	attributes := [][2]string{}
	starts := nameStringRE.FindAllStringSubmatchIndex(subject, -1)
	for i, m := range starts {
		end := len(subject)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		attributes = append(attributes, [2]string{subject[m[2]:m[3]], subject[m[1]:end]})
	}
	return attributes
}

// CertFileName returns the name of the files of a certificate: the hostname CN up to its first
// dot with the server name rules, else the CN, or the local part of the email address without a
// CN, each run of characters besides letters, digits, - and _ as one _; empty when nothing is
// left.
func CertFileName(cn, email string, userNames bool) string {
	name := cn
	if !userNames {
		name, _, _ = strings.Cut(cn, ".")
	} else if cn == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	return strings.Trim(FileNameRE.ReplaceAllString(name, "_"), "_")
}

// ErrCertExists reports a certificate that exists with its key, which cert create does not
// replace.
var ErrCertExists = errors.New("the certificate and its key exist already")

// MakeCert issues a certificate of the type certType, one of builtinTypes or of the types of
// simple-ca.json of the root CA, signed by the CA in caDir, writes it with its key to certDir, and
// records it in index.txt of that CA.
//
// By the server name rules, subjectName is the CN, a hostname or FQDN, which is also the first
// DNS name; sans are hostnames, FQDNs, IPv4 and IPv6 addresses and numeric OIDs.
//
// By the user name rules, subjectName is the CN or the emailAddress of the subject, and the first
// of sans, when given, is the other of the two. The emailAddress is also the first email address
// SAN; the rest of sans are email addresses and numeric OIDs.
//
// kus are added to the key usages of the type and ekus to its extended key usages, as parsed by
// ParseUsages. It returns the certificate issued, and an error wrapping ErrCertExists when the
// certificate and its key exist.
//
// The key is of leafKeyType, rsa or ec, or of the key type of the CA key when it is empty; an
// ECDSA key gets no keyEncipherment usage.
func MakeCert(subjectName string, sans []string, caDir, certDir, certType string, days int, ekus, kus []string,
	leafKeyType string) (*x509.Certificate, error) {
	if days < 1 {
		return nil, errors.New("the validity in days must be a positive integer")
	}
	if leafKeyType != "" && !slices.Contains(keyTypes, leafKeyType) {
		return nil, fmt.Errorf("--key-type '%s' must be rsa or ec", leafKeyType)
	}
	if !DirExists(caDir) {
		return nil, fmt.Errorf("CA directory %s does not exist", caDir)
	}
	if subjectName == "" {
		return nil, errors.New("subject name is required")
	}

	rootDir, issuingCA, err := simpleca.LocateCA(caDir)
	if err != nil {
		return nil, err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return nil, err
	}
	types, err := Types(cfg)
	if err != nil {
		return nil, err
	}
	def, ok := types[certType]
	if !ok {
		return nil, fmt.Errorf("unknown type '%s': must be one of %s", certType, TypeNames(types))
	}
	keyUsage, extKeyUsages, extKeyUsageOIDs, err := ParseUsages(
		append(slices.Clone(def.KeyUsage), kus...), append(slices.Clone(def.ExtKeyUsage), ekus...))
	if err != nil {
		return nil, err
	}
	userNames := def.Names == "user"

	// The subject and the SANs, by the name rules of the certificate type.
	var cn, email string
	var dnsNames, emails []string
	var ips []netip.Addr
	var oids []x509.OID
	rest := sans
	if !userNames {
		if !simpleca.IsHostname(subjectName) {
			return nil, fmt.Errorf("invalid CN '%s': a %s certificate's CN must be a hostname or FQDN", subjectName, certType)
		}
		cn = subjectName
		dnsNames = []string{cn}
	} else {
		if EmailRE.MatchString(subjectName) {
			email = subjectName
		} else {
			cn = subjectName
		}
		if len(rest) > 0 {
			next := rest[0]
			rest = rest[1:]
			switch {
			case email == "" && !EmailRE.MatchString(next):
				return nil, fmt.Errorf("invalid emailAddress '%s': the CN is '%s', so the second argument must be the email address", next, cn)
			case email == "":
				email = next
			case EmailRE.MatchString(next):
				return nil, fmt.Errorf("invalid CN '%s': the emailAddress is '%s', so the second argument must be the CN", next, email)
			default:
				cn = next
			}
		}
		if email != "" {
			emails = []string{email}
		}
		if strings.ContainsFunc(cn, unicode.IsControl) {
			return nil, errors.New("invalid CN: it holds a control character")
		}
	}
	for _, entry := range rest {
		oid, oidErr := x509.ParseOID(entry)
		ip, isIP := simpleca.ParseIP(entry)
		switch {
		case !userNames && isIP:
			ips = append(ips, ip)
		case oidErr == nil:
			oids = append(oids, oid)
		case !userNames && simpleca.IsHostname(entry):
			dnsNames = append(dnsNames, entry)
		case userNames && EmailRE.MatchString(entry):
			emails = append(emails, entry)
		case !userNames:
			return nil, fmt.Errorf("invalid SAN '%s': must be a hostname, FQDN, IPv4 or IPv6 address, or numeric OID", entry)
		default:
			return nil, fmt.Errorf("invalid SAN '%s': must be an email address or numeric OID", entry)
		}
	}

	if certDir == "" {
		certDir = caDir
	}
	if !DirExists(certDir) {
		return nil, fmt.Errorf("certificate directory %s does not exist", certDir)
	}

	caCertPath := filepath.Join(caDir, "ca_cert.pem")
	caKeyPath := filepath.Join(caDir, "ca_key.pem")
	if !simpleca.FileExists(caCertPath) || !simpleca.FileExists(caKeyPath) {
		return nil, fmt.Errorf("CA certificate and key not found in %s, which is not a CA directory", caDir)
	}

	publishURL := cfg.CAPublishBaseURL
	if issuingCA != "" {
		publishURL += "/" + issuingCA
	}

	certName := CertFileName(cn, email, userNames)
	if certName == "" {
		return nil, fmt.Errorf("'%s' gives no file name: it needs a letter or a digit", cmp.Or(cn, email))
	}

	subject := pkix.Name{CommonName: cn}
	if email != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{Type: OIDEmailAddress, Value: asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(email)}},
		}
	}

	// The subjectAltName extension, with the registeredID names.
	var names []asn1.RawValue
	for _, e := range emails {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(e)})
	}
	for _, d := range dnsNames {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(d)})
	}
	for _, ip := range ips {
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: ip.AsSlice()})
	}
	for _, oid := range oids {
		b, err := oid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: b})
	}

	certOut := filepath.Join(certDir, certName+"_cert.pem")
	keyOut := filepath.Join(certDir, certName+"_key.pem")
	if simpleca.FileExists(certOut) && simpleca.FileExists(keyOut) {
		return nil, fmt.Errorf("%w: %s and %s", ErrCertExists, filepath.Base(certOut), filepath.Base(keyOut))
	}

	caCert, err := simpleca.LoadCert(caCertPath)
	if err != nil {
		return nil, err
	}
	caKey, err := simpleca.LoadKey(caKeyPath)
	if err != nil {
		return nil, err
	}
	key, err := newKey(cmp.Or(leafKeyType, simpleca.KeyType(caKey.Public())))
	if err != nil {
		return nil, err
	}
	keyUsage = leafKeyUsage(keyUsage, key.Public())
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if err := CheckValidity(caCert, now, days); err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsages,
		UnknownExtKeyUsage:    extKeyUsageOIDs,
	}
	if len(names) > 0 {
		san, err := asn1.Marshal(names)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Value: san}}
	}
	if cfg.CAPublishBaseURL != "" {
		tmpl.IssuingCertificateURL = []string{publishURL + "/ca_cert.crt"}
		tmpl.CRLDistributionPoints = []string{publishURL + "/crl.pem"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, key.Public(), caKey)
	if err != nil {
		return nil, err
	}
	if err := writeKey(key, keyOut); err != nil {
		return nil, err
	}
	if err := writeCert(der, certOut); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, recordIssued(caDir, cert)
}

// InDomains reports whether name, in lower case, is one of domains or below one.
func InDomains(name string, domains []string) bool {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
