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
	"encoding/asn1"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// CertTypeDef is a certificate type: the name rules of its subject and SANs, "server" or "user",
// and the names of its key usages and extended key usages.
type CertTypeDef struct {
	Names       string
	KeyUsage    []string
	ExtKeyUsage []string
}

// builtinTypes are the certificate types simple-ca.json can redefine.
var builtinTypes = map[string]CertTypeDef{
	"server": {"server", []string{"digitalSignature", "keyEncipherment"}, []string{"serverAuth", "clientAuth"}},
	"user":   {"user", []string{"digitalSignature", "contentCommitment"}, []string{"clientAuth", "emailProtection", "codeSigning"}},
	"none":   {"server", nil, nil},
}

// Types returns the built-in types with the types of simple-ca.json defined or redefined over
// them. A type of the file redefines only the fields it gives; a new type has the server name
// rules unless it names others.
func Types(c *simpleca.Config) (map[string]CertTypeDef, error) {
	types := maps.Clone(builtinTypes)
	for name, t := range c.Types {
		if !simpleca.KebabCaseRE.MatchString(name) {
			return nil, fmt.Errorf("type '%s' in %s is not a kebab-case name, such as web-server", name, c.Path)
		}
		def := types[name]
		if def.Names == "" {
			def.Names = "server"
		}
		if t.Names != "" {
			if t.Names != "server" && t.Names != "user" {
				return nil, fmt.Errorf("type '%s' in %s: names must be 'server' or 'user', got '%s'", name, c.Path, t.Names)
			}
			def.Names = t.Names
		}
		if t.KeyUsage != nil {
			def.KeyUsage = *t.KeyUsage
		}
		if t.ExtKeyUsage != nil {
			def.ExtKeyUsage = *t.ExtKeyUsage
		}
		if _, _, _, err := ParseUsages(def.KeyUsage, def.ExtKeyUsage); err != nil {
			return nil, fmt.Errorf("type '%s' in %s: %w", name, c.Path, err)
		}
		types[name] = def
	}
	return types, nil
}

// TypeNames returns the names of types, sorted, joined by commas.
func TypeNames(types map[string]CertTypeDef) string {
	return strings.Join(slices.Sorted(maps.Keys(types)), ", ")
}

// ParseUsages parses the names of key usages, those of KeyUsageNames other than keyCertSign, and
// of extended key usages, names of ExtKeyUsageNames or numeric OIDs, in any letter case. It
// returns the extended key usages crypto/x509 knows and the OIDs of the others, each once, in the
// order given.
func ParseUsages(kus, ekus []string) (x509.KeyUsage, []x509.ExtKeyUsage, []asn1.ObjectIdentifier, error) {
	var keyUsage x509.KeyUsage
	for _, ku := range kus {
		known := false
		for _, u := range KeyUsageNames {
			if strings.EqualFold(ku, u.Name) && u.Usage != x509.KeyUsageCertSign {
				keyUsage |= u.Usage
				known = true
			}
		}
		if !known {
			return 0, nil, nil, fmt.Errorf("invalid key usage '%s': must be one of digitalSignature, contentCommitment, "+
				"keyEncipherment, dataEncipherment, keyAgreement, cRLSign, encipherOnly, decipherOnly", ku)
		}
	}

	var extKeyUsages []x509.ExtKeyUsage
	var extKeyUsageOIDs []asn1.ObjectIdentifier
	for _, eku := range ekus {
		known := false
		for usage, name := range ExtKeyUsageNames {
			if strings.EqualFold(eku, name) {
				if !slices.Contains(extKeyUsages, usage) {
					extKeyUsages = append(extKeyUsages, usage)
				}
				known = true
			}
		}
		if known {
			continue
		}
		if _, err := x509.ParseOID(eku); err != nil {
			return 0, nil, nil, fmt.Errorf("invalid EKU '%s': must be a name such as clientAuth or a numeric OID", eku)
		}
		var oid asn1.ObjectIdentifier
		for _, arc := range strings.Split(eku, ".") {
			n, err := strconv.Atoi(arc)
			if err != nil {
				return 0, nil, nil, fmt.Errorf("invalid EKU '%s': %w", eku, err)
			}
			oid = append(oid, n)
		}
		if !slices.ContainsFunc(extKeyUsageOIDs, oid.Equal) {
			extKeyUsageOIDs = append(extKeyUsageOIDs, oid)
		}
	}
	return keyUsage, extKeyUsages, extKeyUsageOIDs, nil
}

// KeyUsageNames names the key usage bits in the order of RFC 5280.
var KeyUsageNames = []struct {
	Usage x509.KeyUsage
	Name  string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

// ExtKeyUsageNames names the extended key usages crypto/x509 knows.
var ExtKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msSGC",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "nsSGC",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCodeCom",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "msKernelCodeSigning",
}
