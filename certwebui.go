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

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ---- the certificate page of serve ------------------------------------------

// webuiCert is a certificate of the API, as index.txt of its CA records it: its serial number, the
// attributes of its subject, each a type and a value, its status, valid, revoked or expired, its
// expiry, when and why it was revoked, whether the CA directory holds the key a PKCS#12 file is
// made with, and whether its key, that of an issuing CA too, is ENC, PLAIN or - for none.
type webuiCert struct {
	Serial  string      `json:"serial"`
	Subject [][2]string `json:"subject"`
	Status  string      `json:"status"`
	Expires time.Time   `json:"expires"`
	Revoked *time.Time  `json:"revoked"`
	Reason  string      `json:"reason"`
	HasKey  bool        `json:"has_key"`
	Key     string      `json:"key"`
}

// webuiCRL is the current CRL of a CA: its number, its next update, and whether that has passed.
type webuiCRL struct {
	Number     string    `json:"number"`
	NextUpdate time.Time `json:"next_update"`
	Overdue    bool      `json:"overdue"`
}

// webuiCertRequest is the body of a request changing the certificates of the CA CA: to create a
// certificate, its type, subject and SANs as cert create takes them; to sign a request, its type,
// the request in PEM and the name of the certificate file; to revoke a certificate, its serial
// number and the reason; the validity in days, and the key usages and extended key usages added to
// those of the type.
type webuiCertRequest struct {
	CA      string   `json:"ca"`
	Type    string   `json:"type"`
	Subject string   `json:"subject"`
	SANs    []string `json:"sans"`
	CSR     string   `json:"csr"`
	Name    string   `json:"name"`
	Serial  string   `json:"serial"`
	Reason  string   `json:"reason"`
	Days    int      `json:"days"`
	KU      []string `json:"ku"`
	EKU     []string `json:"eku"`
}

// certAPI answers a request of the certificates:
//
//	GET  /api/certs?ca=ID     the certificates of a CA and its CRL
//	GET  /api/certs/show?ca=ID&serial=HEX
//	                          the content of a certificate, as cert show shows it
//	POST /api/certs           creates a certificate, as cert create does, and returns its serial
//	                          number
//	POST /api/certs/sign      signs a certificate signing request, as cert sign does, and returns
//	                          the name of the certificate file
//	POST /api/certs/pfx       returns the PKCS#12 bundle of a certificate whose key the CA
//	                          directory holds, as cert pfx makes it, with a new random password
//	POST /api/certs/revoke    revokes a certificate, as cert revoke does
//	POST /api/crl             writes the CRL of a CA, as crl create does
//
// The certificates and the CRL are written to the CA directory, as the commands write them; the
// bundle is not written, but returned with its password.
func (s *webuiServer) certAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/certs":
		dir, ok := s.caDir(r.URL.Query().Get("ca"))
		if !ok {
			webuiFail(w, http.StatusNotFound, "no such CA")
			return
		}
		s.listCerts(w, dir)
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/certs/show":
		dir, ok := s.caDir(r.URL.Query().Get("ca"))
		if !ok {
			webuiFail(w, http.StatusNotFound, "no such CA")
			return
		}
		s.showCert(w, dir, r.URL.Query().Get("serial"))
		return
	case r.Method != http.MethodPost ||
		!slices.Contains([]string{"/api/certs", "/api/certs/sign", "/api/certs/pfx", "/api/certs/revoke", "/api/crl"}, r.URL.Path):
		webuiFail(w, http.StatusNotFound, "no such request")
		return
	}

	// The fields each request uses; the API takes no defaults, so those it needs are required.
	fields := map[string][]string{
		"/api/certs":        {"ca", "type", "subject", "sans", "days", "ku", "eku"},
		"/api/certs/sign":   {"ca", "type", "csr", "name", "days", "ku", "eku"},
		"/api/certs/pfx":    {"ca", "serial"},
		"/api/certs/revoke": {"ca", "serial", "reason"},
		"/api/crl":          {"ca", "days"},
	}[r.URL.Path]
	var req webuiCertRequest
	if !webuiDecode(w, r, &req, fields...) {
		return
	}
	if (r.URL.Path == "/api/certs" || r.URL.Path == "/api/certs/sign") && strings.TrimSpace(req.Type) == "" {
		webuiFail(w, http.StatusBadRequest, "type: the certificate type is required")
		return
	}
	dir, ok := s.caDir(req.CA)
	if !ok {
		webuiFail(w, http.StatusNotFound, "no such CA")
		return
	}
	switch r.URL.Path {
	case "/api/certs":
		cert, err := makeCert(strings.TrimSpace(req.Subject), req.SANs, dir, "", req.Type, req.Days, req.EKU, req.KU, "")
		switch {
		case errors.Is(err, errCertExists):
			webuiFail(w, http.StatusConflict, err.Error())
			return
		case err != nil:
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		auditIssued(dir, cert, req.Type, s.auditActor()...)
		webuiReply(w, http.StatusCreated, map[string]string{"subject": req.Subject, "serial": serialHex(cert.SerialNumber)})
	case "/api/certs/sign":
		// The certificate is named after the name given, as cert sign names it after the request
		// file, and replaces an earlier certificate of the name.
		if strings.ContainsAny(req.Name, `/\`) {
			webuiFail(w, http.StatusBadRequest, "name: the file name of the certificate is given without a directory")
			return
		}
		file, err := certFile(req.Name)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, "name: "+err.Error())
			return
		}
		cert, err := requestCert(dir, []byte(req.CSR), req.Type, req.Days, req.EKU, req.KU)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := storeCert(dir, filepath.Join(dir, file), cert); err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		auditIssued(dir, cert, req.Type, s.auditActor()...)
		webuiReply(w, http.StatusCreated, map[string]string{"file": file})
	case "/api/certs/pfx":
		certPath, ok := certFiles(dir)[req.Serial]
		if !ok || !fileExists(strings.TrimSuffix(certPath, "_cert.pem")+"_key.pem") {
			webuiFail(w, http.StatusNotFound, "no certificate file with a key of the CA directory holds the certificate "+req.Serial)
			return
		}
		password := rand.Text()
		bundle, err := encodePFX(certPath, dir, password)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		file := strings.TrimSuffix(filepath.Base(certPath), "_cert.pem") + ".pfx"
		audit(dir, "cert.pfx", append([]any{"file", filepath.Base(certPath)}, s.auditActor()...)...)
		webuiReply(w, http.StatusOK, map[string]any{"file": file, "password": password, "pfx": bundle})
	case "/api/certs/revoke":
		reason := ""
		if req.Reason != "" {
			i := slices.IndexFunc(crlReasons[:6], func(c struct {
				name string
				code int
			}) bool {
				return strings.EqualFold(c.name, req.Reason)
			})
			if i < 0 {
				webuiFail(w, http.StatusBadRequest, "unknown revocation reason '"+req.Reason+"'")
				return
			}
			reason = crlReasons[i].name
		}
		revoked, err := markRevoked(dir, req.Serial, reason)
		switch {
		case err != nil:
			webuiFail(w, http.StatusBadRequest, err.Error())
		case !revoked:
			webuiFail(w, http.StatusBadRequest, "certificate "+req.Serial+" is revoked already")
		default:
			audit(dir, "cert.revoke", append([]any{"serial", req.Serial, "reason", reason}, s.auditActor()...)...)
			webuiReply(w, http.StatusOK, map[string]string{"serial": req.Serial})
		}
	case "/api/crl":
		if err := makeCRL(dir, req.Days); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		auditCRL(dir, s.auditActor()...)
		webuiReply(w, http.StatusOK, map[string]string{"ca": req.CA})
	}
}

// listCerts answers with the certificates index.txt of the CA in dir records, and its CRL.
func (s *webuiServer) listCerts(w http.ResponseWriter, dir string) {
	entries, err := readIndex(dir)
	if err != nil {
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
	files, keys := certFiles(dir), keyFiles(dir)
	certs := []webuiCert{}
	for _, e := range entries {
		status, err := entryStatus(e, now)
		if err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		expires, err := parseIndexTime(e.expires)
		if err != nil {
			webuiFail(w, http.StatusInternalServerError, "invalid expiry of serial "+e.serial)
			return
		}
		c := webuiCert{Serial: e.serial, Subject: subjectAttributes(e.subject), Status: status, Expires: expires, Key: "-"}
		if path, ok := keys[e.serial]; ok {
			c.Key = keyStatus(path)
		}
		if path, ok := files[e.serial]; ok {
			c.HasKey = fileExists(strings.TrimSuffix(path, "_cert.pem") + "_key.pem")
		}
		if e.revoked != "" {
			if t, err := parseIndexTime(e.revoked); err == nil {
				c.Revoked = &t
			}
			c.Reason, _, _ = revocationReason(e.revoked)
		}
		certs = append(certs, c)
	}

	var crl *webuiCRL
	if b, err := os.ReadFile(filepath.Join(dir, "crl.pem")); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if list, err := x509.ParseRevocationList(block.Bytes); err == nil {
				crl = &webuiCRL{Number: list.Number.String(), NextUpdate: list.NextUpdate, Overdue: now.After(list.NextUpdate)}
			}
		}
	}
	webuiReply(w, http.StatusOK, map[string]any{"certs": certs, "crl": crl})
}

// keyFiles returns the paths of the private keys of the certificates the CA in dir issued, by
// their serial numbers: NAME_key.pem beside NAME_cert.pem, and for a root CA, the ca_key.pem of
// each issuing CA; a path may name no file.
func keyFiles(dir string) map[string]string {
	keys := map[string]string{}
	for serial, path := range certFiles(dir) {
		keys[serial] = strings.TrimSuffix(path, "_cert.pem") + "_key.pem"
	}
	issuing, _ := filepath.Glob(filepath.Join(dir, "*", "ca_cert.pem"))
	for _, path := range issuing {
		if cert, err := loadCert(path); err == nil {
			keys[serialHex(cert.SerialNumber)] = filepath.Join(filepath.Dir(path), "ca_key.pem")
		}
	}
	return keys
}

// certFiles returns the certificate files NAME_cert.pem of the CA directory dir, besides that of
// the CA, by the serial numbers of the certificates they hold.
func certFiles(dir string) map[string]string {
	paths, _ := filepath.Glob(filepath.Join(dir, "*_cert.pem"))
	files := map[string]string{}
	for _, path := range paths {
		if filepath.Base(path) == "ca_cert.pem" {
			continue
		}
		if cert, err := loadCert(path); err == nil {
			files[serialHex(cert.SerialNumber)] = path
		}
	}
	return files
}

// showCert answers with the file holding the certificate of the serial number serial, whether its
// key beside it is ENC, PLAIN or - for none, and the content of the certificate, as certDetails
// returns it. The certificate
// is looked for in the certificate files of the CA in dir, and for the root CA also in the
// certificates of its issuing CAs.
func (s *webuiServer) showCert(w http.ResponseWriter, dir, serial string) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*_cert.pem"))
	if dir == s.rootDir {
		issuing, _ := filepath.Glob(filepath.Join(dir, "*", "ca_cert.pem"))
		paths = append(paths, issuing...)
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || serialHex(cert.SerialNumber) != serial {
			continue
		}
		file, _ := filepath.Rel(dir, path)
		webuiReply(w, http.StatusOK, map[string]any{"file": filepath.ToSlash(file),
			"key": keyStatus(strings.TrimSuffix(path, "_cert.pem") + "_key.pem"), "certificate": certDetails(cert, time.Now())})
		return
	}
	webuiFail(w, http.StatusNotFound, "no certificate file of the CA directory holds the certificate "+serial+
		"; a later certificate of the same name may have replaced it")
}
