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
	"crypto/x509"
	"encoding/pem"
	"log"
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
// expiry, and when and why it was revoked.
type webuiCert struct {
	Serial  string      `json:"serial"`
	Subject [][2]string `json:"subject"`
	Status  string      `json:"status"`
	Expires time.Time   `json:"expires"`
	Revoked *time.Time  `json:"revoked"`
	Reason  string      `json:"reason"`
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
//	POST /api/certs           creates a certificate, as cert create does
//	POST /api/certs/sign      signs a certificate signing request, as cert sign does, and returns
//	                          the name of the certificate file
//	POST /api/certs/revoke    revokes a certificate, as cert revoke does
//	POST /api/crl             writes the CRL of a CA, as crl create does
//
// The certificates and the CRL are written to the CA directory, as the commands write them; the
// API returns no file.
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
		!slices.Contains([]string{"/api/certs", "/api/certs/sign", "/api/certs/revoke", "/api/crl"}, r.URL.Path):
		webuiFail(w, http.StatusNotFound, "no such request")
		return
	}

	var req webuiCertRequest
	if !webuiDecode(w, r, &req) {
		return
	}
	dir, ok := s.caDir(req.CA)
	if !ok {
		webuiFail(w, http.StatusNotFound, "no such CA")
		return
	}
	switch r.URL.Path {
	case "/api/certs":
		// makeCert leaves a certificate whose files exist, so a create that adds no entry to
		// index.txt created nothing.
		before, err := readIndex(dir)
		if err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := makeCert(strings.TrimSpace(req.Subject), req.SANs, dir, "", req.Type, req.Days, req.EKU, req.KU); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		if after, err := readIndex(dir); err != nil || len(after) == len(before) {
			webuiFail(w, http.StatusConflict, "a certificate with the files of this name exists already in the CA directory")
			return
		}
		log.Printf("certificate %s of %s created", req.Subject, dir)
		webuiReply(w, http.StatusCreated, map[string]string{"subject": req.Subject})
	case "/api/certs/sign":
		// signCSR reads the request from a file named after the certificate it writes.
		scratch, err := os.MkdirTemp("", "simple-ca-csr-")
		if err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer os.RemoveAll(scratch)
		name := strings.TrimSpace(req.Name)
		if name == "" || strings.ContainsAny(name, `/\`) {
			webuiFail(w, http.StatusBadRequest, "name: the file name of the certificate is required, without a directory")
			return
		}
		csrPath := filepath.Join(scratch, name+".csr")
		if err := os.WriteFile(csrPath, []byte(req.CSR), 0o600); err != nil {
			webuiFail(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := signCSR(csrPath, dir, "", req.Type, req.Days, req.EKU, req.KU, true, nil); err != nil {
			webuiFail(w, http.StatusBadRequest, strings.ReplaceAll(err.Error(), csrPath, "the request"))
			return
		}
		file := strings.Trim(fileNameRE.ReplaceAllString(name, "_"), "_") + "_cert.pem"
		log.Printf("request %s signed by %s as %s", name, dir, file)
		webuiReply(w, http.StatusCreated, map[string]string{"file": file})
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
			webuiFail(w, http.StatusBadRequest, "the certificate is revoked already")
		default:
			log.Printf("certificate %s of %s revoked", req.Serial, dir)
			webuiReply(w, http.StatusOK, map[string]string{"serial": req.Serial})
		}
	case "/api/crl":
		if err := makeCRL(dir, req.Days); err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		webuiReply(w, http.StatusOK, map[string]string{"ca": req.CA})
	}
}

// listCerts answers with the certificates index.txt of the CA in dir records, and its CRL.
func (s *webuiServer) listCerts(w http.ResponseWriter, dir string) {
	entries, err := readIndex(dir)
	if err != nil {
		log.Printf("webui: %v", err)
		webuiFail(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now()
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
		c := webuiCert{Serial: e.serial, Subject: subjectAttributes(e.subject), Status: status, Expires: expires}
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

// showCert answers with the file holding the certificate of the serial number serial, and the
// content of the certificate, as certDetails returns it. The certificate
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
		webuiReply(w, http.StatusOK, map[string]any{"file": filepath.ToSlash(file), "certificate": certDetails(cert, time.Now())})
		return
	}
	webuiFail(w, http.StatusNotFound, "no certificate file of the CA directory holds the certificate "+serial+
		"; a later certificate of the same name may have replaced it")
}
