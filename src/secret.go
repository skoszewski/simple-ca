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
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/secrets"
)

// ---- the one-time secrets ---------------------------------------------------

// takeSecret takes the secret of the one-time code of the root CA in rootDir or of one of its
// issuing CAs, used from the address client, as secrets.Take does, inside the brute-force guard,
// and records it in the audit log, via via. The error has the status 401 for an unknown, used or
// expired code, and 403 for a client the code is not used from.
func takeSecret(w http.ResponseWriter, r *http.Request, rootDir, code, via string, client netip.Addr) (caID, name string, value []byte, err error) {
	err = guard.attempt(w, r, rootDir, func() (err error) {
		if code == "" {
			return apiErr(http.StatusUnauthorized, "a code is required")
		}
		caID, name, value, err = secrets.Take(rootDir, code, client)
		switch {
		case errors.Is(err, secrets.ErrUnknown), errors.Is(err, secrets.ErrExpired):
			return apiErr(http.StatusUnauthorized, "%s", err.Error())
		case errors.Is(err, secrets.ErrClient):
			return apiErr(http.StatusForbidden, "%s", err.Error())
		}
		return err
	})
	if err == nil {
		simpleca.Audit(filepath.Join(rootDir, caID), "secret.get", "name", name, "via", via, "client", client.String())
	}
	return caID, name, value, err
}

// apiSecretGet answers POST /api/secret-get, a JSON body {"code": "..."} of at most
// setupCodeMaxBody bytes from a client behind the trusted proxies, with the CA ID, the name and
// the value of the secret of the code, which is removed then; a value that is not UTF-8 text is
// sent in base64, with "encoding": "base64".
func apiSecretGet(w http.ResponseWriter, r *http.Request, rootDir string) {
	var req struct {
		Code string `json:"code"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, setupCodeMaxBody))
	dec.DisallowUnknownFields()
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		webuiFail(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	err := dec.Decode(&req)
	if bodyTooLarge(err) {
		webuiFail(w, http.StatusRequestEntityTooLarge, tooLargeText(setupCodeMaxBody))
		return
	}
	if err != nil || strings.TrimSpace(req.Code) == "" {
		webuiFail(w, http.StatusBadRequest, "the body is not a JSON object with the code")
		return
	}
	id, name, value, err := takeSecret(w, r, rootDir, strings.TrimSpace(req.Code), "api", clientAddr(r))
	var refused *apiError
	switch {
	case errors.As(err, &refused):
		webuiFail(w, refused.status, refused.msg)
		return
	case err != nil:
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not read the secret")
		return
	}
	answer := map[string]any{"ca": id, "name": name, "secret": string(value)}
	if !utf8.Valid(value) {
		answer["secret"], answer["encoding"] = value, "base64"
	}
	webuiReply(w, http.StatusOK, answer)
}

// secretGetPage serves /secret-get for the root CA in rootDir and its issuing CAs: GET shows the
// form asking for a code, and POST takes the secret of the code, as takeSecret does, and shows its
// value once, or the form again with the error. The client is the one clientAddr finds with the
// trusted proxies.
func secretGetPage(w http.ResponseWriter, r *http.Request, rootDir string) {
	caCert, err := simpleca.LoadCert(filepath.Join(rootDir, "ca_cert.pem"))
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	page := struct {
		Title, Script, Action, Error, CA, Name, Value string
		Shown                                         bool
		Theme                                         template.CSS
	}{Title: caCert.Subject.CommonName, Script: tailwindPath, Action: r.URL.Path, Theme: pageTheme(rootDir)}
	status := http.StatusOK
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, formMaxBody)
		if err := r.ParseForm(); bodyTooLarge(err) {
			http.Error(w, tooLargeText(formMaxBody), http.StatusRequestEntityTooLarge)
			return
		} else if err != nil {
			http.Error(w, "the form is malformed", http.StatusBadRequest)
			return
		}
		var value []byte
		page.CA, page.Name, value, err = takeSecret(w, r, rootDir, strings.TrimSpace(r.PostForm.Get("code")), "form", clientAddr(r))
		var e *apiError
		switch {
		case errors.As(err, &e):
			status, page.Error = e.status, e.msg
		case err != nil:
			slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
			status, page.Error = http.StatusInternalServerError, "could not read the secret"
		default:
			page.Shown, page.Value = true, string(value)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := pageTemplates.ExecuteTemplate(w, "secret-get.html", page); err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
	}
}
