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
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/secrets"
)

// ---- the secret page of serve -----------------------------------------------

// webuiSecret is a secret of the API, without its value: its name, when it was created and
// expires, the client prefixes its code is used from, any when empty, and the actor that created
// it.
type webuiSecret struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Clients []string  `json:"clients"`
	Creator string    `json:"creator"`
}

// webuiSecretRequest is the body of a request changing the secrets of the CA CA: the name of the
// secret, and to create it, its value, the validity of its code, and the client prefixes the code
// is used from.
type webuiSecretRequest struct {
	CA       string   `json:"ca"`
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Valid    string   `json:"valid"`
	Networks []string `json:"networks"`
}

// secretAPI answers a request of the secrets:
//
//	GET  /api/secrets?ca=ID    the secrets of a CA whose codes are not used, without their values
//	POST /api/secrets          creates a secret and returns its one-time code
//	POST /api/secrets/revoke   removes a secret
func (s *webuiServer) secretAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/secrets":
		dir, ok := s.caDir(r.URL.Query().Get("ca"))
		if !ok {
			webuiFail(w, http.StatusNotFound, "no such CA")
			return
		}
		db, err := secrets.Load(dir)
		if err != nil {
			slog.Error("serve.error", "error", err.Error())
			webuiFail(w, http.StatusInternalServerError, "could not read the secrets")
			return
		}
		now := time.Now()
		list := []webuiSecret{}
		for _, name := range slices.Sorted(maps.Keys(db.Secrets)) {
			if sec := db.Secrets[name]; now.Before(sec.Expires) {
				list = append(list, webuiSecret{Name: name, Created: sec.Created, Expires: sec.Expires,
					Clients: append([]string{}, showPrefixes(sec.Clients)...), Creator: sec.Creator})
			}
		}
		webuiReply(w, http.StatusOK, map[string][]webuiSecret{"secrets": list})
		return
	case r.Method != http.MethodPost || !slices.Contains([]string{"/api/secrets", "/api/secrets/revoke"}, r.URL.Path):
		webuiFail(w, http.StatusNotFound, "no such request")
		return
	}

	// The fields each request uses; the API takes no defaults, so those it needs are required.
	fields := map[string][]string{
		"/api/secrets":        {"ca", "name", "value", "valid", "networks"},
		"/api/secrets/revoke": {"ca", "name"},
	}[r.URL.Path]
	var req webuiSecretRequest
	if !webuiDecode(w, r, &req, fields...) {
		return
	}
	dir, ok := s.caDir(req.CA)
	if !ok {
		webuiFail(w, http.StatusNotFound, "no such CA")
		return
	}
	switch r.URL.Path {
	case "/api/secrets":
		valid, err := simpleca.ParseDuration(req.Valid)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, "valid: "+err.Error())
			return
		}
		code, err := secrets.Add(dir, req.Name, []byte(req.Value), valid, req.Networks, s.user)
		if err != nil {
			webuiFail(w, http.StatusBadRequest, err.Error())
			return
		}
		simpleca.Audit(dir, "secret.create", append([]any{"name", req.Name, "valid", simpleca.DurationText(valid),
			"networks", strings.Join(req.Networks, ",")}, s.auditActor()...)...)
		webuiReply(w, http.StatusCreated, map[string]string{"name": req.Name, "code": code})
	case "/api/secrets/revoke":
		if err := secrets.Remove(dir, req.Name); err != nil {
			webuiFail(w, http.StatusNotFound, err.Error())
			return
		}
		simpleca.Audit(dir, "secret.revoke", append([]any{"name", req.Name}, s.auditActor()...)...)
		webuiReply(w, http.StatusOK, map[string]string{"name": req.Name})
	}
}
