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
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/pkg/simpleca/tokens"
)

// ---- token issuer -----------------------------------------------------------

// serveTokenIssuer answers, for the CA caID of rootDir, GET .well-known/openid-configuration with
// the OpenID Connect discovery document of its JWTs, and GET jwks.json with their keys; a CA
// without an issuer is not found.
func serveTokenIssuer(w http.ResponseWriter, r *http.Request, rootDir, caID string, discovery bool) {
	dir := filepath.Join(rootDir, caID)
	if caID != "" && (!simpleca.KebabCaseRE.MatchString(caID) || !simpleca.FileExists(filepath.Join(dir, "ca_cert.pem"))) {
		http.NotFound(w, r)
		return
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the settings", http.StatusInternalServerError)
		return
	}
	issuer := tokens.Issuer(cfg, caID)
	if issuer == "" {
		http.NotFound(w, r)
		return
	}
	var b []byte
	if discovery {
		var cert *x509.Certificate
		if cert, err = simpleca.LoadCert(filepath.Join(dir, "ca_cert.pem")); err == nil {
			b, err = json.MarshalIndent(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks.json",
				"id_token_signing_alg_values_supported": []string{jose.JWTAlg(cert.PublicKey)},
				"response_types_supported":              []string{"id_token"}, "subject_types_supported": []string{"public"}}, "", "  ")
		}
	} else {
		b, err = tokens.CAJWKS(dir)
	}
	if err != nil {
		slog.Error("serve.error", "path", r.URL.Path, "error", err.Error())
		http.Error(w, "could not read the CA", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(append(b, '\n'))
}
