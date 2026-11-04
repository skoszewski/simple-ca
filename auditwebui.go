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
	"net/http"
	"slices"
	"strconv"
)

// ---- the audit page of serve ------------------------------------------------

// auditLimit is the number of records the audit page gets by default.
const auditLimit = 1000

// auditAPI answers a request of the audit page:
//
//	GET /api/entries?limit=N    the newest records of the audit log of the server, auditLimit
//	                            without limit, and the count of all of them; an issuing CA token
//	                            gets those of its own CA
func (s *webuiServer) auditAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/api/entries" {
		webuiFail(w, http.StatusNotFound, "no such request")
		return
	}
	limit := auditLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			webuiFail(w, http.StatusBadRequest, "limit: '"+v+"' is not a positive number")
			return
		}
		limit = n
	}
	all, err := readAudit(s.rootDir)
	if err != nil {
		slog.Error("serve.error", "error", err.Error())
		webuiFail(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	entries, total := []auditEntry{}, 0
	for _, e := range slices.Backward(all) {
		if s.userCA != "" && e.CA != s.userCA {
			continue
		}
		if total++; len(entries) < limit {
			entries = append(entries, e)
		}
	}
	webuiReply(w, http.StatusOK, map[string]any{"entries": entries, "total": total})
}
