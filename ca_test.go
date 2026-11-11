package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/simpleca/cert"
)

func TestReservedNames(t *testing.T) {
	var pages []string
	for _, path := range []string{helpPath, docsPath, tokensPath, certsPath, auditPagePath, downloadsPath, aptPath} {
		pages = append(pages, strings.Trim(path, "/"))
	}
	if !slices.Equal(cert.ReservedNames, pages) {
		t.Errorf("cert.ReservedNames = %v, want the paths of the pages of serve, %v", cert.ReservedNames, pages)
	}
}
