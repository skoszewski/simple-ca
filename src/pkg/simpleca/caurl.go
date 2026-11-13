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

package simpleca

import (
	"fmt"
	"path/filepath"

	"github.com/skoszewski/simple-ca/src/pkg/weburl"
)

// IssuingCAExists reports whether the root CA in rootDir has the issuing CA name: a kebab-case
// name whose directory holds ca_cert.pem.
func IssuingCAExists(rootDir, name string) bool {
	return KebabCaseRE.MatchString(name) && FileExists(filepath.Join(rootDir, name, "ca_cert.pem"))
}

// CheckCAURL returns the issuing CA of the CA URL raw, empty for the root CA, after checking
// that the root CA in rootDir has it.
func CheckCAURL(rootDir, raw string) (string, error) {
	_, ca, err := weburl.CA(raw)
	if err != nil {
		return "", err
	}
	if ca != "" && !IssuingCAExists(rootDir, ca) {
		return "", fmt.Errorf("%q names the issuing CA %s, which the root CA in %q does not have", raw, ca, rootDir)
	}
	return ca, nil
}
