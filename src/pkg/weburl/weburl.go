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

// Package weburl checks the URLs the programs are given: the URL of a server, the URL of a CA
// at a server, and the URL of an endpoint of another service.
package weburl

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// caNameRE matches the name of an issuing CA, as simpleca.KebabCaseRE does.
var caNameRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// parse returns raw parsed as an absolute URL of the scheme https, or also http unless
// httpsOnly, with a host name, a port of 1 to 65535 when one is given, and no user info or
// fragment; form is the form of the URL named in the errors.
func parse(raw string, httpsOnly bool, form string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%q is not a URL such as %s", raw, form)
	}
	switch {
	case u.Scheme != "https" && (httpsOnly || u.Scheme != "http"):
		if httpsOnly {
			return nil, fmt.Errorf("%q is not an https URL such as %s", raw, form)
		}
		return nil, fmt.Errorf("%q is not an http or https URL such as %s", raw, form)
	case u.Opaque != "" || u.Hostname() == "":
		return nil, fmt.Errorf("%q has no host: it must be a URL such as %s", raw, form)
	case u.User != nil:
		return nil, fmt.Errorf("%q has a user name: it must be a URL such as %s", raw, form)
	case u.Fragment != "" || strings.HasSuffix(raw, "#"):
		return nil, fmt.Errorf("%q has a fragment: it must be a URL such as %s", raw, form)
	}
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q has the port %q, not one of 1 to 65535", raw, port)
		}
	}
	return u, nil
}

// server returns the scheme and the host of u, with its port.
func server(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// Server returns the URL of a server raw, its scheme and its host with an optional port, such
// as https://pki.example.com:8443, without a trailing /; raw has no path, query or fragment.
func Server(raw string, httpsOnly bool) (string, error) {
	form := "https://pki.example.com or https://pki.example.com:8443"
	u, err := parse(raw, httpsOnly, form)
	if err != nil {
		return "", err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("%q has a path or a query: it must be the URL of a server such as %s", raw, form)
	}
	return server(u), nil
}

// CA returns the server of the CA URL raw and the name of its issuing CA: raw is the URL of a
// server for the root CA, with an empty ca, or that URL and /NAME of an issuing CA, such as
// https://pki.example.com/servers, with an optional trailing /.
func CA(raw string) (srv, ca string, err error) {
	form := "https://pki.example.com for the root CA, or https://pki.example.com/NAME for the issuing CA NAME"
	u, err := parse(raw, false, form)
	if err != nil {
		return "", "", err
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", fmt.Errorf("%q has a query: it must be a URL such as %s", raw, form)
	}
	name := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/"), "/")
	if (name != "" || (u.Path != "" && u.Path != "/")) && !caNameRE.MatchString(name) {
		return "", "", fmt.Errorf("%q has the path %q, not /NAME of an issuing CA: it must be a URL such as %s",
			raw, u.Path, form)
	}
	return server(u), name, nil
}

// Endpoint returns the URL raw of an endpoint of another service, such as
// https://sso.example.com/realms/lab, as it is given; its path and query are kept.
func Endpoint(raw string, httpsOnly bool) (string, error) {
	if _, err := parse(raw, httpsOnly, "https://sso.example.com/realms/lab"); err != nil {
		return "", err
	}
	return raw, nil
}
