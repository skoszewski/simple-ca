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
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/client"
	"github.com/skoszewski/simple-ca/src/pkg/weburl"
)

// oidcSettings are the settings of GET /api/oidc of serve that request-cert signs in with: its
// public client, the scopes it asks for, the claims of the email address and the endpoints of
// the provider.
type oidcSettings struct {
	CLIClientID                 string   `json:"cli_client_id"`
	CLIScopes                   []string `json:"cli_scopes"`
	EmailClaim                  []string `json:"email_claim"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
}

// The waits of the sign-in, which the tests shorten: the longest wait for the browser to come
// back, and the unit of the polling interval of the device authorization grant.
var (
	loopbackTimeout = 5 * time.Minute
	pollUnit        = time.Second
)

// openBrowser opens url in the browser of the desktop.
var openBrowser = func(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

// fileNameRE matches the characters replaced in the local part of an email address that names
// the files.
var fileNameRE = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// signInSettings returns the settings of the OIDC sign-in of request-cert at serve srv.
func signInSettings(srv string) (*oidcSettings, error) {
	var s oidcSettings
	if err := client.Get(srv+"/api/oidc", &s); err != nil {
		if e, ok := errors.AsType[*client.StatusError](err); ok && e.Code == http.StatusNotFound {
			return nil, fmt.Errorf("%q has no OIDC sign-in", srv)
		}
		return nil, err
	}
	if s.CLIClientID == "" {
		return nil, fmt.Errorf("%q has no OIDC client for request-cert: oidc.cli_client_id is not set", srv)
	}
	for _, endpoint := range []string{s.AuthorizationEndpoint, s.TokenEndpoint, s.DeviceAuthorizationEndpoint} {
		if endpoint == s.DeviceAuthorizationEndpoint && endpoint == "" {
			continue
		}
		if _, err := weburl.Endpoint(endpoint, false); err != nil {
			return nil, fmt.Errorf("the OIDC settings of %q: %w", srv, err)
		}
	}
	return &s, nil
}

// randomText returns 32 random bytes in base64url.
func randomText() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// idTokenClaims returns the claims of the ID token raw, unverified, which serve verifies.
func idTokenClaims(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("the ID token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return nil, errors.New("the claims of the ID token do not read")
	}
	return claims, nil
}

// filePrefix returns the local part of the email address of the claims at the dotted paths of
// emailClaim, each run of characters besides letters, digits, - and _ as one _, else user.
func filePrefix(claims map[string]any, emailClaim []string) string {
	for _, path := range emailClaim {
		var v any = claims
		for _, segment := range strings.Split(path, ".") {
			m, _ := v.(map[string]any)
			v = m[segment]
		}
		if email, ok := v.(string); ok && email != "" {
			local, _, _ := strings.Cut(email, "@")
			if name := strings.Trim(fileNameRE.ReplaceAllString(local, "_"), "_"); name != "" {
				return name
			}
		}
	}
	return "user"
}

// tokenRequest posts form to the token endpoint and returns the ID token of the answer, or the
// OAuth error code of a refusal with its error.
func tokenRequest(endpoint string, form url.Values) (idToken, errorCode string, err error) {
	var answer struct {
		IDToken string `json:"id_token"`
	}
	err = client.Post(endpoint, "application/x-www-form-urlencoded", "", []byte(form.Encode()), &answer)
	if e, ok := errors.AsType[*client.StatusError](err); ok {
		return "", e.ErrorCode, err
	}
	if err == nil && answer.IDToken == "" {
		err = fmt.Errorf("%q gave no ID token; the scopes must hold openid", endpoint)
	}
	return answer.IDToken, "", err
}

// loopbackSignIn signs in with the authorization code flow with PKCE, the browser sent back to a
// loopback redirect URI of a port of 127.0.0.1, and returns the ID token; without noBrowser, the
// browser is opened at the authorization URL, which is printed in any case.
func loopbackSignIn(s *oidcSettings, noBrowser bool) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)
	verifier, state, nonce := randomText(), randomText(), randomText()
	challenge := sha256.Sum256([]byte(verifier))
	authURL, err := url.Parse(s.AuthorizationEndpoint)
	if err != nil {
		listener.Close()
		return "", err
	}
	query := authURL.Query()
	for key, value := range map[string]string{"response_type": "code", "client_id": s.CLIClientID,
		"redirect_uri": redirectURI, "scope": strings.Join(s.CLIScopes, " "), "state": state, "nonce": nonce,
		"code_challenge": base64.RawURLEncoding.EncodeToString(challenge[:]), "code_challenge_method": "S256"} {
		query.Set(key, value)
	}
	authURL.RawQuery = query.Encode()

	// The one answer of the provider: a code, or a refusal, of the state of this sign-in.
	type callback struct {
		code string
		err  error
	}
	done := make(chan callback, 1)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/" || q.Get("state") != state {
			http.NotFound(w, r)
			return
		}
		result := callback{code: q.Get("code")}
		text := "Signed in. You can close this tab and go back to request-cert."
		switch {
		case q.Get("error") != "":
			result.err = fmt.Errorf("the provider refused the sign-in: %s", cmp.Or(q.Get("error_description"), q.Get("error")))
			text = result.err.Error()
		case result.code == "":
			result.err = errors.New("the provider sent no authorization code")
			text = result.err.Error()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>request-cert</title></head>"+
			"<body><p>%s</p></body></html>\n", html.EscapeString(text))
		select {
		case done <- result:
		default:
		}
	})}
	go server.Serve(listener)
	defer server.Close()

	fmt.Printf("Sign in at this URL, which the browser opens:\n  %s\n", authURL)
	if !noBrowser {
		if err := openBrowser(authURL.String()); err != nil {
			fmt.Printf("The browser could not be opened (%v); open the URL yourself.\n", err)
		}
	}
	var result callback
	select {
	case result = <-done:
	case <-time.After(loopbackTimeout):
		return "", fmt.Errorf("no sign-in within %s", loopbackTimeout)
	}
	if result.err != nil {
		return "", result.err
	}
	idToken, _, err := tokenRequest(s.TokenEndpoint, url.Values{"grant_type": {"authorization_code"}, "code": {result.code},
		"client_id": {s.CLIClientID}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}})
	if err != nil {
		return "", err
	}
	claims, err := idTokenClaims(idToken)
	if err != nil {
		return "", err
	}
	if claims["nonce"] != nonce {
		return "", errors.New("the ID token does not answer this sign-in: its nonce differs")
	}
	return idToken, nil
}

// deviceSignIn signs in with the device authorization grant, printing the code the user enters
// at the verification URL, and returns the ID token.
func deviceSignIn(s *oidcSettings) (string, error) {
	if s.DeviceAuthorizationEndpoint == "" {
		return "", errors.New("the OIDC provider has no device authorization endpoint; sign in with --oidc")
	}
	var d struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	form := url.Values{"client_id": {s.CLIClientID}, "scope": {strings.Join(s.CLIScopes, " ")}}
	if err := client.Post(s.DeviceAuthorizationEndpoint, "application/x-www-form-urlencoded", "", []byte(form.Encode()), &d); err != nil {
		return "", err
	}
	if d.DeviceCode == "" || d.UserCode == "" || d.VerificationURI == "" {
		return "", fmt.Errorf("%q answers without a device code, a user code or a verification URL", s.DeviceAuthorizationEndpoint)
	}
	fmt.Printf("Sign in at %s with the code %s\n", d.VerificationURI, d.UserCode)
	if d.VerificationURIComplete != "" {
		fmt.Printf("or at %s\n", d.VerificationURIComplete)
	}
	interval := time.Duration(cmp.Or(d.Interval, 5)) * pollUnit
	deadline := time.Now().Add(time.Duration(cmp.Or(d.ExpiresIn, 300)) * pollUnit)
	for {
		time.Sleep(interval)
		if time.Now().After(deadline) {
			return "", errors.New("the device code has expired; sign in again")
		}
		idToken, code, err := tokenRequest(s.TokenEndpoint, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {d.DeviceCode}, "client_id": {s.CLIClientID}})
		switch code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * pollUnit
		default:
			return idToken, err
		}
	}
}
