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

// Package client holds the client code of the commands of simple-ca: the requests to
// simple-ca serve, to Google's Security Token Service and IAM Service Account Credentials
// API and to Microsoft Entra ID, and the configuration file federation.json.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/weburl"
)

// Client sends the requests of the package.
var Client = &http.Client{Timeout: 30 * time.Second}

// MaxAnswer is the most that is read of an answer.
const MaxAnswer = 1 << 20

// DefaultConfig is the configuration file ReadConfig reads from the working directory
// without a path.
const DefaultConfig = "federation.json"

// DefaultEntraScope is the scope of an Entra ID access token, and DefaultGoogleScope of a
// Google one, without one given.
const (
	DefaultEntraScope  = "https://graph.microsoft.com/.default"
	DefaultGoogleScope = "https://www.googleapis.com/auth/cloud-platform"
)

// STSURL is Google's Security Token Service, and JWTTokenType the token type of the JWT
// there.
const (
	STSURL       = "https://sts.googleapis.com/v1/token"
	JWTTokenType = "urn:ietf:params:oauth:token-type:jwt"
)

// Settings are the keys of federation.json: the URL of the CA, the api token or the file
// holding it, the provider of Google, the service account and the scope of its access
// token, and the tenant, the application and the scope of Entra ID; empty keys are not
// written.
type Settings struct {
	CAURL          string `json:"ca_url,omitempty"`
	Token          string `json:"token,omitempty"`
	TokenFile      string `json:"token_file,omitempty"`
	Provider       string `json:"provider,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	GoogleScope    string `json:"google_scope,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	Scope          string `json:"scope,omitempty"`
}

// ReadConfig returns the settings of the JSON file path, or of federation.json of the working
// directory, when it exists, without path, and the path of the file read. A key it does not know,
// or both token and token_file, are refused; a relative token_file is read relative to the file.
func ReadConfig(path string) (Settings, string, error) {
	var s Settings
	file := path
	if file == "" {
		file = DefaultConfig
	}
	b, err := os.ReadFile(file)
	switch {
	case path == "" && errors.Is(err, os.ErrNotExist):
		return s, "", nil
	case err != nil:
		return s, "", err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, "", fmt.Errorf("could not read %q: %w", file, err)
	}
	if s.Token != "" && s.TokenFile != "" {
		return s, "", fmt.Errorf("%q: give token or token_file, not both", file)
	}
	if s.TokenFile != "" && !filepath.IsAbs(s.TokenFile) {
		s.TokenFile = filepath.Join(filepath.Dir(file), s.TokenFile)
	}
	return s, file, nil
}

// ReplaceFile writes data to path, mode 0600, through a new file in its directory renamed to it,
// so a reader never sees a part of it.
func ReplaceFile(path, data string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// StatusError is an answer that is not 200 OK: its target, its status and its message.
type StatusError struct {
	Target  string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%q: %d %q", e.Target, e.Code, e.Message)
}

// Post sends body of contentType to target, with the bearer token when it is not empty, and
// decodes the JSON answer into result; an answer that is not 200 OK is a *StatusError with its
// message, of the field error_description or error, or the text of the answer.
func Post(target, contentType, bearer string, body []byte, result any) error {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, MaxAnswer))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(answer))
		var e struct {
			Error            any    `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(answer, &e) == nil {
			if s, ok := e.Error.(string); ok && s != "" {
				message = s
			}
			if e.ErrorDescription != "" {
				message = e.ErrorDescription
			}
		}
		return &StatusError{Target: target, Code: resp.StatusCode, Message: message}
	}
	if err := json.Unmarshal(answer, result); err != nil {
		return fmt.Errorf("%q: %w", target, err)
	}
	return nil
}

// PostCA posts as Post does to path of the CA at the CA URL caURL, such as /api/sign; an answer
// 404 of an issuing CA is the error that the server has no such issuing CA.
func PostCA(caURL, path, bearer string, body []byte, result any) error {
	srv, ca, err := weburl.CA(caURL)
	if err != nil {
		return err
	}
	target := srv + path
	if ca != "" {
		target = srv + "/" + ca + path
	}
	err = Post(target, "application/json", bearer, body, result)
	if e, ok := errors.AsType[*StatusError](err); ok && e.Code == http.StatusNotFound && ca != "" {
		return fmt.Errorf("%q has no issuing CA %s", srv, ca)
	}
	return err
}

// Exchange exchanges the setup code at /api/token-setup of the server of the CA at caURL, and
// returns the token.
func Exchange(caURL, code string) (string, error) {
	srv, _, err := weburl.CA(caURL)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return "", err
	}
	var result struct{ Token string }
	target := srv + "/api/token-setup"
	if err := Post(target, "application/json", "", body, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("%q: the answer holds no token", target)
	}
	return result.Token, nil
}

// FederationToken returns a new JWT of the token type of the api token, from
// /api/federation-token of the CA at the CA URL caURL, and when it expires.
func FederationToken(caURL, token string) (string, time.Time, error) {
	var result struct {
		Token   string
		Expires time.Time
	}
	if err := PostCA(caURL, "/api/federation-token", token, []byte("{}"), &result); err != nil {
		return "", time.Time{}, err
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("%q: the answer holds no token", caURL)
	}
	return result.Token, result.Expires, nil
}

// GoogleToken exchanges jwt at Google's Security Token Service for a federated access token of
// the workload identity pool provider, of the scope cloud-platform.
func GoogleToken(provider, jwt string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":           provider,
		"scope":              DefaultGoogleScope,
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   JWTTokenType,
		"subjectToken":       jwt,
	})
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := Post(STSURL, "application/json", "", body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%s: the answer holds no access_token", STSURL)
	}
	return result.AccessToken, nil
}

// ServiceAccountToken exchanges the federated access token of Google for an access token of the
// service account email, of scope, at generateAccessToken of the IAM Service Account Credentials
// API.
func ServiceAccountToken(email, scope, federated string) (string, error) {
	target := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) +
		":generateAccessToken"
	body, err := json.Marshal(map[string][]string{"scope": {scope}})
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := Post(target, "application/json", federated, body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%q: the answer holds no accessToken", target)
	}
	return result.AccessToken, nil
}

// EntraToken gets an access token of the application clientID of the Entra ID tenant, of scope,
// by the client credentials flow, with jwt as the client assertion of a federated credential.
func EntraToken(tenant, clientID, scope, jwt string) (string, error) {
	target := "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	form := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"scope":                 {scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {jwt},
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := Post(target, "application/x-www-form-urlencoded", "", []byte(form.Encode()), &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%q: the answer holds no access_token", target)
	}
	return result.AccessToken, nil
}
