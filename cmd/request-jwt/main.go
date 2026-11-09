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

// Command request-jwt requests a JWT of workload identity federation from simple-ca serve, and
// exchanges it for an access token of Google Cloud or Microsoft Entra ID.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

// client sends the requests of request-jwt, and maxAnswer is the most it reads of an answer.
var client = &http.Client{Timeout: 30 * time.Second}

const maxAnswer = 1 << 20

// defaultConfig is the configuration file read from the working directory without --config.
const defaultConfig = "federation.json"

// defaultScope is the scope of an Entra ID access token without one given.
const defaultScope = "https://graph.microsoft.com/.default"

// settings are the settings of request-jwt, from the configuration file, the environment and the
// options: the URL of the CA, the api token with the scope federate or the file holding it, the
// provider of Google, and the tenant, the application and the scope of Entra ID.
type settings struct {
	CAURL     string `json:"ca_url"`
	Token     string `json:"token"`
	TokenFile string `json:"token_file"`
	Provider  string `json:"provider"`
	TenantID  string `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
}

func run() error {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Usage:\n"+
			"  request-jwt [options]\n\n"+
			"Requests a JWT of workload identity federation from simple-ca serve, with an api token\n"+
			"with the scope federate, and prints it; with --provider, it prints the Google access\n"+
			"token the JWT is exchanged for, and with --tenant-id, the Microsoft Entra ID one.\n\n"+
			"Each setting is read from the JSON file of --config, else federation.json of the\n"+
			"working directory, with the keys ca_url, token, token_file, provider, tenant_id,\n"+
			"client_id and scope; an environment variable replaces it, and an option replaces both.\n"+
			"The token itself is given by the key token or SIMPLE_CA_TOKEN alone.\n\n"+
			"Options:\n")
		flag.PrintDefaults()
	}
	configFile := flag.String("config", "", "JSON `file` of the settings (default: "+defaultConfig+" when it exists)")
	caURL := flag.String("ca-url", "", "`URL` of the CA, such as https://pki.example.com/gcp-wif (default: SIMPLE_CA_URL)")
	tokenFile := flag.String("token-file", "", "`file` holding the token, or the token of --setup-code is written to\n"+
		"(default: SIMPLE_CA_TOKEN_FILE)")
	setupCode := flag.String("setup-code", "", "one-time setup `code` exchanged for the token")
	provider := flag.String("provider", "", "Google: the `name` of the workload identity pool provider,\n"+
		"//iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/ID\n"+
		"(default: SIMPLE_CA_PROVIDER)")
	tenantID := flag.String("tenant-id", "", "Entra ID: the `tenant` (default: SIMPLE_CA_TENANT_ID)")
	clientID := flag.String("client-id", "", "Entra ID: the application (client) `ID` (default: SIMPLE_CA_CLIENT_ID)")
	scope := flag.String("scope", "", "Entra ID: the `scope` of the access token (default: SIMPLE_CA_SCOPE, else\n"+defaultScope+")")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		if version == "" {
			version = "dev"
		}
		fmt.Println("request-jwt", version)
		return nil
	}
	if flag.NArg() > 0 {
		fmt.Fprintln(flag.CommandLine.Output(), "request-jwt: no arguments are taken, only options")
		flag.Usage()
		return errUsage
	}

	// The settings of the file, replaced by those of the environment, replaced by the options.
	s, err := readConfig(*configFile)
	if err != nil {
		return err
	}
	if os.Getenv("SIMPLE_CA_TOKEN") != "" && os.Getenv("SIMPLE_CA_TOKEN_FILE") != "" {
		return errors.New("give the token in SIMPLE_CA_TOKEN or in SIMPLE_CA_TOKEN_FILE, not both")
	}
	if v := os.Getenv("SIMPLE_CA_TOKEN"); v != "" {
		s.Token, s.TokenFile = v, ""
	}
	if v := os.Getenv("SIMPLE_CA_TOKEN_FILE"); v != "" {
		s.Token, s.TokenFile = "", v
	}
	for name, field := range map[string]*string{"SIMPLE_CA_URL": &s.CAURL, "SIMPLE_CA_PROVIDER": &s.Provider,
		"SIMPLE_CA_TENANT_ID": &s.TenantID, "SIMPLE_CA_CLIENT_ID": &s.ClientID, "SIMPLE_CA_SCOPE": &s.Scope} {
		if v := os.Getenv(name); v != "" {
			*field = v
		}
	}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "ca-url":
			s.CAURL = *caURL
		case "token-file":
			s.Token, s.TokenFile = "", *tokenFile
		case "provider":
			s.Provider = *provider
		case "tenant-id":
			s.TenantID = *tenantID
		case "client-id":
			s.ClientID = *clientID
		case "scope":
			s.Scope = *scope
		}
	})

	switch {
	case s.CAURL == "":
		return errors.New("no URL of the CA: give ca_url, SIMPLE_CA_URL or --ca-url")
	case s.Provider != "" && s.TenantID != "":
		return errors.New("give the provider of Google or the tenant of Entra ID, not both")
	case s.TenantID != "" && s.ClientID == "":
		return errors.New("the tenant of Entra ID needs the client ID: give client_id, SIMPLE_CA_CLIENT_ID or --client-id")
	case s.TenantID == "" && (s.ClientID != "" || s.Scope != ""):
		return errors.New("the client ID and the scope belong to Entra ID: give its tenant too")
	}
	if s.Scope == "" {
		s.Scope = defaultScope
	}

	// The token: of a setup code, written to a new token file when one is given; else of the file.
	token, code := s.Token, strings.TrimSpace(*setupCode)
	switch {
	case code != "" && token != "":
		return errors.New("give the token or a setup code with --setup-code, not both")
	case code != "":
		var file *os.File
		if s.TokenFile != "" {
			if file, err = os.OpenFile(s.TokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
				return fmt.Errorf("%w; the token of --setup-code is written to a new file", err)
			}
		}
		if token, err = exchange(s.CAURL, code); err != nil {
			if file != nil {
				file.Close()
				os.Remove(s.TokenFile)
			}
			return err
		}
		if file != nil {
			if _, err := file.WriteString(token + "\n"); err != nil {
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Token written to %s\n", s.TokenFile)
		}
	case s.TokenFile != "":
		b, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return err
		}
		if token = strings.TrimSpace(string(b)); token == "" {
			return fmt.Errorf("%s is empty", s.TokenFile)
		}
	case token == "":
		return errors.New("no token: give token, token_file, SIMPLE_CA_TOKEN, SIMPLE_CA_TOKEN_FILE, --token-file or --setup-code")
	}

	jwt, err := federationToken(s.CAURL, token)
	if err != nil {
		return err
	}
	switch {
	case s.Provider != "":
		jwt, err = googleToken(s.Provider, jwt)
	case s.TenantID != "":
		jwt, err = entraToken(s.TenantID, s.ClientID, s.Scope, jwt)
	}
	if err != nil {
		return err
	}
	fmt.Println(jwt)
	return nil
}

// readConfig returns the settings of the JSON file path, or of federation.json of the working
// directory, when it exists, without path. A key it does not know, or both token and token_file,
// are refused; a relative token_file is read relative to the file.
func readConfig(path string) (settings, error) {
	var s settings
	file := path
	if file == "" {
		file = defaultConfig
	}
	b, err := os.ReadFile(file)
	switch {
	case path == "" && errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("could not read %s: %w", file, err)
	}
	if s.Token != "" && s.TokenFile != "" {
		return s, fmt.Errorf("%s: give token or token_file, not both", file)
	}
	if s.TokenFile != "" && !filepath.IsAbs(s.TokenFile) {
		s.TokenFile = filepath.Join(filepath.Dir(file), s.TokenFile)
	}
	return s, nil
}

// post sends body of contentType to target, with the bearer token when it is not empty, and
// decodes the JSON answer into result; an answer that is not 200 OK is returned as an error with
// its status and its message, of the field error_description or error, or the text of the answer.
func post(target, contentType, bearer string, body []byte, result any) error {
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
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
		return fmt.Errorf("%s: %d %s", target, resp.StatusCode, message)
	}
	if err := json.Unmarshal(answer, result); err != nil {
		return fmt.Errorf("%s: %w", target, err)
	}
	return nil
}

// federationToken returns a new JWT of the token type of the api token, from
// /api/federation-token of the CA at caURL.
func federationToken(caURL, token string) (string, error) {
	target := strings.TrimSuffix(strings.TrimSuffix(caURL, "/"), "/api/federation-token") + "/api/federation-token"
	var result struct{ Token string }
	if err := post(target, "application/json", token, []byte("{}"), &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("%s: the answer holds no token", target)
	}
	return result.Token, nil
}

// googleToken exchanges jwt at Google's Security Token Service for an access token of the
// workload identity pool provider, of the scope cloud-platform.
func googleToken(provider, jwt string) (string, error) {
	const target = "https://sts.googleapis.com/v1/token"
	body, err := json.Marshal(map[string]string{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":           provider,
		"scope":              "https://www.googleapis.com/auth/cloud-platform",
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
		"subjectToken":       jwt,
	})
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := post(target, "application/json", "", body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%s: the answer holds no access_token", target)
	}
	return result.AccessToken, nil
}

// entraToken gets an access token of the application clientID of the Entra ID tenant, of scope,
// by the client credentials flow, with jwt as the client assertion of a federated credential.
func entraToken(tenant, clientID, scope, jwt string) (string, error) {
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
	if err := post(target, "application/x-www-form-urlencoded", "", []byte(form.Encode()), &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%s: the answer holds no access_token", target)
	}
	return result.AccessToken, nil
}

// exchange exchanges the setup code at /api/token-setup of the server of the CA at caURL, and
// returns the token.
func exchange(caURL, code string) (string, error) {
	u, err := url.Parse(caURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%s is not a URL such as https://pki.example.com/gcp-wif", caURL)
	}
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return "", err
	}
	var result struct{ Token string }
	target := u.Scheme + "://" + u.Host + "/api/token-setup"
	if err := post(target, "application/json", "", body, &result); err != nil {
		return "", err
	}
	if result.Token == "" {
		return "", fmt.Errorf("%s: the answer holds no token", target)
	}
	return result.Token, nil
}

func main() {
	if err := run(); errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "request-jwt:", err)
		os.Exit(1)
	}
}
