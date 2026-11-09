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

// Command request-token gets the tokens of a machine from simple-ca serve: the api token of a
// one-time setup code, and the JWT of workload identity federation, which it exchanges for an
// access token of Google Cloud or Microsoft Entra ID; it also writes the credential file of
// Google's Application Default Credentials and gcloud.
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

// client sends the requests of request-token, and maxAnswer is the most it reads of an answer.
var client = &http.Client{Timeout: 30 * time.Second}

const maxAnswer = 1 << 20

// defaultConfig is the configuration file read from the working directory without --config.
const defaultConfig = "federation.json"

// defaultScope is the scope of an Entra ID access token, and defaultGoogleScope of a Google one,
// without one given.
const (
	defaultScope       = "https://graph.microsoft.com/.default"
	defaultGoogleScope = "https://www.googleapis.com/auth/cloud-platform"
)

// stsURL is Google's Security Token Service, and jwtTokenType the token type of the JWT there.
const (
	stsURL       = "https://sts.googleapis.com/v1/token"
	jwtTokenType = "urn:ietf:params:oauth:token-type:jwt"
)

// settings are the settings of request-token, from the configuration file, the environment and
// the options: the URL of the CA, the api token or the file holding it, the provider of Google,
// the service account and the scope of its access token, and the tenant, the application and the
// scope of Entra ID.
type settings struct {
	CAURL          string `json:"ca_url"`
	Token          string `json:"token"`
	TokenFile      string `json:"token_file"`
	Provider       string `json:"provider"`
	ServiceAccount string `json:"service_account"`
	GoogleScope    string `json:"google_scope"`
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	Scope          string `json:"scope"`
}

// option is a setting given as an option: its name, its environment variable, its usage and its
// field of the settings.
type option struct {
	name, env, usage string
	field            func(*settings) *string
}

// options are the settings given as options; each subcommand takes those it names.
var options = map[string]option{
	"ca-url": {"ca-url", "SIMPLE_CA_URL", "`URL` of the CA, such as https://pki.example.com/gcp-wif",
		func(s *settings) *string { return &s.CAURL }},
	"token-file": {"token-file", "SIMPLE_CA_TOKEN_FILE", "`file` holding the api token",
		func(s *settings) *string { return &s.TokenFile }},
	"provider": {"provider", "SIMPLE_CA_PROVIDER", "Google: the `name` of the workload identity pool provider,\n" +
		"//iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/ID",
		func(s *settings) *string { return &s.Provider }},
	"service-account": {"service-account", "SIMPLE_CA_SERVICE_ACCOUNT", "Google: the `email` of the service account impersonated",
		func(s *settings) *string { return &s.ServiceAccount }},
	"google-scope": {"google-scope", "SIMPLE_CA_GOOGLE_SCOPE", "Google: the `scope` of the access token of the service account, else\n" +
		defaultGoogleScope, func(s *settings) *string { return &s.GoogleScope }},
	"tenant-id": {"tenant-id", "SIMPLE_CA_TENANT_ID", "Entra ID: the `tenant`",
		func(s *settings) *string { return &s.TenantID }},
	"client-id": {"client-id", "SIMPLE_CA_CLIENT_ID", "Entra ID: the application (client) `ID`",
		func(s *settings) *string { return &s.ClientID }},
	"scope": {"scope", "SIMPLE_CA_SCOPE", "Entra ID: the `scope` of the access token, else " + defaultScope,
		func(s *settings) *string { return &s.Scope }},
}

// subcommand is a subcommand of request-token: its name, its summary and its function.
type subcommand struct {
	name, summary string
	run           func(args []string) error
}

// subcommands lists the subcommands in the order of the usage text.
var subcommands = []subcommand{
	{"api", "Exchange a one-time setup code for the api token.", runAPI},
	{"jwt", "Print the JWT of workload identity federation of the api token.", runJWT},
	{"google-wif", "Print the federated access token of Google the JWT is exchanged for.", runGoogleWIF},
	{"google-access-token", "Print the access token of a Google service account.", runGoogleAccessToken},
	{"entra-id", "Print the Microsoft Entra ID access token of the JWT.", runEntraID},
	{"google-cred-config", "Write the credential file of Application Default Credentials and gcloud.", runGoogleCredConfig},
}

// usage prints the usage of request-token.
func usage(w io.Writer) {
	fmt.Fprint(w, "Usage:\n"+
		"  request-token SUBCOMMAND [options]\n"+
		"  request-token --version\n\n"+
		"Subcommands:\n")
	for _, c := range subcommands {
		fmt.Fprintf(w, "  %-21s %s\n", c.name, c.summary)
	}
	fmt.Fprint(w, "\nEach setting is read from the JSON file of --config, else federation.json of the\n"+
		"working directory, with the keys ca_url, token, token_file, provider, service_account,\n"+
		"google_scope, tenant_id, client_id and scope; an environment variable replaces it, and an\n"+
		"option replaces both. The token itself is given by the key token or SIMPLE_CA_TOKEN alone.\n"+
		"request-token SUBCOMMAND -h lists the options of a subcommand.\n")
}

func run() error {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return errUsage
	}
	name, args := os.Args[1], os.Args[2:]
	switch name {
	case "help", "-h", "-help", "--help":
		usage(os.Stdout)
		return nil
	case "version", "-version", "--version":
		version := buildVersion
		if info, ok := debug.ReadBuildInfo(); version == "" && ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		if version == "" {
			version = "dev"
		}
		fmt.Println("request-token", version)
		return nil
	}
	for _, c := range subcommands {
		if c.name == name {
			return c.run(args)
		}
	}
	fmt.Fprintf(os.Stderr, "request-token: unknown subcommand '%s'\n", name)
	usage(os.Stderr)
	return errUsage
}

// newFlagSet returns the flag set of the subcommand name, whose usage names its arguments and
// describes it.
func newFlagSet(name, arguments, description string) *flag.FlagSet {
	fs := flag.NewFlagSet("request-token "+name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  request-token %s [options]%s\n\n%s\n\nOptions:\n", name, arguments, description)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses args with fs, --config and the options named, and returns the settings of the
// file, replaced by those of the environment, replaced by the options given, and the path of the
// file read, empty without one.
func parse(fs *flag.FlagSet, args []string, names ...string) (settings, string, error) {
	configFile := fs.String("config", "", "JSON `file` of the settings (default: "+defaultConfig+" when it exists)")
	values := map[string]*string{}
	for _, name := range names {
		o := options[name]
		values[name] = fs.String(name, "", o.usage+" (default: "+o.env+")")
	}
	fs.Parse(args)

	s, path, err := readConfig(*configFile)
	if err != nil {
		return s, "", err
	}
	if os.Getenv("SIMPLE_CA_TOKEN") != "" && os.Getenv("SIMPLE_CA_TOKEN_FILE") != "" {
		return s, "", errors.New("give the token in SIMPLE_CA_TOKEN or in SIMPLE_CA_TOKEN_FILE, not both")
	}
	if v := os.Getenv("SIMPLE_CA_TOKEN"); v != "" {
		s.Token, s.TokenFile = v, ""
	}
	for _, o := range options {
		if v := os.Getenv(o.env); v != "" {
			*o.field(&s) = v
			if o.name == "token-file" {
				s.Token = ""
			}
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if v, ok := values[f.Name]; ok {
			*options[f.Name].field(&s) = *v
			if f.Name == "token-file" {
				s.Token = ""
			}
		}
	})
	return s, path, nil
}

// noArguments refuses the arguments left after the options of fs.
func noArguments(fs *flag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	fmt.Fprintf(fs.Output(), "%s: no arguments are taken, only options\n", fs.Name())
	fs.Usage()
	return errUsage
}

// readConfig returns the settings of the JSON file path, or of federation.json of the working
// directory, when it exists, without path, and the path of the file read. A key it does not know,
// or both token and token_file, are refused; a relative token_file is read relative to the file.
func readConfig(path string) (settings, string, error) {
	var s settings
	file := path
	if file == "" {
		file = defaultConfig
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
		return s, "", fmt.Errorf("could not read %s: %w", file, err)
	}
	if s.Token != "" && s.TokenFile != "" {
		return s, "", fmt.Errorf("%s: give token or token_file, not both", file)
	}
	if s.TokenFile != "" && !filepath.IsAbs(s.TokenFile) {
		s.TokenFile = filepath.Join(filepath.Dir(file), s.TokenFile)
	}
	return s, file, nil
}

// runAPI exchanges a one-time setup code for the api token, and prints it or writes it to the
// token file, a new file.
func runAPI(args []string) error {
	fs := newFlagSet("api", " CODE", "Exchanges the one-time setup code for the api token at /api/token-setup of the server\n"+
		"of the CA, and prints it, or writes it to the token file, a new file of mode 0600.")
	s, _, err := parse(fs, args, "ca-url", "token-file")
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(fs.Output(), "%s: the setup code is the one argument\n", fs.Name())
		fs.Usage()
		return errUsage
	}
	code := strings.TrimSpace(fs.Arg(0))
	if s.CAURL == "" {
		return errors.New("no URL of the CA: give ca_url, SIMPLE_CA_URL or --ca-url")
	}

	// The token file is made before the exchange, so a code is not spent on a file that exists.
	var file *os.File
	if s.TokenFile != "" {
		if file, err = os.OpenFile(s.TokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return fmt.Errorf("%w; the api token is written to a new file", err)
		}
	}
	token, err := exchange(s.CAURL, code)
	if err != nil {
		if file != nil {
			file.Close()
			os.Remove(s.TokenFile)
		}
		return err
	}
	if file == nil {
		fmt.Println(token)
		return nil
	}
	if _, err := file.WriteString(token + "\n"); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Token written to %s\n", s.TokenFile)
	return nil
}

// simpleCAJWT returns a new JWT of the api token of s, and when it expires.
func simpleCAJWT(s settings) (string, time.Time, error) {
	if s.CAURL == "" {
		return "", time.Time{}, errors.New("no URL of the CA: give ca_url, SIMPLE_CA_URL or --ca-url")
	}
	token := s.Token
	switch {
	case s.TokenFile != "":
		b, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return "", time.Time{}, err
		}
		if token = strings.TrimSpace(string(b)); token == "" {
			return "", time.Time{}, fmt.Errorf("%s is empty", s.TokenFile)
		}
	case token == "":
		return "", time.Time{}, errors.New("no token: give token, token_file, SIMPLE_CA_TOKEN, SIMPLE_CA_TOKEN_FILE or --token-file")
	}
	return federationToken(s.CAURL, token)
}

// runJWT prints the JWT of the api token, writes it to a file, or prints it as the answer of an
// executable source of Google's credential file.
func runJWT(args []string) error {
	fs := newFlagSet("jwt", "", "Requests a JWT of workload identity federation from simple-ca serve with the api token,\n"+
		"and prints it.")
	output := fs.String("output", "", "write the JWT to `file`, mode 0600, replacing it, instead of printing it")
	executable := fs.Bool("google-executable", false, "print the JWT as the answer of an executable source of Google's\n"+
		"credential file, also on an error")
	s, _, err := parse(fs, args, "ca-url", "token-file")
	if err == nil {
		err = noArguments(fs)
	}
	if err == nil && *output != "" && *executable {
		err = errors.New("give --output or --google-executable, not both")
	}
	var jwt string
	var expires time.Time
	if err == nil {
		jwt, expires, err = simpleCAJWT(s)
	}

	switch {
	case *executable:
		answer := map[string]any{"version": 1, "success": true, "token_type": jwtTokenType, "id_token": jwt,
			"expiration_time": expires.Unix()}
		if err != nil {
			answer = map[string]any{"version": 1, "success": false, "code": "request-token", "message": err.Error()}
		}
		b, jsonErr := json.Marshal(answer)
		if jsonErr != nil {
			return jsonErr
		}
		fmt.Println(string(b))
		return err
	case err != nil:
		return err
	case *output != "":
		return replaceFile(*output, jwt)
	}
	fmt.Println(jwt)
	return nil
}

// replaceFile writes data to path, mode 0600, through a new file in its directory renamed to it,
// so a reader never sees a part of it.
func replaceFile(path, data string) error {
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

// googleFederated returns the federated access token of Google of the JWT of the api token of s.
func googleFederated(s settings) (string, error) {
	if s.Provider == "" {
		return "", errors.New("no provider of Google: give provider, SIMPLE_CA_PROVIDER or --provider")
	}
	jwt, _, err := simpleCAJWT(s)
	if err != nil {
		return "", err
	}
	return googleToken(s.Provider, jwt)
}

// runGoogleWIF prints the federated access token of Google of the JWT.
func runGoogleWIF(args []string) error {
	fs := newFlagSet("google-wif", "", "Requests a JWT from simple-ca serve, exchanges it at Google's Security Token Service\n"+
		"for a federated access token of the workload identity pool provider, and prints it.")
	s, _, err := parse(fs, args, "ca-url", "token-file", "provider")
	if err != nil {
		return err
	}
	if err := noArguments(fs); err != nil {
		return err
	}
	token, err := googleFederated(s)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runGoogleAccessToken prints the access token of the service account the federated access token
// of Google impersonates.
func runGoogleAccessToken(args []string) error {
	fs := newFlagSet("google-access-token", "", "Requests a JWT from simple-ca serve, exchanges it for a federated access token of\n"+
		"Google, and that for an access token of the service account, which the principal of the\n"+
		"JWT impersonates with roles/iam.workloadIdentityUser, and prints it.")
	s, _, err := parse(fs, args, "ca-url", "token-file", "provider", "service-account", "google-scope")
	if err != nil {
		return err
	}
	if err := noArguments(fs); err != nil {
		return err
	}
	if s.ServiceAccount == "" {
		return errors.New("no service account: give service_account, SIMPLE_CA_SERVICE_ACCOUNT or --service-account")
	}
	if s.GoogleScope == "" {
		s.GoogleScope = defaultGoogleScope
	}
	federated, err := googleFederated(s)
	if err != nil {
		return err
	}
	token, err := serviceAccountToken(s.ServiceAccount, s.GoogleScope, federated)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runEntraID prints the Entra ID access token of the JWT.
func runEntraID(args []string) error {
	fs := newFlagSet("entra-id", "", "Requests a JWT from simple-ca serve, and gets an access token of the application of\n"+
		"Microsoft Entra ID by the client credentials flow, with the JWT as the client assertion,\n"+
		"and prints it.")
	s, _, err := parse(fs, args, "ca-url", "token-file", "tenant-id", "client-id", "scope")
	if err != nil {
		return err
	}
	if err := noArguments(fs); err != nil {
		return err
	}
	switch {
	case s.TenantID == "":
		return errors.New("no tenant of Entra ID: give tenant_id, SIMPLE_CA_TENANT_ID or --tenant-id")
	case s.ClientID == "":
		return errors.New("no client ID of Entra ID: give client_id, SIMPLE_CA_CLIENT_ID or --client-id")
	}
	if s.Scope == "" {
		s.Scope = defaultScope
	}
	jwt, _, err := simpleCAJWT(s)
	if err != nil {
		return err
	}
	token, err := entraToken(s.TenantID, s.ClientID, s.Scope, jwt)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runGoogleCredConfig writes the credential file of Google's Application Default Credentials and
// gcloud auth login --cred-file, whose JWT comes from request-token jwt or from a file.
func runGoogleCredConfig(args []string) error {
	fs := newFlagSet("google-cred-config", "", "Writes the credential file of the workload identity pool provider, for\n"+
		"GOOGLE_APPLICATION_CREDENTIALS and gcloud auth login --cred-file, impersonating the service\n"+
		"account when one is given. With the source executable, Google runs request-token jwt\n"+
		"--google-executable with the configuration file for each JWT, and needs\n"+
		"GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1; with the source file, it reads the JWT of\n"+
		"--jwt-file, which request-token jwt --output keeps fresh.")
	source := fs.String("credential-source", "executable", "where the JWT comes from: `executable` or file")
	jwtFile := fs.String("jwt-file", "", "the `file` of the JWT of the source file")
	outputFile := fs.String("output-file", "cred.json", "the credential `file` written, a new file of mode 0600")
	s, configPath, err := parse(fs, args, "provider", "service-account")
	if err != nil {
		return err
	}
	if err := noArguments(fs); err != nil {
		return err
	}
	if s.Provider == "" {
		return errors.New("no provider of Google: give provider, SIMPLE_CA_PROVIDER or --provider")
	}

	cred := map[string]any{
		"type":               "external_account",
		"audience":           s.Provider,
		"subject_token_type": jwtTokenType,
		"token_url":          stsURL,
	}
	if s.ServiceAccount != "" {
		cred["service_account_impersonation_url"] = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
			url.PathEscape(s.ServiceAccount) + ":generateAccessToken"
	}
	switch *source {
	case "executable":
		if *jwtFile != "" {
			return errors.New("--jwt-file belongs to the source file")
		}
		if configPath == "" {
			return errors.New("the source executable needs the configuration file of request-token jwt: give --config, or " +
				defaultConfig + " in the working directory")
		}
		program, err := os.Executable()
		if err != nil {
			return err
		}
		if program, err = filepath.Abs(program); err != nil {
			return err
		}
		config, err := filepath.Abs(configPath)
		if err != nil {
			return err
		}
		cred["credential_source"] = map[string]any{"executable": map[string]any{
			"command":        program + " jwt --google-executable --config " + config,
			"timeout_millis": 30000,
		}}
	case "file":
		if *jwtFile == "" {
			return errors.New("the source file needs --jwt-file")
		}
		path, err := filepath.Abs(*jwtFile)
		if err != nil {
			return err
		}
		cred["credential_source"] = map[string]any{"file": path, "format": map[string]string{"type": "text"}}
	default:
		return fmt.Errorf("unknown credential source '%s': must be executable or file", *source)
	}

	b, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w; the credential file is written to a new file", err)
	}
	if _, err := file.Write(append(b, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Credential file written to %s\n", *outputFile)
	if *source == "executable" {
		fmt.Fprintln(os.Stderr, "Google runs its command only with GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1.")
	}
	return nil
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
// /api/federation-token of the CA at caURL, and when it expires.
func federationToken(caURL, token string) (string, time.Time, error) {
	target := strings.TrimSuffix(strings.TrimSuffix(caURL, "/"), "/api/federation-token") + "/api/federation-token"
	var result struct {
		Token   string
		Expires time.Time
	}
	if err := post(target, "application/json", token, []byte("{}"), &result); err != nil {
		return "", time.Time{}, err
	}
	if result.Token == "" {
		return "", time.Time{}, fmt.Errorf("%s: the answer holds no token", target)
	}
	return result.Token, result.Expires, nil
}

// googleToken exchanges jwt at Google's Security Token Service for a federated access token of
// the workload identity pool provider, of the scope cloud-platform.
func googleToken(provider, jwt string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":           provider,
		"scope":              defaultGoogleScope,
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   jwtTokenType,
		"subjectToken":       jwt,
	})
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := post(stsURL, "application/json", "", body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%s: the answer holds no access_token", stsURL)
	}
	return result.AccessToken, nil
}

// serviceAccountToken exchanges the federated access token of Google for an access token of the
// service account email, of scope, at generateAccessToken of the IAM Service Account Credentials
// API.
func serviceAccountToken(email, scope, federated string) (string, error) {
	target := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(email) +
		":generateAccessToken"
	body, err := json.Marshal(map[string][]string{"scope": {scope}})
	if err != nil {
		return "", err
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := post(target, "application/json", federated, body, &result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("%s: the answer holds no accessToken", target)
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
		fmt.Fprintln(os.Stderr, "request-token:", err)
		os.Exit(1)
	}
}
