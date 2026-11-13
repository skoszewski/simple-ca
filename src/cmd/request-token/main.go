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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/client"
	"github.com/skoszewski/simple-ca/src/pkg/weburl"
)

// buildVersion is the version a release build is given at link time with
// -ldflags "-X main.buildVersion=...", empty otherwise.
var buildVersion string

// errUsage reports wrong arguments, after the usage has been printed.
var errUsage = errors.New("usage")

// option is a setting given as an option: its name, its environment variable, its usage and its
// field of the settings.
type option struct {
	name, env, usage string
	field            func(*client.Settings) *string
}

// options are the settings given as options; each subcommand takes those it names.
var options = map[string]option{
	"ca-url": {"ca-url", "SIMPLE_CA_URL", "`URL` of the CA, such as https://pki.example.com/gcp-wif",
		func(s *client.Settings) *string { return &s.CAURL }},
	"token-file": {"token-file", "SIMPLE_CA_TOKEN_FILE", "`file` holding the api token",
		func(s *client.Settings) *string { return &s.TokenFile }},
	"provider": {"provider", "SIMPLE_CA_PROVIDER", "Google: the `name` of the workload identity pool provider,\n" +
		"//iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/ID",
		func(s *client.Settings) *string { return &s.Provider }},
	"service-account": {"service-account", "SIMPLE_CA_SERVICE_ACCOUNT", "Google: the `email` of the service account impersonated",
		func(s *client.Settings) *string { return &s.ServiceAccount }},
	"google-scope": {"google-scope", "SIMPLE_CA_GOOGLE_SCOPE", "Google: the `scope` of the access token of the service account, else\n" +
		client.DefaultGoogleScope, func(s *client.Settings) *string { return &s.GoogleScope }},
	"tenant-id": {"tenant-id", "SIMPLE_CA_TENANT_ID", "Entra ID: the `tenant`",
		func(s *client.Settings) *string { return &s.TenantID }},
	"client-id": {"client-id", "SIMPLE_CA_CLIENT_ID", "Entra ID: the application (client) `ID`",
		func(s *client.Settings) *string { return &s.ClientID }},
	"scope": {"scope", "SIMPLE_CA_SCOPE", "Entra ID: the `scope` of the access token, else " + client.DefaultEntraScope,
		func(s *client.Settings) *string { return &s.Scope }},
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
	fmt.Fprint(w, `Usage: request-token SUBCOMMAND [options]
       request-token --version

Subcommands:
`)
	for _, c := range subcommands {
		fmt.Fprintf(w, "  %-21s %s\n", c.name, c.summary)
	}
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
	fmt.Fprintf(os.Stderr, "request-token: unknown subcommand %q\n", name)
	usage(os.Stderr)
	return errUsage
}

// newFlagSet returns the flag set of the subcommand name, whose usage names its arguments and
// its description.
func newFlagSet(name, arguments, description string) *flag.FlagSet {
	fs := flag.NewFlagSet("request-token "+name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: request-token %s [options]%s\n\n%s\n\nOptions:\n", name, arguments, description)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses args with fs, --config and the options named, and returns the settings of the
// file, replaced by those of the environment, replaced by the options given, and the path of the
// file read, empty without one.
func parse(fs *flag.FlagSet, args []string, names ...string) (client.Settings, string, error) {
	configFile := fs.String("config", "", "JSON `file` of the settings (default: "+client.DefaultConfig+" when it exists)")
	values := map[string]*string{}
	for _, name := range names {
		o := options[name]
		values[name] = fs.String(name, "", o.usage+" (default: "+o.env+")")
	}
	fs.Parse(args)

	s, path, err := client.ReadConfig(*configFile)
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
	if s.CAURL != "" {
		if _, _, err := weburl.CA(s.CAURL); err != nil {
			return s, "", fmt.Errorf("the URL of the CA, ca_url, SIMPLE_CA_URL or --ca-url: %w", err)
		}
	}
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

// runAPI exchanges a one-time setup code for the api token, and prints it or writes it to the
// token file, a new file.
func runAPI(args []string) error {
	fs := newFlagSet("api", " CODE",
		"Exchanges the one-time setup code for the api token at /api/token-setup of the server of the CA,\n"+
			"and prints it, or writes it to the token file, a new file of mode 0600.")
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
	token, err := client.Exchange(s.CAURL, code)
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
	fmt.Fprintf(os.Stderr, "Token written to %q\n", s.TokenFile)
	return nil
}

// simpleCAJWT returns a new JWT of the api token of s, and when it expires.
func simpleCAJWT(s client.Settings) (string, time.Time, error) {
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
			return "", time.Time{}, fmt.Errorf("%q is empty", s.TokenFile)
		}
	case token == "":
		return "", time.Time{}, errors.New("no token: give token, token_file, SIMPLE_CA_TOKEN, SIMPLE_CA_TOKEN_FILE or --token-file")
	}
	return client.FederationToken(s.CAURL, token)
}

// runJWT prints the JWT of the api token, writes it to a file, or prints it as the answer of an
// executable source of Google's credential file.
func runJWT(args []string) error {
	fs := newFlagSet("jwt", "",
		"Requests a JWT of workload identity federation from simple-ca serve with the api token, and prints it.")
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
		answer := map[string]any{"version": 1, "success": true, "token_type": client.JWTTokenType, "id_token": jwt,
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
		return client.ReplaceFile(*output, jwt)
	}
	fmt.Println(jwt)
	return nil
}

// googleFederated returns the federated access token of Google of the JWT of the api token of s.
func googleFederated(s client.Settings) (string, error) {
	if s.Provider == "" {
		return "", errors.New("no provider of Google: give provider, SIMPLE_CA_PROVIDER or --provider")
	}
	jwt, _, err := simpleCAJWT(s)
	if err != nil {
		return "", err
	}
	return client.GoogleToken(s.Provider, jwt)
}

// runGoogleWIF prints the federated access token of Google of the JWT.
func runGoogleWIF(args []string) error {
	fs := newFlagSet("google-wif", "",
		"Requests a JWT from simple-ca serve, exchanges it at Google's Security Token Service for a\n"+
			"federated access token of the workload identity pool provider, and prints it.")
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
	fs := newFlagSet("google-access-token", "",
		"Requests a JWT from simple-ca serve and exchanges it for an access token of the service account,\n"+
			"and prints it. The principal of the JWT needs roles/iam.workloadIdentityUser on the service account.")
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
		s.GoogleScope = client.DefaultGoogleScope
	}
	federated, err := googleFederated(s)
	if err != nil {
		return err
	}
	token, err := client.ServiceAccountToken(s.ServiceAccount, s.GoogleScope, federated)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runEntraID prints the Entra ID access token of the JWT.
func runEntraID(args []string) error {
	fs := newFlagSet("entra-id", "",
		"Requests a JWT from simple-ca serve, gets an access token of the Microsoft Entra ID application\n"+
			"by the client credentials flow, with the JWT as the client assertion, and prints it.")
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
		s.Scope = client.DefaultEntraScope
	}
	jwt, _, err := simpleCAJWT(s)
	if err != nil {
		return err
	}
	token, err := client.EntraToken(s.TenantID, s.ClientID, s.Scope, jwt)
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// runGoogleCredConfig writes the credential file of Google's Application Default Credentials and
// gcloud auth login --cred-file, whose JWT comes from request-token jwt or from a file.
func runGoogleCredConfig(args []string) error {
	fs := newFlagSet("google-cred-config", "",
		"Writes the credential file of the workload identity pool provider for Application Default\n"+
			"Credentials and gcloud. Its source executable needs GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1.")
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
		"subject_token_type": client.JWTTokenType,
		"token_url":          client.STSURL,
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
				client.DefaultConfig + " in the working directory")
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
		return fmt.Errorf("unknown credential source %q: must be executable or file", *source)
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
	fmt.Fprintf(os.Stderr, "Credential file written to %q\n", *outputFile)
	if *source == "executable" {
		fmt.Fprintln(os.Stderr, "Google runs its command only with GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1.")
	}
	return nil
}

func main() {
	if err := run(); errors.Is(err, errUsage) {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "request-token:", err)
		os.Exit(1)
	}
}
