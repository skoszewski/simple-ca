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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/client"
)

// parseCAURL parses args with a new flag set taking --ca-url, from the directory dir.
func parseCAURL(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(dir)
	fs := flag.NewFlagSet("request-token jwt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	s, _, err := parse(fs, args, "ca-url")
	return s.CAURL, err
}

func TestParseCAURL(t *testing.T) {
	t.Setenv("SIMPLE_CA_TOKEN", "")
	t.Setenv("SIMPLE_CA_TOKEN_FILE", "")
	t.Setenv("SIMPLE_CA_URL", "")
	dir := t.TempDir()
	config := filepath.Join(dir, "federation.json")
	if err := os.WriteFile(config, []byte(`{"ca_url": "https://pki.example.com/gcp-wif/x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	prefix := "the URL of the CA, ca_url, SIMPLE_CA_URL or --ca-url: "

	if _, err := parseCAURL(t, dir); err == nil ||
		!strings.HasPrefix(err.Error(), prefix+`"https://pki.example.com/gcp-wif/x" has the path`) {
		t.Errorf("ca_url of federation.json: %v", err)
	}
	if got, err := parseCAURL(t, dir, "--ca-url", "https://pki.example.com:8443/gcp-wif"); err != nil ||
		got != "https://pki.example.com:8443/gcp-wif" {
		t.Errorf("--ca-url over ca_url: %q, %v", got, err)
	}
	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com/gcp-wif?\n")
	if _, err := parseCAURL(t, t.TempDir()); err == nil ||
		!strings.HasPrefix(err.Error(), prefix+`"https://pki.example.com/gcp-wif?\n" is not a URL`) {
		t.Errorf("SIMPLE_CA_URL: %v", err)
	}
	t.Setenv("SIMPLE_CA_URL", "")
	if got, err := parseCAURL(t, t.TempDir()); err != nil || got != "" {
		t.Errorf("no URL of the CA: %q, %v, want none and no error", got, err)
	}
}

const (
	testProvider = "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca"
	testEmail    = "build-01@lab-project.iam.gserviceaccount.com"
	testExpires  = "2030-01-02T03:04:05Z"
)

// fakeServices stands in for simple-ca serve at pki.example.com, Google's Security Token Service,
// the IAM Service Account Credentials API and the token endpoint of Entra ID. It records the
// host and path of each request, with its body by them. It takes the setup code good-code for the
// api token api-token, and the api token for the JWT jwt-1; a service account or a tenant named
// denied is refused.
type fakeServices struct {
	mu       sync.Mutex
	requests []string
	bodies   map[string]string
}

func (f *fakeServices) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	target := r.Header.Get("X-Original-Host") + r.URL.EscapedPath()
	f.mu.Lock()
	f.requests = append(f.requests, target)
	f.bodies[target] = string(body)
	f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	auth := r.Header.Get("Authorization")
	host, path := r.Header.Get("X-Original-Host"), r.URL.Path
	switch {
	case host == "pki.example.com" && path == "/api/token-setup":
		var req struct{ Code string }
		json.Unmarshal(body, &req)
		if req.Code != "good-code" {
			reply(http.StatusUnauthorized, map[string]string{"error": "the setup code is not valid"})
			return
		}
		reply(http.StatusOK, map[string]string{"token": "api-token"})
	case host == "pki.example.com" && strings.HasSuffix(path, "/api/federation-token"):
		if auth != "Bearer api-token" {
			reply(http.StatusUnauthorized, map[string]string{"error": "the token is not valid"})
			return
		}
		reply(http.StatusOK, map[string]string{"token": "jwt-1", "expires": testExpires})
	case host == "sts.googleapis.com" && path == "/v1/token":
		reply(http.StatusOK, map[string]string{"access_token": "federated-1"})
	case host == "iamcredentials.googleapis.com" && strings.Contains(path, "denied"):
		reply(http.StatusForbidden, map[string]any{"error": map[string]any{"message": "permission denied"}})
	case host == "iamcredentials.googleapis.com" && auth == "Bearer federated-1":
		reply(http.StatusOK, map[string]string{"accessToken": "sa-1"})
	case host == "login.microsoftonline.com" && strings.HasPrefix(path, "/denied/"):
		reply(http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "the assertion is refused"})
	case host == "login.microsoftonline.com":
		reply(http.StatusOK, map[string]string{"access_token": "entra-1"})
	default:
		reply(http.StatusNotFound, map[string]string{"error": "no such path"})
	}
}

// count returns the number of requests received.
func (f *fakeServices) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// body returns the body of the last request to target, host and path.
func (f *fakeServices) body(target string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[target]
}

// redirect sends every request to the test server at target, naming the host it was for in the
// header X-Original-Host.
type redirect struct{ target *url.URL }

func (rd redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("X-Original-Host", req.URL.Host)
	r.URL.Scheme, r.URL.Host, r.Host = rd.target.Scheme, rd.target.Host, ""
	return http.DefaultTransport.RoundTrip(r)
}

// newServices starts a fakeServices, sends the requests of client.Client to it until the test
// ends, clears the environment variables of the settings, and makes a new directory the working
// directory.
func newServices(t *testing.T) *fakeServices {
	t.Helper()
	f := &fakeServices{bodies: map[string]string{}}
	srv := httptest.NewServer(f)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	orig := client.Client.Transport
	client.Client.Transport = redirect{u}
	t.Cleanup(func() {
		client.Client.Transport = orig
		srv.Close()
	})
	for _, env := range []string{"SIMPLE_CA_TOKEN", "SIMPLE_CA_TOKEN_FILE", "SIMPLE_CA_URL", "SIMPLE_CA_PROVIDER",
		"SIMPLE_CA_SERVICE_ACCOUNT", "SIMPLE_CA_GOOGLE_SCOPE", "SIMPLE_CA_TENANT_ID", "SIMPLE_CA_CLIENT_ID", "SIMPLE_CA_SCOPE"} {
		t.Setenv(env, "")
	}
	t.Chdir(t.TempDir())
	return f
}

// runCaptured runs request-token with args and returns what it printed on stdout and stderr, and
// its error.
func runCaptured(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut []byte
	var wg sync.WaitGroup
	wg.Go(func() { out, _ = io.ReadAll(outR) })
	wg.Go(func() { errOut, _ = io.ReadAll(errR) })
	savedArgs, savedOut, savedErr := os.Args, os.Stdout, os.Stderr
	os.Args, os.Stdout, os.Stderr = append([]string{"request-token"}, args...), outW, errW
	err = run()
	os.Args, os.Stdout, os.Stderr = savedArgs, savedOut, savedErr
	outW.Close()
	errW.Close()
	wg.Wait()
	return string(out), string(errOut), err
}

// writeFile writes data to the file name of the working directory.
func writeFile(t *testing.T, name, data string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// wantError fails t unless err holds want.
func wantError(t *testing.T, what string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, want an error with %q", what, err, want)
	}
}

func TestRun(t *testing.T) {
	newServices(t)
	_, errOut, err := runCaptured(t)
	if !errors.Is(err, errUsage) || !strings.HasPrefix(errOut, "Usage: request-token SUBCOMMAND") {
		t.Errorf("no arguments: %v, stderr %q, want the usage error and the usage", err, errOut)
	}
	for _, help := range []string{"help", "-h", "--help"} {
		out, _, err := runCaptured(t, help)
		if err != nil || !strings.HasPrefix(out, "Usage: request-token SUBCOMMAND") {
			t.Errorf("%s: %v, stdout %q, want the usage", help, err, out)
		}
		for _, c := range subcommands {
			if !strings.Contains(out, "\n  "+c.name+" ") {
				t.Errorf("%s: the usage does not list %s:\n%s", help, c.name, out)
			}
		}
	}
	if out, _, err := runCaptured(t, "--version"); err != nil || !strings.HasPrefix(out, "request-token ") ||
		len(strings.TrimSpace(out)) == len("request-token") {
		t.Errorf("--version: %v, %q, want the version", err, out)
	}
	_, errOut, err = runCaptured(t, "nosuch")
	if !errors.Is(err, errUsage) || !strings.HasPrefix(errOut, "request-token: unknown subcommand \"nosuch\"\nUsage:") {
		t.Errorf("an unknown subcommand: %v, stderr %q", err, errOut)
	}
}

func TestBadCAURL(t *testing.T) {
	newServices(t)
	t.Setenv("SIMPLE_CA_URL", "ftp://pki.example.com")
	for _, c := range subcommands {
		_, _, err := runCaptured(t, c.name)
		wantError(t, c.name+" with a bad SIMPLE_CA_URL", err, "the URL of the CA, ca_url, SIMPLE_CA_URL or --ca-url: ")
	}
}

func TestAPI(t *testing.T) {
	f := newServices(t)
	_, _, err := runCaptured(t, "api", "good-code")
	wantError(t, "no URL of the CA", err, "no URL of the CA: give ca_url, SIMPLE_CA_URL or --ca-url")
	_, errOut, err := runCaptured(t, "api", "--ca-url", "https://pki.example.com")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "request-token api: the setup code is the one argument\nUsage:") {
		t.Errorf("no setup code: %v, stderr %q", err, errOut)
	}
	if f.count() != 0 {
		t.Fatalf("the refused commands made requests: %v", f.requests)
	}

	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com/servers")
	out, _, err := runCaptured(t, "api", " good-code ")
	if err != nil || out != "api-token\n" {
		t.Errorf("api: %v, %q, want the token printed", err, out)
	}
	if b := f.body("pki.example.com/api/token-setup"); b != `{"code":"good-code"}` {
		t.Errorf("the body of the exchange %q, want the code trimmed", b)
	}

	out, errOut, err = runCaptured(t, "api", "--token-file", "token", "good-code")
	if err != nil || out != "" || errOut != "Token written to \"token\"\n" {
		t.Fatalf("api --token-file: %v, stdout %q, stderr %q", err, out, errOut)
	}
	b, err := os.ReadFile("token")
	if err != nil || string(b) != "api-token\n" {
		t.Errorf("the token file: %q, %v", b, err)
	}
	if info, err := os.Stat("token"); err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("the token file has the mode %v, want 0600", info.Mode().Perm())
	}
	n := f.count()
	_, _, err = runCaptured(t, "api", "--token-file", "token", "good-code")
	wantError(t, "an existing token file", err, "the api token is written to a new file")
	if f.count() != n {
		t.Error("the code was exchanged for an existing token file")
	}

	var se *client.StatusError
	_, _, err = runCaptured(t, "api", "--token-file", "spent", "bad-code")
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Errorf("a code refused: %v, want 401", err)
	}
	if _, err := os.Stat("spent"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a code refused left the token file: %v", err)
	}
	if _, _, err = runCaptured(t, "api", "bad-code"); !errors.As(err, &se) {
		t.Errorf("a code refused without a token file: %v, want the status error", err)
	}
}

func TestJWT(t *testing.T) {
	f := newServices(t)
	_, _, err := runCaptured(t, "jwt")
	wantError(t, "no URL of the CA", err, "no URL of the CA: give ca_url, SIMPLE_CA_URL or --ca-url")
	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com/gcp-wif")
	_, _, err = runCaptured(t, "jwt")
	wantError(t, "no token", err, "no token: give token, token_file, SIMPLE_CA_TOKEN, SIMPLE_CA_TOKEN_FILE or --token-file")
	_, errOut, err := runCaptured(t, "jwt", "extra")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "request-token jwt: no arguments are taken, only options\nUsage:") {
		t.Errorf("an argument: %v, stderr %q", err, errOut)
	}

	t.Setenv("SIMPLE_CA_TOKEN", "api-token")
	out, _, err := runCaptured(t, "jwt")
	if err != nil || out != "jwt-1\n" {
		t.Errorf("jwt: %v, %q, want the JWT", err, out)
	}
	if !slices.Contains(f.requests, "pki.example.com/gcp-wif/api/federation-token") {
		t.Errorf("requests %v, want the federation token of the issuing CA gcp-wif", f.requests)
	}
	if out, _, err := runCaptured(t, "jwt", "--output", "jwt.txt"); err != nil || out != "" {
		t.Errorf("jwt --output: %v, %q", err, out)
	}
	if b, err := os.ReadFile("jwt.txt"); err != nil || string(b) != "jwt-1" {
		t.Errorf("the file of --output: %q, %v", b, err)
	}

	expires, _ := time.Parse(time.RFC3339, testExpires)
	out, _, err = runCaptured(t, "jwt", "--google-executable")
	var answer map[string]any
	if err != nil || json.Unmarshal([]byte(out), &answer) != nil {
		t.Fatalf("jwt --google-executable: %v, %q", err, out)
	}
	if answer["version"] != float64(1) || answer["success"] != true || answer["token_type"] != client.JWTTokenType ||
		answer["id_token"] != "jwt-1" || answer["expiration_time"] != float64(expires.Unix()) {
		t.Errorf("jwt --google-executable: %v", answer)
	}
	out, _, err = runCaptured(t, "jwt", "--google-executable", "--output", "jwt.txt")
	wantError(t, "--google-executable with --output", err, "give --output or --google-executable, not both")
	answer = nil
	if json.Unmarshal([]byte(out), &answer) != nil || answer["success"] != false || answer["code"] != "request-token" ||
		answer["message"] != "give --output or --google-executable, not both" {
		t.Errorf("the failure of --google-executable: %q", out)
	}

	t.Setenv("SIMPLE_CA_TOKEN", "wrong")
	_, _, err = runCaptured(t, "jwt")
	wantError(t, "a token refused", err, `"the token is not valid"`)
	writeFile(t, "token", "api-token\n")
	if out, _, err := runCaptured(t, "jwt", "--token-file", "token"); err != nil || out != "jwt-1\n" {
		t.Errorf("--token-file over SIMPLE_CA_TOKEN: %v, %q", err, out)
	}
	_, _, err = runCaptured(t, "jwt", "--token-file", "missing")
	wantError(t, "a missing token file", err, "missing")

	t.Setenv("SIMPLE_CA_TOKEN_FILE", "token")
	_, _, err = runCaptured(t, "jwt")
	wantError(t, "SIMPLE_CA_TOKEN and SIMPLE_CA_TOKEN_FILE", err, "give the token in SIMPLE_CA_TOKEN or in SIMPLE_CA_TOKEN_FILE, not both")
	t.Setenv("SIMPLE_CA_TOKEN", "")
	if out, _, err := runCaptured(t, "jwt"); err != nil || out != "jwt-1\n" {
		t.Errorf("SIMPLE_CA_TOKEN_FILE: %v, %q", err, out)
	}
	writeFile(t, "empty", "\n")
	t.Setenv("SIMPLE_CA_TOKEN_FILE", "empty")
	_, _, err = runCaptured(t, "jwt")
	wantError(t, "an empty token file", err, `"empty" is empty`)

	t.Setenv("SIMPLE_CA_TOKEN_FILE", "")
	t.Setenv("SIMPLE_CA_URL", "")
	writeFile(t, client.DefaultConfig, `{"ca_url": "https://pki.example.com", "token": "api-token"}`)
	if out, _, err := runCaptured(t, "jwt"); err != nil || out != "jwt-1\n" {
		t.Errorf("the settings of %s: %v, %q", client.DefaultConfig, err, out)
	}
	_, _, err = runCaptured(t, "jwt", "--config", "nosuch.json")
	wantError(t, "a missing --config", err, "nosuch.json")
}

func TestGoogleWIF(t *testing.T) {
	f := newServices(t)
	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com")
	t.Setenv("SIMPLE_CA_TOKEN", "api-token")
	_, _, err := runCaptured(t, "google-wif")
	wantError(t, "no provider", err, "no provider of Google: give provider, SIMPLE_CA_PROVIDER or --provider")
	_, errOut, err := runCaptured(t, "google-wif", "--provider", testProvider, "extra")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "no arguments are taken") {
		t.Errorf("an argument: %v, stderr %q", err, errOut)
	}
	out, _, err := runCaptured(t, "google-wif", "--provider", testProvider)
	if err != nil || out != "federated-1\n" {
		t.Fatalf("google-wif: %v, %q", err, out)
	}
	var body map[string]string
	json.Unmarshal([]byte(f.body("sts.googleapis.com/v1/token")), &body)
	if body["audience"] != testProvider || body["subjectToken"] != "jwt-1" || body["subjectTokenType"] != client.JWTTokenType {
		t.Errorf("the body of the exchange at STS: %v", body)
	}
	t.Setenv("SIMPLE_CA_TOKEN", "wrong")
	_, _, err = runCaptured(t, "google-wif", "--provider", testProvider)
	wantError(t, "a token refused", err, `"the token is not valid"`)
}

func TestGoogleAccessToken(t *testing.T) {
	f := newServices(t)
	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com")
	t.Setenv("SIMPLE_CA_TOKEN", "api-token")
	t.Setenv("SIMPLE_CA_PROVIDER", testProvider)
	_, _, err := runCaptured(t, "google-access-token")
	wantError(t, "no service account", err, "no service account: give service_account, SIMPLE_CA_SERVICE_ACCOUNT or --service-account")
	_, errOut, err := runCaptured(t, "google-access-token", "extra")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "no arguments are taken") {
		t.Errorf("an argument: %v, stderr %q", err, errOut)
	}

	target := "iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + url.PathEscape(testEmail) + ":generateAccessToken"
	out, _, err := runCaptured(t, "google-access-token", "--service-account", testEmail)
	if err != nil || out != "sa-1\n" {
		t.Fatalf("google-access-token: %v, %q", err, out)
	}
	if b := f.body(target); b != `{"scope":["`+client.DefaultGoogleScope+`"]}` {
		t.Errorf("the body of generateAccessToken %q, want the default scope", b)
	}
	t.Setenv("SIMPLE_CA_GOOGLE_SCOPE", "https://www.googleapis.com/auth/devstorage.read_only")
	if out, _, err := runCaptured(t, "google-access-token", "--service-account", testEmail); err != nil || out != "sa-1\n" {
		t.Fatalf("google-access-token with a scope: %v, %q", err, out)
	}
	if b := f.body(target); b != `{"scope":["https://www.googleapis.com/auth/devstorage.read_only"]}` {
		t.Errorf("the body of generateAccessToken %q, want SIMPLE_CA_GOOGLE_SCOPE", b)
	}

	_, _, err = runCaptured(t, "google-access-token", "--service-account", "denied@lab-project.iam.gserviceaccount.com")
	wantError(t, "a service account refused", err, ": 403 ")
	t.Setenv("SIMPLE_CA_PROVIDER", "")
	_, _, err = runCaptured(t, "google-access-token", "--service-account", testEmail)
	wantError(t, "no provider", err, "no provider of Google")
}

func TestEntraID(t *testing.T) {
	f := newServices(t)
	t.Setenv("SIMPLE_CA_URL", "https://pki.example.com")
	t.Setenv("SIMPLE_CA_TOKEN", "api-token")
	_, _, err := runCaptured(t, "entra-id", "--client-id", "app-1")
	wantError(t, "no tenant", err, "no tenant of Entra ID: give tenant_id, SIMPLE_CA_TENANT_ID or --tenant-id")
	_, _, err = runCaptured(t, "entra-id", "--tenant-id", "tenant-1")
	wantError(t, "no client ID", err, "no client ID of Entra ID: give client_id, SIMPLE_CA_CLIENT_ID or --client-id")
	_, errOut, err := runCaptured(t, "entra-id", "extra")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "no arguments are taken") {
		t.Errorf("an argument: %v, stderr %q", err, errOut)
	}

	out, _, err := runCaptured(t, "entra-id", "--tenant-id", "tenant-1", "--client-id", "app-1")
	if err != nil || out != "entra-1\n" {
		t.Fatalf("entra-id: %v, %q", err, out)
	}
	form, _ := url.ParseQuery(f.body("login.microsoftonline.com/tenant-1/oauth2/v2.0/token"))
	if form.Get("client_id") != "app-1" || form.Get("scope") != client.DefaultEntraScope || form.Get("client_assertion") != "jwt-1" ||
		form.Get("grant_type") != "client_credentials" {
		t.Errorf("the form of the token endpoint: %v", form)
	}
	if out, _, err := runCaptured(t, "entra-id", "--tenant-id", "tenant-1", "--client-id", "app-1", "--scope", "api://app-2/.default"); err != nil ||
		out != "entra-1\n" {
		t.Fatalf("entra-id --scope: %v, %q", err, out)
	}
	if form, _ := url.ParseQuery(f.body("login.microsoftonline.com/tenant-1/oauth2/v2.0/token")); form.Get("scope") != "api://app-2/.default" {
		t.Errorf("the scope of --scope: %q", form.Get("scope"))
	}

	_, _, err = runCaptured(t, "entra-id", "--tenant-id", "denied", "--client-id", "app-1")
	wantError(t, "a tenant refusing", err, `"the assertion is refused"`)
	t.Setenv("SIMPLE_CA_TOKEN", "wrong")
	_, _, err = runCaptured(t, "entra-id", "--tenant-id", "tenant-1", "--client-id", "app-1")
	wantError(t, "a token refused", err, `"the token is not valid"`)
}

func TestGoogleCredConfig(t *testing.T) {
	newServices(t)
	_, _, err := runCaptured(t, "google-cred-config")
	wantError(t, "no provider", err, "no provider of Google: give provider, SIMPLE_CA_PROVIDER or --provider")
	_, errOut, err := runCaptured(t, "google-cred-config", "--provider", testProvider, "extra")
	if !errors.Is(err, errUsage) || !strings.Contains(errOut, "no arguments are taken") {
		t.Errorf("an argument: %v, stderr %q", err, errOut)
	}
	_, _, err = runCaptured(t, "google-cred-config", "--provider", testProvider)
	wantError(t, "the source executable without a configuration", err, "the source executable needs the configuration file")
	_, _, err = runCaptured(t, "google-cred-config", "--provider", testProvider, "--jwt-file", "jwt.txt")
	wantError(t, "--jwt-file of the source executable", err, "--jwt-file belongs to the source file")
	_, _, err = runCaptured(t, "google-cred-config", "--provider", testProvider, "--credential-source", "file")
	wantError(t, "the source file without --jwt-file", err, "the source file needs --jwt-file")
	_, _, err = runCaptured(t, "google-cred-config", "--provider", testProvider, "--credential-source", "url")
	wantError(t, "an unknown source", err, `unknown credential source "url": must be executable or file`)
	if _, err := os.Stat("cred.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused command wrote cred.json: %v", err)
	}

	// The source executable runs request-token jwt with the configuration file.
	writeFile(t, client.DefaultConfig, fmt.Sprintf(`{"provider": %q, "service_account": %q}`, testProvider, testEmail))
	_, errOut, err = runCaptured(t, "google-cred-config")
	if err != nil || errOut != "Credential file written to \"cred.json\"\n"+
		"Google runs its command only with GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1.\n" {
		t.Fatalf("google-cred-config: %v, stderr %q", err, errOut)
	}
	program, _ := os.Executable()
	program, _ = filepath.Abs(program)
	config, _ := filepath.Abs(client.DefaultConfig)
	var cred map[string]any
	b, err := os.ReadFile("cred.json")
	if err != nil || json.Unmarshal(b, &cred) != nil {
		t.Fatalf("cred.json: %q, %v", b, err)
	}
	executable, _ := cred["credential_source"].(map[string]any)["executable"].(map[string]any)
	if cred["type"] != "external_account" || cred["audience"] != testProvider || cred["subject_token_type"] != client.JWTTokenType ||
		cred["token_url"] != client.STSURL ||
		cred["service_account_impersonation_url"] != "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+
			url.PathEscape(testEmail)+":generateAccessToken" ||
		executable["command"] != program+" jwt --google-executable --config "+config || executable["timeout_millis"] != float64(30000) {
		t.Errorf("cred.json:\n%s", b)
	}
	if info, err := os.Stat("cred.json"); err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("cred.json has the mode %v, want 0600", info.Mode().Perm())
	}
	_, _, err = runCaptured(t, "google-cred-config")
	wantError(t, "an existing credential file", err, "the credential file is written to a new file")

	// The source file is the file of the JWT, without the impersonation of a service account.
	t.Chdir(t.TempDir())
	_, errOut, err = runCaptured(t, "google-cred-config", "--provider", testProvider, "--credential-source", "file",
		"--jwt-file", "jwt.txt", "--output-file", "file-cred.json")
	if err != nil || errOut != "Credential file written to \"file-cred.json\"\n" {
		t.Fatalf("google-cred-config of the source file: %v, stderr %q", err, errOut)
	}
	jwtPath, _ := filepath.Abs("jwt.txt")
	cred = nil
	b, err = os.ReadFile("file-cred.json")
	if err != nil || json.Unmarshal(b, &cred) != nil {
		t.Fatalf("file-cred.json: %q, %v", b, err)
	}
	source, _ := cred["credential_source"].(map[string]any)
	format, _ := source["format"].(map[string]any)
	if source["file"] != jwtPath || format["type"] != "text" || cred["service_account_impersonation_url"] != nil {
		t.Errorf("file-cred.json:\n%s", b)
	}
}
