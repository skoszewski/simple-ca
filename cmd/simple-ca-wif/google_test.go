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
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skoszewski/simple-ca/pkg/client"
	"github.com/skoszewski/simple-ca/pkg/simpleca"
	"github.com/skoszewski/simple-ca/pkg/simpleca/tokens"
)

const (
	testPool      = "/iam/v1/projects/123456789/locations/global/workloadIdentityPools/lab-pool"
	testProvider  = testPool + "/providers/simple-ca"
	testAudience  = "https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca"
	testPrincipal = "principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/lab-pool/subject/build-01"
	testEmail     = "build-01@lab-project.iam.gserviceaccount.com"
	testAccount   = "/iam/v1/projects/lab-project/serviceAccounts/" + testEmail
	testProject   = "/crm/v3/projects/lab-project"
)

// fakeGoogle stands in for the IAM and Resource Manager APIs: their resources and IAM policies by
// path, the requests made and the queries and bodies of getIamPolicy. A service account it
// creates is not found by the next hideNew calls of its IAM policy, and a member is refused as
// missing by the next missingMember setIamPolicy calls of the project.
type fakeGoogle struct {
	mu            sync.Mutex
	resources     map[string]map[string]any
	policies      map[string]*policy
	gets          map[string]string
	requests      []string
	auth          string
	conflict      bool
	failAccount   bool
	etags         int
	hideNew       int
	hidden        int
	missingMember int
	out           bytes.Buffer
}

func (g *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path)
	g.auth = r.Header.Get("Authorization")
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	json.Unmarshal(raw, &body)
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	failure := func(code int, status, message string) {
		reply(code, map[string]any{"error": map[string]any{"code": code, "message": message, "status": status}})
	}
	path := r.URL.Path
	resource, method, _ := strings.Cut(path, ":")
	switch {
	case method != "" && resource == testAccount && g.hidden > 0:
		g.hidden--
		failure(http.StatusNotFound, "NOT_FOUND", "unknown service account")
	case method == "setIamPolicy" && resource == testProject && g.missingMember > 0:
		g.missingMember--
		failure(http.StatusBadRequest, "INVALID_ARGUMENT", "Service account "+testEmail+" does not exist.")
	case method == "getIamPolicy":
		g.gets[resource] = r.URL.RawQuery + " " + string(raw)
		if g.policies[resource] == nil {
			g.policies[resource] = &policy{Etag: "e0"}
		}
		reply(http.StatusOK, g.policies[resource])
	case method == "setIamPolicy":
		var req struct{ Policy policy }
		json.Unmarshal(raw, &req)
		if g.conflict || g.policies[resource] == nil || req.Policy.Etag != g.policies[resource].Etag {
			failure(http.StatusConflict, "ABORTED", "There were concurrent policy changes.")
			return
		}
		g.etags++
		req.Policy.Etag = fmt.Sprintf("e%d", g.etags)
		g.policies[resource] = &req.Policy
		reply(http.StatusOK, req.Policy)
	case strings.Contains(path, "/operations/"):
		reply(http.StatusOK, map[string]any{"name": strings.TrimPrefix(path, "/iam/v1/"), "done": true})
	case r.Method == http.MethodGet:
		if res, ok := g.resources[path]; ok {
			reply(http.StatusOK, res)
			return
		}
		failure(http.StatusNotFound, "NOT_FOUND", "not found")
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/serviceAccounts") && g.failAccount:
		failure(http.StatusForbidden, "PERMISSION_DENIED", "iam.serviceAccounts.create denied")
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/serviceAccounts"):
		g.hidden = g.hideNew
		email := body["accountId"].(string) + "@lab-project.iam.gserviceaccount.com"
		account := map[string]any{"email": email, "displayName": body["serviceAccount"].(map[string]any)["displayName"]}
		g.resources[path+"/"+email] = account
		reply(http.StatusOK, account)
	case r.Method == http.MethodPost:
		q := r.URL.Query()
		key := path + "/" + cmp.Or(q.Get("workloadIdentityPoolId"), q.Get("workloadIdentityPoolProviderId"))
		name := strings.TrimPrefix(key, "/iam/v1/")
		body["name"], body["state"] = name, "ACTIVE"
		g.resources[key] = body
		reply(http.StatusOK, map[string]any{"name": name + "/operations/op1", "done": false})
	case r.Method == http.MethodPatch:
		res, ok := g.resources[path]
		if !ok || r.URL.Query().Get("updateMask") != "oidc.jwksJson" {
			failure(http.StatusBadRequest, "INVALID_ARGUMENT", "bad patch")
			return
		}
		res["oidc"].(map[string]any)["jwksJson"] = body["oidc"].(map[string]any)["jwksJson"]
		reply(http.StatusOK, map[string]any{"name": strings.TrimPrefix(path, "/iam/v1/") + "/operations/op2", "done": true})
	default:
		failure(http.StatusMethodNotAllowed, "UNIMPLEMENTED", r.Method)
	}
}

// changes returns the requests of g after the first n that are not GETs.
func (g *fakeGoogle) changes(n int) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var changes []string
	for _, r := range g.requests[n:] {
		if !strings.HasPrefix(r, "GET ") && !strings.Contains(r, ":getIamPolicy") {
			changes = append(changes, r)
		}
	}
	return changes
}

// newFakeGoogle starts a fakeGoogle with the project lab-project, number 123456789, points the
// API URLs and stdout at it, and gives the access token test-token.
func newFakeGoogle(t *testing.T) *fakeGoogle {
	g := &fakeGoogle{
		resources: map[string]map[string]any{testProject: {"name": "projects/123456789", "projectId": "lab-project"}},
		policies:  map[string]*policy{},
		gets:      map[string]string{},
	}
	srv := httptest.NewServer(g)
	oldIAM, oldRM, oldPoll, oldOut := iamURL, resourceManagerURL, pollInterval, stdout
	oldWait, oldWaitMax := accountWait, accountWaitMax
	t.Cleanup(func() {
		srv.Close()
		iamURL, resourceManagerURL, pollInterval, stdout = oldIAM, oldRM, oldPoll, oldOut
		accountWait, accountWaitMax = oldWait, oldWaitMax
		accessToken, quotaProject = "", ""
	})
	iamURL, resourceManagerURL, pollInterval, stdout = srv.URL+"/iam/v1/", srv.URL+"/crm/v3/", time.Millisecond, &g.out
	accountWait, accountWaitMax = time.Millisecond, 4*time.Millisecond
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "test-token")
	t.Setenv("SIMPLE_CA_KEY_PASSWORD", "")
	t.Setenv("SIMPLE_CA_KEY_PASSWORD_FILE", "")
	return g
}

// newTestCA makes a root CA with its issuing CA gcp-wif, of ECDSA P-256 keys, and returns their
// directories.
func newTestCA(t *testing.T) (string, string) {
	root := t.TempDir()
	caDir := filepath.Join(root, "gcp-wif")
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	var parent *x509.Certificate
	var parentKey *ecdsa.PrivateKey
	for i, dir := range []string{root, caDir} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "Test CA " + dir},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		if parent == tmpl {
			if parent, err = x509.ParseCertificate(der); err != nil {
				t.Fatal(err)
			}
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(dir, "ca_cert.pem"), "CERTIFICATE", der)
		write(filepath.Join(dir, "ca_key.pem"), "PRIVATE KEY", keyDER)
	}
	return root, caDir
}

// setTokenType sets the issuer https://pki.example.com and the token type gcp-wif of the provider
// in simple-ca.json of root.
func setTokenType(t *testing.T, root string) {
	cfg, err := simpleca.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Federation.Issuer = "https://pki.example.com"
	cfg.Federation.Types = map[string]simpleca.TokenTypeConfig{"gcp-wif": {Base: "google", Audience: testAudience}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

// wantLines fails t for each line not in out.
func wantLines(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, line := range lines {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
}

func TestSetupCreatesThenLeavesAlone(t *testing.T) {
	root, caDir := newTestCA(t)
	g := newFakeGoogle(t)
	args := []string{"--ca-dir", caDir, "--project", "lab-project", "--pool", "lab-pool", "--issuer", "https://pki.example.com/"}
	if err := runGoogleSetup(args); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, simpleca.ConfigFile)
	wantLines(t, g.out.String(),
		"project lab-project: number 123456789",
		"pool projects/123456789/locations/global/workloadIdentityPools/lab-pool: created",
		"provider projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca: created",
		"issuer https://pki.example.com/gcp-wif in "+cfgPath+": created",
		"token type gcp-wif in "+cfgPath+": created")
	if g.auth != "Bearer test-token" {
		t.Errorf("Authorization %q", g.auth)
	}
	if !slices.Contains(g.requests, "GET "+testPool+"/operations/op1") ||
		!slices.Contains(g.requests, "GET "+testProvider+"/operations/op1") {
		t.Errorf("the operations are not polled: %v", g.requests)
	}

	jwks, err := tokens.CAJWKS(caDir)
	if err != nil {
		t.Fatal(err)
	}
	prov := g.resources[testProvider]
	oidc := prov["oidc"].(map[string]any)
	if oidc["issuerUri"] != "https://pki.example.com/gcp-wif" || oidc["jwksJson"] != string(jwks) {
		t.Errorf("provider oidc %v", oidc)
	}
	if m := prov["attributeMapping"].(map[string]any); len(m) != 1 || m["google.subject"] != "assertion.sub" {
		t.Errorf("attributeMapping %v", m)
	}
	cfg, err := simpleca.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Federation.Issuer != "https://pki.example.com" {
		t.Errorf("federation.issuer %q", cfg.Federation.Issuer)
	}
	if typ := cfg.Federation.Types["gcp-wif"]; typ.Base != "google" || typ.Audience != testAudience {
		t.Errorf("token type %+v", typ)
	}

	// A second run finds everything and changes nothing.
	g.out.Reset()
	n := len(g.requests)
	if err := runGoogleSetup(args); err != nil {
		t.Fatal(err)
	}
	if c := g.changes(n); len(c) > 0 {
		t.Errorf("the second run changed %v", c)
	}
	if out := g.out.String(); strings.Contains(out, "created") || strings.Contains(out, "updated") {
		t.Errorf("the second run printed:\n%s", out)
	}
}

func TestSetupPatchesKeys(t *testing.T) {
	_, caDir := newTestCA(t)
	g := newFakeGoogle(t)
	args := []string{"--ca-dir", caDir, "--project", "lab-project", "--pool", "lab-pool", "--issuer", "https://pki.example.com"}
	if err := runGoogleSetup(args); err != nil {
		t.Fatal(err)
	}
	g.resources[testProvider]["oidc"].(map[string]any)["jwksJson"] = `{"keys":[]}`
	g.out.Reset()
	n := len(g.requests)
	if err := runGoogleSetup(args); err != nil {
		t.Fatal(err)
	}
	if c := g.changes(n); !slices.Equal(c, []string{"PATCH " + testProvider}) {
		t.Errorf("changes %v", c)
	}
	wantLines(t, g.out.String(), "provider projects/123456789/locations/global/workloadIdentityPools/lab-pool/providers/simple-ca: updated")
	jwks, _ := tokens.CAJWKS(caDir)
	if got := g.resources[testProvider]["oidc"].(map[string]any)["jwksJson"]; got != string(jwks) {
		t.Errorf("jwksJson %v", got)
	}
}

func TestSetupRefusals(t *testing.T) {
	tests := []struct {
		name, issuer, configIssuer, want string
		seed                             map[string]map[string]any
		googleCalls                      bool
	}{
		{name: "other issuer", issuer: "https://pki.example.com", configIssuer: "https://other.example.com",
			want: "is not federation.issuer"},
		{name: "http issuer", issuer: "http://pki.example.com", want: "https://"},
		{name: "no issuer", want: "has no issuer"},
		{name: "provider of another issuer", issuer: "https://pki.example.com", want: "has the issuer https://else.example.com",
			googleCalls: true, seed: map[string]map[string]any{
				testPool:     {"state": "ACTIVE"},
				testProvider: {"state": "ACTIVE", "oidc": map[string]any{"issuerUri": "https://else.example.com"}}}},
		{name: "deleted pool", issuer: "https://pki.example.com", want: "undelete it first", googleCalls: true,
			seed: map[string]map[string]any{testPool: {"state": "DELETED"}}},
		{name: "deleted provider", issuer: "https://pki.example.com", want: "undelete it first", googleCalls: true,
			seed: map[string]map[string]any{testPool: {"state": "ACTIVE"}, testProvider: {"state": "DELETED"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, caDir := newTestCA(t)
			g := newFakeGoogle(t)
			if tt.configIssuer != "" {
				cfg, _ := simpleca.LoadConfig(root)
				cfg.Federation.Issuer = tt.configIssuer
				if err := cfg.Save(); err != nil {
					t.Fatal(err)
				}
			}
			for k, v := range tt.seed {
				g.resources[k] = v
			}
			args := []string{"--ca-dir", caDir, "--project", "lab-project", "--pool", "lab-pool"}
			if tt.issuer != "" {
				args = append(args, "--issuer", tt.issuer)
			}
			err := runGoogleSetup(args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %v, want %q", err, tt.want)
			}
			if !tt.googleCalls && len(g.requests) > 0 {
				t.Errorf("requests %v", g.requests)
			}
			if c := g.changes(0); len(c) > 0 {
				t.Errorf("changes %v", c)
			}
			cfg, _ := simpleca.LoadConfig(root)
			if len(cfg.Federation.Types) > 0 {
				t.Errorf("simple-ca.json changed: %+v", cfg.Federation)
			}
		})
	}
}

func TestMachineServiceAccount(t *testing.T) {
	root, caDir := newTestCA(t)
	setTokenType(t, root)
	g := newFakeGoogle(t)
	g.policies[testProject] = &policy{Version: 1, Etag: "e-project",
		Bindings: []binding{{Role: "roles/browser", Members: []string{"user:alice@example.com"}}}}
	out := t.TempDir()
	args := []string{"--ca-dir", caDir, "--project", "lab-project", "--service-account", "build-01", "build-01",
		"--role", "roles/browser", "--role", "roles/viewer", "--network", "10.20.0.0/16", "--output-dir", out}
	if err := runGoogleMachine(args); err != nil {
		t.Fatal(err)
	}
	tokenPath, configPath := filepath.Join(out, "build-01.token"), filepath.Join(out, "federation.json")
	wantLines(t, g.out.String(),
		"service account "+testEmail+": created",
		"role roles/iam.workloadIdentityUser of "+testPrincipal+" on "+testEmail+": created",
		"role roles/browser of serviceAccount:"+testEmail+" on project lab-project: created",
		"role roles/viewer of serviceAccount:"+testEmail+" on project lab-project: created",
		"token build-01 in "+tokenPath+": created",
		configPath+": created")

	if dn := g.resources[testAccount]["displayName"]; dn != "simple-ca build-01" {
		t.Errorf("displayName %v", dn)
	}
	if q := g.gets[testAccount]; !strings.HasPrefix(q, "options.requestedPolicyVersion=3 ") {
		t.Errorf("getIamPolicy of the service account: %q", q)
	}
	if q := g.gets[testProject]; !strings.Contains(q, `"requestedPolicyVersion":3`) {
		t.Errorf("getIamPolicy of the project: %q", q)
	}
	sa := g.policies[testAccount]
	if len(sa.Bindings) != 1 || sa.Bindings[0].Role != "roles/iam.workloadIdentityUser" ||
		!slices.Equal(sa.Bindings[0].Members, []string{testPrincipal}) {
		t.Errorf("policy of the service account %+v", sa)
	}
	p := g.policies[testProject]
	want := []binding{
		{Role: "roles/browser", Members: []string{"user:alice@example.com", "serviceAccount:" + testEmail}},
		{Role: "roles/viewer", Members: []string{"serviceAccount:" + testEmail}},
	}
	if p.Etag == "e-project" || len(p.Bindings) != 2 {
		t.Fatalf("policy of the project %+v", p)
	}
	for i := range want {
		if p.Bindings[i].Role != want[i].Role || !slices.Equal(p.Bindings[i].Members, want[i].Members) {
			t.Errorf("binding %d %+v, want %+v", i, p.Bindings[i], want[i])
		}
	}

	b, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(string(b)), ".") != 2 {
		t.Errorf("token file %q", b)
	}
	if info, _ := os.Stat(tokenPath); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v", info.Mode())
	}
	db, err := tokens.LoadTokens(caDir)
	if err != nil {
		t.Fatal(err)
	}
	tok := db.Tokens["build-01"]
	if tok == nil || tok.Federate == nil || tok.Federate.Type != "gcp-wif" || !slices.Equal(tok.Scopes, []string{"federate"}) ||
		!slices.Equal(tok.Clients, []string{"10.20.0.0/16"}) || tok.Expires.Sub(tok.Issued) != 2160*time.Hour {
		t.Errorf("token %+v", tok)
	}
	var s client.Settings
	b, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	wantSettings := client.Settings{CAURL: "https://pki.example.com/gcp-wif", TokenFile: "build-01.token",
		Provider: "//iam.googleapis.com/" + strings.TrimPrefix(testProvider, "/iam/v1/"), ServiceAccount: testEmail}
	if s != wantSettings {
		t.Errorf("federation.json %+v", s)
	}
	audit, err := os.ReadFile(filepath.Join(root, simpleca.AuditFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"event=token.create", "name=build-01", "scopes=federate", "federate=gcp-wif", "via=cli"} {
		if !strings.Contains(string(audit), field) {
			t.Errorf("audit log lacks %s: %s", field, audit)
		}
	}

	// A second run is refused before any request, federation.json being there.
	n := len(g.requests)
	if err := runGoogleMachine(args); err == nil || !strings.Contains(err.Error(), "federation.json is written as a new file") {
		t.Errorf("second run: %v", err)
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(after, b) {
		t.Errorf("the second run changed federation.json: %v", err)
	}
	if len(g.requests) != n {
		t.Errorf("the second run made requests %v", g.requests[n:])
	}
}

func TestMachineWaitsForNewAccount(t *testing.T) {
	root, caDir := newTestCA(t)
	setTokenType(t, root)
	g := newFakeGoogle(t)
	g.hideNew, g.missingMember = 2, 1
	if err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--service-account", "build-01",
		"--role", "roles/browser", "--output-dir", t.TempDir(), "build-01"}); err != nil {
		t.Fatal(err)
	}
	count := func(request string) int {
		n := 0
		for _, r := range g.requests {
			if r == request {
				n++
			}
		}
		return n
	}
	if n := count("POST " + testAccount + ":getIamPolicy"); n != 3 {
		t.Errorf("getIamPolicy of the service account %d times, want 3", n)
	}
	if n := count("POST " + testProject + ":setIamPolicy"); n != 2 {
		t.Errorf("setIamPolicy of the project %d times, want 2", n)
	}
	wantLines(t, g.out.String(),
		"role roles/iam.workloadIdentityUser of "+testPrincipal+" on "+testEmail+": created",
		"role roles/browser of serviceAccount:"+testEmail+" on project lab-project: created")
}

func TestMachinePrincipalWithSetupCode(t *testing.T) {
	root, caDir := newTestCA(t)
	setTokenType(t, root)
	g := newFakeGoogle(t)
	out := t.TempDir()
	if err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
		"--otc", "--otc-network", "10.30.0.0/16,192.0.2.1", "--output-dir", out, "build-01"}); err != nil {
		t.Fatal(err)
	}
	wantLines(t, g.out.String(), "role roles/browser of "+testPrincipal+" on project lab-project: created")
	if !strings.Contains(g.out.String(), "token build-01: created, setup code ") {
		t.Errorf("output:\n%s", g.out.String())
	}
	if p := g.policies[testProject]; len(p.Bindings) != 1 || !slices.Equal(p.Bindings[0].Members, []string{testPrincipal}) {
		t.Errorf("policy of the project %+v", p)
	}
	if _, err := os.Stat(filepath.Join(out, "build-01.token")); !os.IsNotExist(err) {
		t.Errorf("token file: %v", err)
	}
	db, _ := tokens.LoadTokens(caDir)
	if tok := db.Tokens["build-01"]; tok == nil || !tok.Pending() ||
		!slices.Equal(tok.Setup.Clients, []string{"10.30.0.0/16", "192.0.2.1/32"}) {
		t.Errorf("token %+v", tok)
	}
	b, err := os.ReadFile(filepath.Join(out, "federation.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "service_account") {
		t.Errorf("federation.json %s", b)
	}
}

func TestMachineRefusals(t *testing.T) {
	t.Run("no token type", func(t *testing.T) {
		_, caDir := newTestCA(t)
		g := newFakeGoogle(t)
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--output-dir", t.TempDir(), "build-01"})
		if err == nil || !strings.Contains(err.Error(), "run simple-ca-wif google setup") {
			t.Errorf("error %v", err)
		}
		if len(g.requests) > 0 {
			t.Errorf("requests %v", g.requests)
		}
	})
	t.Run("otc-network without otc", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		out := t.TempDir()
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--otc-network", "10.30.0.0/16", "--output-dir", out, "build-01"})
		if err != errUsage {
			t.Errorf("error %v", err)
		}
		db, _ := tokens.LoadTokens(caDir)
		entries, _ := os.ReadDir(out)
		if len(g.requests) > 0 || len(db.Tokens) > 0 || len(entries) > 0 {
			t.Errorf("requests %v, tokens %v, files %v", g.requests, db.Tokens, entries)
		}
	})
	t.Run("output directory missing", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--output-dir", filepath.Join(t.TempDir(), "missing"), "build-01"})
		if err == nil || !strings.Contains(err.Error(), "federation.json") {
			t.Errorf("error %v", err)
		}
		db, _ := tokens.LoadTokens(caDir)
		if len(g.requests) > 0 || len(db.Tokens) > 0 {
			t.Errorf("requests %v, tokens %v", g.requests, db.Tokens)
		}
	})
	t.Run("Google failure leaves no files", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		g.failAccount = true
		out := t.TempDir()
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--service-account", "build-01",
			"--output-dir", out, "build-01"})
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Errorf("error %v", err)
		}
		db, _ := tokens.LoadTokens(caDir)
		entries, _ := os.ReadDir(out)
		if len(db.Tokens) > 0 || len(entries) > 0 {
			t.Errorf("tokens %v, files %v", db.Tokens, entries)
		}
	})
	t.Run("existing account not retried", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		g.resources[testAccount] = map[string]any{"email": testEmail}
		g.hidden = 1
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--service-account", "build-01",
			"--output-dir", t.TempDir(), "build-01"})
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Errorf("error %v", err)
		}
	})
	t.Run("federation.json exists", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		out := t.TempDir()
		os.WriteFile(filepath.Join(out, "federation.json"), []byte("{}\n"), 0o644)
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--output-dir", out, "build-01"})
		if err == nil || !strings.Contains(err.Error(), "exists") {
			t.Errorf("error %v", err)
		}
		db, _ := tokens.LoadTokens(caDir)
		if len(g.requests) > 0 || len(db.Tokens) > 0 {
			t.Errorf("requests %v, tokens %v", g.requests, db.Tokens)
		}
	})
	t.Run("token exists", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		if _, err := tokens.MakeToken(caDir, "build-01", time.Hour, []string{"tokens"}, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--output-dir", t.TempDir(), "build-01"})
		if err == nil || !strings.Contains(err.Error(), "token 'build-01' exists") {
			t.Errorf("error %v", err)
		}
		if len(g.requests) > 0 {
			t.Errorf("requests %v", g.requests)
		}
	})
	t.Run("etag conflict, then run again", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		g.conflict = true
		out := t.TempDir()
		args := []string{"--ca-dir", caDir, "--project", "lab-project", "--service-account", "build-01",
			"--role", "roles/browser", "--output-dir", out, "build-01"}
		err := runGoogleMachine(args)
		if err == nil || !strings.Contains(err.Error(), "run the command again") {
			t.Fatalf("error %v", err)
		}
		db, _ := tokens.LoadTokens(caDir)
		entries, _ := os.ReadDir(out)
		if len(db.Tokens) > 0 || len(entries) > 0 {
			t.Fatalf("tokens %v, files %v", db.Tokens, entries)
		}
		g.conflict = false
		g.out.Reset()
		if err := runGoogleMachine(args); err != nil {
			t.Fatal(err)
		}
		wantLines(t, g.out.String(), "service account "+testEmail+": unchanged",
			"role roles/browser of serviceAccount:"+testEmail+" on project lab-project: created")
	})
	t.Run("members left alone", func(t *testing.T) {
		root, caDir := newTestCA(t)
		setTokenType(t, root)
		g := newFakeGoogle(t)
		g.policies[testProject] = &policy{Etag: "e-project",
			Bindings: []binding{{Role: "roles/browser", Members: []string{testPrincipal}}}}
		if err := runGoogleMachine([]string{"--ca-dir", caDir, "--project", "lab-project", "--role", "roles/browser",
			"--output-dir", t.TempDir(), "build-01"}); err != nil {
			t.Fatal(err)
		}
		wantLines(t, g.out.String(), "role roles/browser of "+testPrincipal+" on project lab-project: unchanged")
		if c := g.changes(0); len(c) > 0 {
			t.Errorf("changes %v", c)
		}
	})
}
