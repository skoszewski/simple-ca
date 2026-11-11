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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/skoszewski/simple-ca/pkg/client"
	"github.com/skoszewski/simple-ca/pkg/simpleca"
)

// iamURL is the base URL of the IAM API v1, and resourceManagerURL that of the Resource Manager
// API v3.
var (
	iamURL             = "https://iam.googleapis.com/v1/"
	resourceManagerURL = "https://cloudresourcemanager.googleapis.com/v3/"
)

// pollInterval is the time between two polls of an operation, and pollTimeout the longest an
// operation is waited for.
var (
	pollInterval = 2 * time.Second
	pollTimeout  = 5 * time.Minute
)

// accountWait is the first wait for a service account created in this run that Google does not
// show yet, doubled up to accountWaitMax, and accountWaitTotal the longest it is waited for.
var (
	accountWait      = 2 * time.Second
	accountWaitMax   = 16 * time.Second
	accountWaitTotal = 90 * time.Second
)

// stdout is where the commands print their lines.
var stdout io.Writer = os.Stdout

// poolIDRE matches the ID of a workload identity pool or provider.
var poolIDRE = regexp.MustCompile(`^[a-z0-9-]{4,32}$`)

// accountIDRE matches the account ID of a service account, of 6 to 30 characters.
var accountIDRE = regexp.MustCompile(`^[a-z]([-a-z0-9]{4,28}[a-z0-9])$`)

// audienceRE matches the audience of a token type for a workload identity pool provider, with
// the resource name of the provider, the project number and the pool.
var audienceRE = regexp.MustCompile(
	`^https://iam\.googleapis\.com/(projects/([0-9]+)/locations/global/workloadIdentityPools/([a-z0-9-]+)/providers/[a-z0-9-]+)$`)

// googleError is an answer of a Google API that is not a success: its request, HTTP status, and
// the message and status of its error.
type googleError struct {
	target          string
	code            int
	message, status string
}

func (e *googleError) Error() string {
	return fmt.Sprintf("%s: %d %s", e.target, e.code, e.message)
}

// isNotFound reports whether err is an answer 404 of a Google API.
func isNotFound(err error) bool {
	var e *googleError
	return errors.As(err, &e) && e.code == http.StatusNotFound
}

// googleCall sends the request method to target with the JSON of body, none for nil, and the
// access token, and decodes the JSON answer into result unless it is nil; an answer that is not
// a success is a *googleError.
func googleCall(method, target string, body, result any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if quotaProject != "" {
		req.Header.Set("x-goog-user-project", quotaProject)
	}
	resp, err := client.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, client.MaxAnswer))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &googleError{target: method + " " + target, code: resp.StatusCode, message: strings.TrimSpace(string(answer))}
		var g struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
			} `json:"error"`
		}
		if json.Unmarshal(answer, &g) == nil && g.Error.Message != "" {
			e.message, e.status = g.Error.Message, g.Error.Status
		}
		return e
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(answer, result); err != nil {
		return fmt.Errorf("%s %s: %w", method, target, err)
	}
	return nil
}

// operation is a long-running operation of the IAM API.
type operation struct {
	Name  string `json:"name"`
	Done  bool   `json:"done"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// wait polls the operation until it is done, at most pollTimeout, and returns its error.
func (op operation) wait() error {
	deadline := time.Now().Add(pollTimeout)
	for !op.Done {
		if time.Now().After(deadline) {
			return fmt.Errorf("the operation %s is not done after %s", op.Name, pollTimeout)
		}
		time.Sleep(pollInterval)
		if err := googleCall(http.MethodGet, iamURL+op.Name, nil, &op); err != nil {
			return err
		}
	}
	if op.Error != nil {
		return fmt.Errorf("the operation %s failed: %d %s", op.Name, op.Error.Code, op.Error.Message)
	}
	return nil
}

// policy is an IAM policy; what it holds beyond its bindings is kept as it is read.
type policy struct {
	Version      int             `json:"version,omitempty"`
	Bindings     []binding       `json:"bindings,omitempty"`
	AuditConfigs json.RawMessage `json:"auditConfigs,omitempty"`
	Etag         string          `json:"etag,omitempty"`
}

// binding is a role binding of an IAM policy, with its condition kept as it is read.
type binding struct {
	Role      string          `json:"role"`
	Members   []string        `json:"members"`
	Condition json.RawMessage `json:"condition,omitempty"`
}

// grant adds each member of grants, role and member pairs, to the binding of its role without
// a condition in the IAM policy of resource, read at getURL with getBody, and writes the policy
// with its etag to setURL when a member is new; it prints a line for each pair. With newAccount,
// the calls are retried while Google does not show the service account created in this run. A
// policy changed meanwhile is refused by Google, and the error says to run the command again.
func grant(resource, getURL string, getBody any, setURL string, grants [][2]string, newAccount bool) error {
	var p policy
	if err := retryNewAccount(newAccount, func() error {
		return googleCall(http.MethodPost, getURL, getBody, &p)
	}); err != nil {
		return err
	}
	var lines []string
	changed := false
	for _, g := range grants {
		role, member := g[0], g[1]
		status := "unchanged"
		i := slices.IndexFunc(p.Bindings, func(b binding) bool { return b.Role == role && len(b.Condition) == 0 })
		switch {
		case i < 0:
			p.Bindings = append(p.Bindings, binding{Role: role, Members: []string{member}})
			status = "created"
		case !slices.Contains(p.Bindings[i].Members, member):
			p.Bindings[i].Members = append(p.Bindings[i].Members, member)
			status = "created"
		}
		changed = changed || status == "created"
		lines = append(lines, fmt.Sprintf("role %s of %s on %s: %s", role, member, resource, status))
	}
	if changed {
		err := retryNewAccount(newAccount, func() error {
			return googleCall(http.MethodPost, setURL, map[string]any{"policy": p}, nil)
		})
		var e *googleError
		if errors.As(err, &e) && (e.code == http.StatusConflict || e.status == "ABORTED") {
			return fmt.Errorf("the IAM policy of %s changed while it was updated: run the command again", resource)
		}
		if err != nil {
			return err
		}
	}
	for _, line := range lines {
		fmt.Fprintln(stdout, line)
	}
	return nil
}

// runGoogleSetup creates the workload identity pool and the OIDC provider of the CA, with its
// keys, and the token type of the provider in simple-ca.json, leaving alone what exists.
func runGoogleSetup(args []string) error {
	fs := newFlagSet("google setup", "", "Creates, in the Google Cloud project, the workload identity pool and its OIDC provider of\n"+
		"the CA in --ca-dir, with the issuer of the CA and its keys uploaded, and sets the token type\n"+
		"of the provider in federation.types of simple-ca.json of the root CA: the base google and\n"+
		"the audience of the provider. It prints a line for each step: created, updated or unchanged.\n\n"+
		"What exists is left alone, except the keys of an existing provider, which are replaced by\n"+
		"the current ones when they differ. A pool or a provider that is deleted, a provider of another\n"+
		"issuer, and an --issuer other than federation.issuer of simple-ca.json are refused.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA (default: SIMPLE_CA_DIR, else the working directory)")
	accessFlag := fs.String("access-token", "", "Google access `token` (default: GOOGLE_OAUTH_ACCESS_TOKEN, else Application\n"+
		"Default Credentials)")
	project := fs.String("project", "", "`ID` of the Google Cloud project")
	pool := fs.String("pool", "", "`ID` of the workload identity pool")
	provider := fs.String("provider", "simple-ca", "`ID` of the workload identity pool provider")
	issuer := fs.String("issuer", "", "`URL` of federation.issuer of simple-ca.json, set when it is not; the issuer of\n"+
		"an issuing CA is followed by /NAME of the CA")
	typeName := fs.String("type", "gcp-wif", "`name` of the token type in federation.types of simple-ca.json")
	mapping := fs.String("attribute-mapping", "google.subject=assertion.sub", "attribute mapping of a new provider:\n"+
		"comma-separated `pairs` attribute=expression")
	fs.Parse(args)
	switch {
	case fs.NArg() > 0:
		return usageError(fs, "no arguments are taken, only options")
	case *project == "" || *pool == "":
		return usageError(fs, "--project and --pool are required")
	case !poolIDRE.MatchString(*pool) || strings.HasPrefix(*pool, "gcp-"):
		return fmt.Errorf("pool ID '%s' must be 4 to 32 lower-case letters, digits and hyphens, not starting with gcp-", *pool)
	case !poolIDRE.MatchString(*provider) || strings.HasPrefix(*provider, "gcp-"):
		return fmt.Errorf("provider ID '%s' must be 4 to 32 lower-case letters, digits and hyphens, not starting with gcp-",
			*provider)
	}
	attributes := map[string]string{}
	for pair := range strings.SplitSeq(*mapping, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || key == "" || value == "" {
			return fmt.Errorf("'%s' of --attribute-mapping is not a pair such as google.subject=assertion.sub", pair)
		}
		attributes[key] = value
	}

	// The issuer and the keys of the CA.
	dir := resolveCADir(*caDir)
	_, caID, err := simpleca.LocateCA(dir)
	if err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}
	setIssuer := strings.TrimSuffix(*issuer, "/")
	switch {
	case setIssuer == "":
	case cfg.Federation.Issuer == "":
		cfg.Federation.Issuer = setIssuer
	case strings.TrimSuffix(cfg.Federation.Issuer, "/") != setIssuer:
		return fmt.Errorf("--issuer %s is not federation.issuer %s of %s", *issuer, cfg.Federation.Issuer, cfg.Path)
	default:
		setIssuer = ""
	}
	iss := cfg.TokenIssuer(caID)
	switch {
	case iss == "":
		return fmt.Errorf("the CA has no issuer: give --issuer, or set federation.issuer of %s", cfg.Path)
	case !strings.HasPrefix(iss, "https://"):
		return fmt.Errorf("the issuer %s of the CA does not start with https://, which Google requires", iss)
	}
	jwks, err := simpleca.CAJWKS(dir)
	if err != nil {
		return err
	}
	if err := googleCredentials(*accessFlag); err != nil {
		return err
	}

	// The project number names the pool and the provider.
	var proj struct {
		Name string `json:"name"`
	}
	if err := googleCall(http.MethodGet, resourceManagerURL+"projects/"+url.PathEscape(*project), nil, &proj); err != nil {
		return err
	}
	number, ok := strings.CutPrefix(proj.Name, "projects/")
	if !ok || number == "" {
		return fmt.Errorf("the project %s has the name '%s', not projects/NUMBER", *project, proj.Name)
	}
	fmt.Fprintf(stdout, "project %s: number %s\n", *project, number)
	poolName := "projects/" + number + "/locations/global/workloadIdentityPools/" + *pool
	providerName := poolName + "/providers/" + *provider

	// The token type is checked before any change in Google.
	old, typeExists := cfg.Federation.Types[*typeName]
	def := old
	def.Base, def.Audience = "google", "https://iam.googleapis.com/"+providerName
	if cfg.Federation.Types == nil {
		cfg.Federation.Types = map[string]simpleca.TokenTypeConfig{}
	}
	cfg.Federation.Types[*typeName] = def
	if _, err := cfg.TokenTypes(); err != nil {
		return err
	}

	// The pool.
	var p struct {
		State string `json:"state"`
	}
	status := "unchanged"
	err = googleCall(http.MethodGet, iamURL+poolName, nil, &p)
	if isNotFound(err) {
		var op operation
		err = googleCall(http.MethodPost, iamURL+"projects/"+number+"/locations/global/workloadIdentityPools?workloadIdentityPoolId="+
			*pool, map[string]any{}, &op)
		if err == nil {
			err = op.wait()
		}
		status = "created"
	}
	if err != nil {
		return err
	}
	if p.State == "DELETED" {
		return fmt.Errorf("the pool %s is deleted: undelete it first", poolName)
	}
	fmt.Fprintf(stdout, "pool %s: %s\n", poolName, status)

	// The provider.
	var prov struct {
		State string `json:"state"`
		OIDC  *struct {
			IssuerURI string `json:"issuerUri"`
			JWKSJSON  string `json:"jwksJson"`
		} `json:"oidc"`
	}
	oidc := map[string]string{"issuerUri": iss, "jwksJson": string(jwks)}
	status = "unchanged"
	err = googleCall(http.MethodGet, iamURL+providerName, nil, &prov)
	if isNotFound(err) {
		var op operation
		err = googleCall(http.MethodPost, iamURL+poolName+"/providers?workloadIdentityPoolProviderId="+*provider,
			map[string]any{"attributeMapping": attributes, "oidc": oidc}, &op)
		if err == nil {
			err = op.wait()
		}
		status = "created"
	} else if err == nil {
		var have, want any
		switch {
		case prov.State == "DELETED":
			return fmt.Errorf("the provider %s is deleted: undelete it first", providerName)
		case prov.OIDC == nil:
			return fmt.Errorf("the provider %s is not an OIDC provider", providerName)
		case prov.OIDC.IssuerURI != iss:
			return fmt.Errorf("the provider %s has the issuer %s, not %s of the CA", providerName, prov.OIDC.IssuerURI, iss)
		}
		// The keys are compared as JSON, whatever their layout.
		json.Unmarshal([]byte(prov.OIDC.JWKSJSON), &have)
		json.Unmarshal(jwks, &want)
		if !reflect.DeepEqual(have, want) {
			var op operation
			err = googleCall(http.MethodPatch, iamURL+providerName+"?updateMask=oidc.jwksJson", map[string]any{"oidc": oidc}, &op)
			if err == nil {
				err = op.wait()
			}
			status = "updated"
		}
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "provider %s: %s\n", providerName, status)

	// simple-ca.json.
	typeStatus := "unchanged"
	switch {
	case !typeExists:
		typeStatus = "created"
	case old.Base != def.Base || old.Audience != def.Audience:
		typeStatus = "updated"
	}
	issuerStatus := "unchanged"
	if setIssuer != "" {
		issuerStatus = "created"
	}
	if setIssuer != "" || typeStatus != "unchanged" {
		if err := cfg.Save(); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "issuer %s in %s: %s\n", iss, cfg.Path, issuerStatus)
	fmt.Fprintf(stdout, "token type %s in %s: %s\n", *typeName, cfg.Path, typeStatus)
	return nil
}

// runGoogleMachine gives the machine NAME its access to Google Cloud as the principal of its
// subject, or as a service account, then makes its token of the scope federate and writes its
// federation.json.
func runGoogleMachine(args []string) error {
	fs := newFlagSet("google machine", " NAME", "Sets up the machine NAME for the token type of the provider that google setup made, in\n"+
		"this order, and prints a line for each step:\n\n"+
		"1. checks the options, makes federation.json and NAME.token in --output-dir as new empty\n"+
		"   files, removed when a later step fails, and checks that the token type has the audience\n"+
		"   of a provider and that the CA has no token NAME;\n"+
		"2. with --service-account, creates the service account when it is missing, lets the principal\n"+
		"   of the subject of NAME impersonate it with roles/iam.workloadIdentityUser, and grants it\n"+
		"   each --role on the project; without it, grants each --role to the principal;\n"+
		"3. makes the token NAME of the scope federate and the token type, and writes it to NAME.token,\n"+
		"   a new file of mode 0600, or prints its one-time setup code with --otc, valid for\n"+
		"   --otc-valid and exchanged from the clients of --otc-network;\n"+
		"4. writes federation.json of request-token, a new file.\n\n"+
		"Step 2 leaves alone the members a role already has, so after a failed step, such as an IAM\n"+
		"policy changed meanwhile, the command is run again.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA (default: SIMPLE_CA_DIR, else the working directory)")
	accessFlag := fs.String("access-token", "", "Google access `token` (default: GOOGLE_OAUTH_ACCESS_TOKEN, else Application\n"+
		"Default Credentials)")
	typeName := fs.String("type", "gcp-wif", "`name` of the token type in federation.types of simple-ca.json")
	project := fs.String("project", "", "`ID` of the Google Cloud project of the service account and the roles")
	serviceAccount := fs.String("service-account", "", "account `ID` of the service account the machine acts as, in --project")
	displayName := fs.String("display-name", "", "display `name` of a new service account (default: simple-ca NAME)")
	var roles, clients []string
	fs.Func("role", "`role` granted on the project, such as roles/browser; may be specified multiple times", func(s string) error {
		roles = append(roles, s)
		return nil
	})
	valid := 2160 * time.Hour
	fs.Func("valid", "validity `period` of the token: minutes, or a number with h, d, m (30 days) or y (365\n"+
		"days), such as 30, 8h, 180d or 1y (default: 2160h)", func(s string) (err error) {
		valid, err = simpleca.ParseDuration(s)
		return err
	})
	fs.Func("host", "client IP `address` the token is accepted from; may be specified multiple times\n"+
		"(default: any)", func(s string) error {
		clients = append(clients, s)
		return nil
	})
	// A prefix list flag adds each of its comma-separated prefixes to list.
	prefixList := func(list *[]string) func(string) error {
		return func(s string) error {
			for p := range strings.SplitSeq(s, ",") {
				if p = strings.TrimSpace(p); p == "" {
					return fmt.Errorf("empty prefix in '%s'", s)
				}
				*list = append(*list, p)
			}
			return nil
		}
	}
	fs.Func("network", "comma-separated client `prefixes` the token is accepted from, such as\n"+
		"192.168.1.0/24,10.0.0.0/8; may be specified multiple times (default: any)", prefixList(&clients))
	otc := fs.Bool("otc", false, "print a one-time setup code, exchanged for the token, instead of writing the token")
	otcValid := 15 * time.Minute
	fs.Func("otc-valid", "validity `period` of the setup code, such as 15 (minutes) or 1h (default: 15)", func(s string) (err error) {
		otcValid, err = simpleca.ParseDuration(s)
		return err
	})
	var setupClients []string
	fs.Func("otc-network", "comma-separated client `prefixes` the setup code is exchanged from; may be\n"+
		"specified multiple times (default: any)", prefixList(&setupClients))
	caURL := fs.String("ca-url", "", "`URL` of the CA at serve, as the machine reaches it (default: the issuer of the CA)")
	outputDir := fs.String("output-dir", ".", "`directory` of NAME.token and federation.json")
	var rest []string
	for fs.Parse(args); fs.NArg() > 0; fs.Parse(args) {
		rest, args = append(rest, fs.Arg(0)), fs.Args()[1:]
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	switch {
	case len(rest) != 1:
		return usageError(fs, "the name of the machine is the one argument")
	case (*serviceAccount != "" || len(roles) > 0) && *project == "":
		return usageError(fs, "--service-account and --role need --project")
	case given["display-name"] && *serviceAccount == "":
		return usageError(fs, "--display-name needs --service-account")
	case (given["otc-valid"] || given["otc-network"]) && !*otc:
		return usageError(fs, "--otc-valid and --otc-network need --otc")
	case *serviceAccount != "" && !accountIDRE.MatchString(*serviceAccount):
		return fmt.Errorf("service account ID '%s' must be 6 to 30 lower-case letters, digits and hyphens, starting "+
			"with a letter and not ending with a hyphen", *serviceAccount)
	}
	name := rest[0]
	var setupValid time.Duration
	if *otc {
		setupValid = otcValid
	}

	// The files of the machine are made empty first, and removed unless the command succeeds.
	configPath := filepath.Join(*outputDir, client.DefaultConfig)
	tokenPath := filepath.Join(*outputDir, name+".token")
	var files []*os.File
	succeeded := false
	defer func() {
		for _, f := range files {
			f.Close()
			if !succeeded {
				os.Remove(f.Name())
			}
		}
	}()
	configFile, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("%w; federation.json is written as a new file", err)
	}
	files = append(files, configFile)
	var tokenFile *os.File
	if !*otc {
		if tokenFile, err = os.OpenFile(tokenPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return fmt.Errorf("%w; the token is written to a new file", err)
		}
		files = append(files, tokenFile)
	}

	// The token type gives the provider, and the principal the subject of NAME.
	dir := resolveCADir(*caDir)
	if err := simpleca.ReadKeyPassphrase(filepath.Join(dir, "ca_key.pem")); err != nil {
		return err
	}
	_, caID, err := simpleca.LocateCA(dir)
	if err != nil {
		return err
	}
	cfg, err := simpleca.LoadRootConfig(dir)
	if err != nil {
		return err
	}
	m := audienceRE.FindStringSubmatch(cfg.Federation.Types[*typeName].Audience)
	if m == nil {
		return fmt.Errorf("the token type %s of %s has no audience of a Google workload identity pool provider: "+
			"run simple-ca-wif google setup", *typeName, cfg.Path)
	}
	fed := &simpleca.TokenFederate{Type: *typeName}
	resolved, err := fed.Resolve(cfg, caID, name)
	if err != nil {
		return err
	}
	if _, _, err := simpleca.NewTokenSetup(valid, setupValid, setupClients); err != nil {
		return err
	}
	if _, _, err := simpleca.PrepareToken(dir, name, fed, valid, []string{"federate"}, nil, nil, nil, clients); err != nil {
		return err
	}
	db, err := simpleca.LoadTokens(dir)
	if err != nil {
		return err
	}
	if _, ok := db.Tokens[name]; ok {
		return fmt.Errorf("token '%s' exists", name)
	}
	principal := "principal://iam.googleapis.com/projects/" + m[2] + "/locations/global/workloadIdentityPools/" + m[3] +
		"/subject/" + resolved.Subject
	settings := client.Settings{CAURL: cmp.Or(*caURL, resolved.Issuer), TokenFile: name + ".token",
		Provider: "//iam.googleapis.com/" + m[1]}

	// The access of the machine.
	if *serviceAccount != "" || len(roles) > 0 {
		if err := googleCredentials(*accessFlag); err != nil {
			return err
		}
		member, newAccount := principal, false
		if *serviceAccount != "" {
			projectURL := iamURL + "projects/" + url.PathEscape(*project) + "/serviceAccounts"
			email := *serviceAccount + "@" + *project + ".iam.gserviceaccount.com"
			var account struct {
				Email string `json:"email"`
			}
			status := "unchanged"
			err := googleCall(http.MethodGet, projectURL+"/"+email, nil, &account)
			if isNotFound(err) {
				err = googleCall(http.MethodPost, projectURL, map[string]any{"accountId": *serviceAccount,
					"serviceAccount": map[string]string{"displayName": cmp.Or(*displayName, "simple-ca "+name)}}, &account)
				status = "created"
			}
			if err != nil {
				return err
			}
			email = cmp.Or(account.Email, email)
			fmt.Fprintf(stdout, "service account %s: %s\n", email, status)
			accountURL := projectURL + "/" + email
			newAccount = status == "created"
			if err := grant(email, accountURL+":getIamPolicy?options.requestedPolicyVersion=3", nil, accountURL+":setIamPolicy",
				[][2]string{{"roles/iam.workloadIdentityUser", principal}}, newAccount); err != nil {
				return err
			}
			member, settings.ServiceAccount = "serviceAccount:"+email, email
		}
		if len(roles) > 0 {
			var grants [][2]string
			for _, role := range roles {
				grants = append(grants, [2]string{role, member})
			}
			projectURL := resourceManagerURL + "projects/" + url.PathEscape(*project)
			if err := grant("project "+*project, projectURL+":getIamPolicy",
				map[string]any{"options": map[string]int{"requestedPolicyVersion": 3}}, projectURL+":setIamPolicy",
				grants, newAccount); err != nil {
				return err
			}
		}
	}

	// The token.
	token, err := simpleca.AddToken(dir, name, fed, valid, []string{"federate"}, nil, nil, nil, clients, setupValid, setupClients)
	if err != nil {
		return err
	}
	record := append([]any{"name", name, "scopes", "federate", "setup_code", setupValid > 0}, simpleca.FederateAudit(fed)...)
	simpleca.Audit(dir, "token.create", append(record, "via", "cli", "actor", simpleca.CLIActor())...)
	if *otc {
		fmt.Fprintf(stdout, "token %s: created, setup code %s\n", name, token)
	} else {
		_, err := tokenFile.WriteString(token + "\n")
		if err := cmp.Or(err, tokenFile.Close()); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "token %s in %s: created\n", name, tokenPath)
	}

	// federation.json.
	b, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	_, err = configFile.Write(append(b, '\n'))
	if err := cmp.Or(err, configFile.Close()); err != nil {
		return err
	}
	succeeded = true
	fmt.Fprintf(stdout, "%s: created\n", configPath)
	return nil
}

// retryNewAccount runs call once, or, with retry, again while it fails because Google does not
// show a service account created in this run yet, waiting accountWait at first, doubling up to
// accountWaitMax, for at most accountWaitTotal.
func retryNewAccount(retry bool, call func() error) error {
	wait, deadline := accountWait, time.Now().Add(accountWaitTotal)
	for {
		err := call()
		var e *googleError
		missing := errors.As(err, &e) && (e.code == http.StatusNotFound ||
			e.code == http.StatusBadRequest && strings.Contains(strings.ToLower(e.message), "does not exist"))
		if !retry || !missing || time.Now().Add(wait).After(deadline) {
			return err
		}
		time.Sleep(wait)
		wait = min(2*wait, accountWaitMax)
	}
}
