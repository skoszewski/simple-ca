package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/jose"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// tokCapture runs the command line args of simple-ca and returns what it printed to stdout.
func tokCapture(t *testing.T, args ...string) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = writer
	printed := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(reader)
		printed <- b
	}()
	err = run(args)
	os.Stdout = stdout
	writer.Close()
	return string(<-printed), err
}

// tokFederationCA makes a root CA with the issuing CA servers, whose simple-ca.json sets the
// issuer https://pki.example.com, and returns the root CA directory.
func tokFederationCA(t *testing.T) string {
	t.Helper()
	root := newHierarchy(t)
	cfg, err := simpleca.LoadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Federation.Issuer = "https://pki.example.com"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	return root
}

// tokClaims verifies the JWT jwt with the key of caCert and returns its claims.
func tokClaims(t *testing.T, caCert *x509.Certificate, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", jwt)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := jose.VerifyJWS(jose.JWTAlg(caCert.PublicKey), caCert.PublicKey, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		t.Fatalf("the signature of the JWT: %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestTokenIssue(t *testing.T) {
	root := tokFederationCA(t)
	servers := filepath.Join(root, "servers")
	out, err := tokCapture(t, "token", "issue", "--ca-dir", servers, "--token-type", "azure", "--claim", "env=prod", "build-01")
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := simpleca.LoadCert(filepath.Join(servers, "ca_cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	claims := tokClaims(t, caCert, strings.TrimSpace(out))
	if claims["iss"] != "https://pki.example.com/servers" || claims["sub"] != "build-01" ||
		claims["aud"] != "api://AzureADTokenExchange" || claims["env"] != "prod" {
		t.Errorf("claims of token issue: %v", claims)
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--ca-dir", servers, "build-01"}, "--token-type is required"},
		{[]string{"--ca-dir", servers, "--token-type", "azure", "Bad_Name"}, `name "Bad_Name" is not a kebab-case name`},
		{[]string{"--ca-dir", t.TempDir(), "--token-type", "azure", "build-01"}, "CA certificate and key not found in"},
		{[]string{"--ca-dir", servers, "--token-type", "nosuch", "build-01"}, `unknown token type "nosuch"`},
		{[]string{"--ca-dir", servers, "--token-type", "google", "--audience", "//iam.example.com/x", "--valid", "2d", "build-01"},
			"allows a validity of at most"},
	} {
		if _, err := tokCapture(t, append([]string{"token", "issue"}, c.args...)...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("token issue %q: %v, want %s", c.args, err, c.want)
		}
	}
	if _, err := tokCapture(t, "token", "issue", "--ca-dir", servers, "--token-type", "azure", "--claim", "noequals", "build-01"); err == nil {
		t.Error("token issue --claim noequals: no error")
	}
}

func TestClaimFlag(t *testing.T) {
	var claims map[string]string
	set := claimFlag(&claims)
	if err := set("env=prod"); err != nil || claims["env"] != "prod" {
		t.Errorf("env=prod: %v, %v", err, claims)
	}
	if err := set("team=a=b"); err != nil || claims["team"] != "a=b" {
		t.Errorf("team=a=b: %v, %v", err, claims)
	}
	if err := set("noequals"); err == nil || err.Error() != `"noequals" is not a claim such as env=prod` {
		t.Errorf("noequals: %v", err)
	}
}

func TestTokenDescribeRenew(t *testing.T) {
	root := newHierarchy(t)
	servers := filepath.Join(root, "servers")
	out, err := tokCapture(t, "token", "create", "--ca-dir", servers, "--domain", "example.com", "web-deploy")
	if err != nil {
		t.Fatal(err)
	}
	jwt := strings.TrimSpace(out)
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contains := func(what, out string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(out, w) {
				t.Errorf("%s:\n%s\nwant %q", what, out, w)
			}
		}
	}

	out, err = tokCapture(t, "token", "describe", "--ca-dir", servers, "web-deploy")
	if err != nil {
		t.Fatal(err)
	}
	contains("token describe NAME", out, "Name:", "web-deploy", "Status:", "valid until", "Domains:", "example.com")
	out, err = tokCapture(t, "token", "describe", "--token-file", jwtFile)
	if err != nil {
		t.Fatal(err)
	}
	contains("token describe --token-file", out, "web-deploy", "Signature:", "not checked")
	if strings.Contains(out, "Domains:") {
		t.Errorf("token describe --token-file without --ca-dir shows the limits:\n%s", out)
	}
	input := cli.Input
	t.Cleanup(func() { cli.Input = input })
	cli.Input = strings.NewReader(jwt + "\n")
	out, err = tokCapture(t, "token", "describe", "--ca-dir", servers, "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	contains("token describe --stdin --ca-dir", out, "web-deploy", "Domains:", "example.com")
	cli.Input = strings.NewReader(jwt)
	if _, err := tokCapture(t, "token", "describe", "--ca-dir", root, "--stdin"); err == nil ||
		!strings.Contains(err.Error(), "the token is not one signed by the CA in") {
		t.Errorf("token describe with the root CA of a token of servers: %v", err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage")
	if err := os.WriteFile(garbage, []byte("not a token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tokCapture(t, "token", "describe", "--token-file", garbage); err == nil ||
		err.Error() != "the token is not a JWT of simple-ca token create" {
		t.Errorf("token describe of a file without a token: %v", err)
	}

	// token renew gives a new JWT, and the old one is shown as refused.
	out, err = tokCapture(t, "token", "renew", "--ca-dir", servers, "web-deploy")
	if renewed := strings.TrimSpace(out); err != nil || !strings.HasPrefix(renewed, "eyJ") || renewed == jwt {
		t.Fatalf("token renew: %q, %v, want a new JWT", out, err)
	}
	out, err = tokCapture(t, "token", "describe", "--ca-dir", servers, "--token-file", jwtFile)
	if err != nil {
		t.Fatal(err)
	}
	contains("token describe of a renewed token", out, "refused: the token was renewed, revoked or removed in")
	out, err = tokCapture(t, "token", "renew", "--ca-dir", servers, "--otc", "web-deploy")
	if code := strings.TrimSpace(out); err != nil || code == "" || strings.HasPrefix(code, "eyJ") {
		t.Errorf("token renew --otc: %q, %v, want a setup code", out, err)
	}
	out, err = tokCapture(t, "token", "describe", "--ca-dir", servers, "web-deploy")
	if err != nil {
		t.Fatal(err)
	}
	contains("token describe after token renew --otc", out, "waits for its setup code")

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"describe", "--token-file", jwtFile, "--stdin"}, "give --token-file or --stdin, not both"},
		{[]string{"describe", "--stdin", "web-deploy"}, "give NAME, or --token-file or --stdin, not both"},
		{[]string{"describe"}, "give NAME, --token-file or --stdin"},
		{[]string{"describe", "--ca-dir", servers, "nosuch"}, `token "nosuch" not found in`},
		{[]string{"describe", "--ca-dir", t.TempDir(), "web-deploy"}, "CA certificate not found in"},
		{[]string{"describe", "--token-file", filepath.Join(t.TempDir(), "missing")}, "no such file"},
		{[]string{"renew", "--ca-dir", servers, "--otc-valid", "30", "web-deploy"}, "--otc-valid and --otc-network need --otc"},
		{[]string{"renew", "--ca-dir", servers, "nosuch"}, "nosuch"},
	} {
		if _, err := tokCapture(t, append([]string{"token"}, c.args...)...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("token %q: %v, want %s", c.args, err, c.want)
		}
	}
	for _, args := range [][]string{{"renew", "--ca-dir", servers}, {"describe", "a", "b"}, {"jwks", "--ca-dir", servers, "extra"},
		{"issue", "--token-type", "azure"}} {
		if _, err := tokCapture(t, append([]string{"token"}, args...)...); !errors.Is(err, cli.ErrUsage) {
			t.Errorf("token %q: %v, want the usage", args, err)
		}
	}

	// A tokens-db.json that cannot be read fails the commands reading it.
	if err := os.WriteFile(filepath.Join(servers, tokens.TokensFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tokCapture(t, "token", "describe", "--ca-dir", servers, "web-deploy"); err == nil {
		t.Error("token describe NAME with a malformed tokens-db.json: no error")
	}
	cli.Input = strings.NewReader(jwt)
	if _, err := tokCapture(t, "token", "describe", "--ca-dir", servers, "--stdin"); err == nil {
		t.Error("token describe --stdin --ca-dir with a malformed tokens-db.json: no error")
	}
}

func TestTokenJWKS(t *testing.T) {
	root := newHierarchy(t)
	servers := filepath.Join(root, "servers")
	out, err := tokCapture(t, "token", "jwks", "--ca-dir", servers)
	if err != nil {
		t.Fatal(err)
	}
	want, err := tokens.CAJWKS(servers)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want)+"\n" {
		t.Errorf("token jwks:\n%s\nwant\n%s", out, want)
	}
	if _, err := tokCapture(t, "token", "jwks", "--ca-dir", t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "CA certificate not found in") {
		t.Errorf("token jwks without a CA: %v", err)
	}
}
