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

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// request is what a test server received.
type request struct {
	Method, Path, ContentType, Authorization string
	Body                                     []byte
}

// serve starts a server that records each request and answers with status and answer.
func serve(t *testing.T, status int, answer string) (*httptest.Server, *[]request) {
	t.Helper()
	var mu sync.Mutex
	var got []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, request{r.Method, r.URL.EscapedPath(), r.Header.Get("Content-Type"),
			r.Header.Get("Authorization"), body})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// one returns the only request a server received.
func one(t *testing.T, got *[]request) request {
	t.Helper()
	if len(*got) != 1 {
		t.Fatalf("the server received %d requests, want 1", len(*got))
	}
	return (*got)[0]
}

// redirect sends every request to the test server at target and records the URL it was sent to.
type redirect struct {
	target *url.URL
	mu     sync.Mutex
	urls   []string
}

func (rd *redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	rd.mu.Lock()
	rd.urls = append(rd.urls, req.URL.String())
	rd.mu.Unlock()
	r := req.Clone(req.Context())
	r.URL.Scheme = rd.target.Scheme
	r.URL.Host = rd.target.Host
	r.Host = ""
	return http.DefaultTransport.RoundTrip(r)
}

// redirectTo sets the transport of Client to a redirect to srv until the test ends.
func redirectTo(t *testing.T, srv *httptest.Server) *redirect {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rd := &redirect{target: u}
	orig := Client.Transport
	Client.Transport = rd
	t.Cleanup(func() { Client.Transport = orig })
	return rd
}

// sentTo checks that the only request through rd was sent to want.
func sentTo(t *testing.T, rd *redirect, want string) {
	t.Helper()
	if len(rd.urls) != 1 || rd.urls[0] != want {
		t.Fatalf("requests sent to %q, want [%q]", rd.urls, want)
	}
}

// jsonBody decodes the JSON object of a request body.
func jsonBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body %q is not a JSON object: %v", body, err)
	}
	return m
}

func TestPostSendsAndDecodes(t *testing.T) {
	srv, got := serve(t, http.StatusOK, `{"name":"web","count":2}`)
	var result struct {
		Name  string
		Count int
	}
	body := []byte(`{"a":"b"}`)
	if err := Post(srv.URL+"/api/x", "application/json", "secret", body, &result); err != nil {
		t.Fatal(err)
	}
	r := one(t, got)
	if r.Method != http.MethodPost || r.Path != "/api/x" {
		t.Errorf("request %s %s, want POST /api/x", r.Method, r.Path)
	}
	if r.ContentType != "application/json" {
		t.Errorf("Content-Type %q", r.ContentType)
	}
	if r.Authorization != "Bearer secret" {
		t.Errorf("Authorization %q, want Bearer secret", r.Authorization)
	}
	if string(r.Body) != string(body) {
		t.Errorf("body %q, want %q", r.Body, body)
	}
	if result.Name != "web" || result.Count != 2 {
		t.Errorf("result %+v", result)
	}
}

func TestPostWithoutBearer(t *testing.T) {
	srv, got := serve(t, http.StatusOK, `{}`)
	var result map[string]any
	if err := Post(srv.URL, "application/x-www-form-urlencoded", "", []byte("a=b"), &result); err != nil {
		t.Fatal(err)
	}
	r := one(t, got)
	if r.Authorization != "" {
		t.Errorf("Authorization %q, want none", r.Authorization)
	}
	if r.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type %q", r.ContentType)
	}
}

func TestPostErrors(t *testing.T) {
	for _, tc := range []struct {
		name, answer, message string
		status                int
	}{
		{"error", `{"error":"the token is not known"}`, "the token is not known", http.StatusUnauthorized},
		{"error_description", `{"error":"invalid_grant","error_description":"the JWT expired"}`,
			"the JWT expired", http.StatusBadRequest},
		{"description alone", `{"error_description":"no client"}`, "no client", http.StatusBadRequest},
		{"error object", `{"error":{"code":403,"message":"denied"}}`,
			`{"error":{"code":403,"message":"denied"}}`, http.StatusForbidden},
		{"empty error", `{"error":""}`, `{"error":""}`, http.StatusBadRequest},
		{"text", "  bad gateway\n", "bad gateway", http.StatusBadGateway},
		{"empty", "", "", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := serve(t, tc.status, tc.answer)
			var result map[string]any
			err := Post(srv.URL+"/api/x", "application/json", "", []byte("{}"), &result)
			want := fmt.Sprintf("%q: %d %q", srv.URL+"/api/x", tc.status, tc.message)
			if err == nil || err.Error() != want {
				t.Errorf("error %v, want %q", err, want)
			}
		})
	}
}

func TestPostErrorEscapesMessage(t *testing.T) {
	srv, _ := serve(t, http.StatusBadRequest, `{"error":"bad\nforged line \u001b[31mred"}`)
	err := Post(srv.URL+"/api/x", "application/json", "", []byte("{}"), nil)
	want := `"` + srv.URL + `/api/x": 400 "bad\nforged line \x1b[31mred"`
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %s", err, want)
	}
}

func TestPostAnswerNotJSON(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, "<html>proxy</html>")
	var result map[string]any
	err := Post(srv.URL+"/api/x", "application/json", "", nil, &result)
	if err == nil || !strings.HasPrefix(err.Error(), strconv.Quote(srv.URL+"/api/x")+": ") {
		t.Errorf("error %v, want one starting with the URL", err)
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Errorf("error %v does not wrap a json.SyntaxError", err)
	}
}

func TestPostAnswerLargerThanMaxAnswer(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		srv, _ := serve(t, http.StatusOK, `{"token":"`+strings.Repeat("a", MaxAnswer)+`"}`)
		var result struct{ Token string }
		err := Post(srv.URL, "application/json", "", nil, &result)
		if err == nil || !strings.HasPrefix(err.Error(), strconv.Quote(srv.URL)+": ") {
			t.Errorf("error %v, want the cut answer refused with the URL", err)
		}
	})
	t.Run("ok within", func(t *testing.T) {
		token := strings.Repeat("a", MaxAnswer-len(`{"token":""}`))
		srv, _ := serve(t, http.StatusOK, `{"token":"`+token+`"}`)
		var result struct{ Token string }
		if err := Post(srv.URL, "application/json", "", nil, &result); err != nil {
			t.Fatal(err)
		}
		if result.Token != token {
			t.Errorf("token of %d bytes, want %d", len(result.Token), len(token))
		}
	})
	t.Run("error", func(t *testing.T) {
		srv, _ := serve(t, http.StatusInternalServerError, strings.Repeat("e", MaxAnswer+100))
		var result map[string]any
		err := Post(srv.URL, "application/json", "", nil, &result)
		want := fmt.Sprintf("%q: 500 %q", srv.URL, strings.Repeat("e", MaxAnswer))
		if err == nil {
			t.Fatal("a 500 answer is not an error")
		}
		if err.Error() != want {
			t.Errorf("error of %d bytes, want %d: the answer cut at MaxAnswer", len(err.Error()), len(want))
		}
	})
}

func TestPostRequestErrors(t *testing.T) {
	var result map[string]any
	if err := Post("http://[::1", "application/json", "", nil, &result); err == nil {
		t.Error("an invalid URL is not refused")
	}
	srv, _ := serve(t, http.StatusOK, `{}`)
	srv.Close()
	if err := Post(srv.URL, "application/json", "", nil, &result); err == nil {
		t.Error("a closed server is not an error")
	}
}

func TestExchange(t *testing.T) {
	answer := `{"ca":"root","name":"web","token":"jwt-of-token","scopes":["sign"]}`
	for _, caURL := range []string{"", "/", "/ca1", "/ca1/"} {
		t.Run(caURL, func(t *testing.T) {
			srv, got := serve(t, http.StatusOK, answer)
			token, err := Exchange(srv.URL+caURL, "ABCD-EFGH")
			if err != nil {
				t.Fatal(err)
			}
			if token != "jwt-of-token" {
				t.Errorf("token %q", token)
			}
			r := one(t, got)
			if r.Method != http.MethodPost || r.Path != "/api/token-setup" {
				t.Errorf("request %s %s, want POST /api/token-setup", r.Method, r.Path)
			}
			if r.ContentType != "application/json" || r.Authorization != "" {
				t.Errorf("Content-Type %q, Authorization %q", r.ContentType, r.Authorization)
			}
			if b := jsonBody(t, r.Body); !reflect.DeepEqual(b, map[string]any{"code": "ABCD-EFGH"}) {
				t.Errorf("body %v, want the code alone", b)
			}
		})
	}
}

func TestExchangeInvalidURL(t *testing.T) {
	for _, caURL := range []string{"", "pki.example.com", "https://", "/api", "http://[::1",
		"https://pki.example.com/ca1/api/token-setup"} {
		_, err := Exchange(caURL, "code")
		if err == nil || !strings.Contains(err.Error(), "such as") {
			t.Errorf("Exchange(%q): error %v", caURL, err)
		}
	}
}

func TestExchangeAnswerWithoutToken(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, `{"ca":"root","name":"web"}`)
	_, err := Exchange(srv.URL, "code")
	want := strconv.Quote(srv.URL+"/api/token-setup") + ": the answer holds no token"
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestExchangeServerError(t *testing.T) {
	srv, _ := serve(t, http.StatusNotFound, `{"error":"the setup code is not known"}`)
	_, err := Exchange(srv.URL, "code")
	want := fmt.Sprintf("%q: 404 %q", srv.URL+"/api/token-setup", "the setup code is not known")
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestFederationToken(t *testing.T) {
	expires := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	answer := `{"token":"jwt","token_type":"google","audience":"aud","subject":"sub","expires":"` +
		expires.Format(time.RFC3339) + `"}`
	for _, tc := range []struct{ suffix, path string }{
		{"", "/api/federation-token"},
		{"/", "/api/federation-token"},
		{"/ca1", "/ca1/api/federation-token"},
		{"/ca1/", "/ca1/api/federation-token"},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			srv, got := serve(t, http.StatusOK, answer)
			jwt, exp, err := FederationToken(srv.URL+tc.suffix, "api-token")
			if err != nil {
				t.Fatal(err)
			}
			if jwt != "jwt" || !exp.Equal(expires) {
				t.Errorf("FederationToken = %q, %v", jwt, exp)
			}
			r := one(t, got)
			if r.Method != http.MethodPost || r.Path != tc.path {
				t.Errorf("request %s %s, want POST %s", r.Method, r.Path, tc.path)
			}
			if r.Authorization != "Bearer api-token" || r.ContentType != "application/json" {
				t.Errorf("Authorization %q, Content-Type %q", r.Authorization, r.ContentType)
			}
			if string(r.Body) != "{}" {
				t.Errorf("body %q, want {}", r.Body)
			}
		})
	}
}

func TestFederationTokenErrors(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, `{"token_type":"google"}`)
	_, _, err := FederationToken(srv.URL, "api-token")
	if want := strconv.Quote(srv.URL) + ": the answer holds no token"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
	srv, _ = serve(t, http.StatusNotFound, "404 page not found")
	_, _, err = FederationToken(srv.URL+"/nosuch", "api-token")
	if want := strconv.Quote(srv.URL) + " has no issuing CA nosuch"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
	if _, _, err = FederationToken(srv.URL+"/ca1/api/federation-token", "api-token"); err == nil ||
		!strings.Contains(err.Error(), "not /NAME of an issuing CA") {
		t.Errorf("a CA URL with the path of the API: %v", err)
	}
	srv, _ = serve(t, http.StatusForbidden, `{"error":"the token does not have the scope federate"}`)
	_, _, err = FederationToken(srv.URL, "api-token")
	want := fmt.Sprintf("%q: 403 %q", srv.URL+"/api/federation-token", "the token does not have the scope federate")
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestGoogleToken(t *testing.T) {
	srv, got := serve(t, http.StatusOK,
		`{"access_token":"federated","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`)
	rd := redirectTo(t, srv)
	provider := "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q"
	token, err := GoogleToken(provider, "the-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if token != "federated" {
		t.Errorf("token %q", token)
	}
	sentTo(t, rd, STSURL)
	r := one(t, got)
	if r.Method != http.MethodPost || r.ContentType != "application/json" || r.Authorization != "" {
		t.Errorf("request %s, Content-Type %q, Authorization %q", r.Method, r.ContentType, r.Authorization)
	}
	want := map[string]any{
		"grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":           provider,
		"scope":              DefaultGoogleScope,
		"requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectTokenType":   JWTTokenType,
		"subjectToken":       "the-jwt",
	}
	if b := jsonBody(t, r.Body); !reflect.DeepEqual(b, want) {
		t.Errorf("body %v, want %v", b, want)
	}
}

func TestGoogleTokenErrors(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, `{"token_type":"Bearer"}`)
	redirectTo(t, srv)
	_, err := GoogleToken("provider", "jwt")
	if want := STSURL + ": the answer holds no access_token"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
	srv, _ = serve(t, http.StatusBadRequest,
		`{"error":"invalid_grant","error_description":"The audience does not match"}`)
	redirectTo(t, srv)
	_, err = GoogleToken("provider", "jwt")
	if want := fmt.Sprintf("%q: 400 %q", STSURL, "The audience does not match"); err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestServiceAccountToken(t *testing.T) {
	srv, got := serve(t, http.StatusOK, `{"accessToken":"sa-token","expireTime":"2026-11-11T13:00:00Z"}`)
	rd := redirectTo(t, srv)
	email := "ca@project.iam.gserviceaccount.com"
	token, err := ServiceAccountToken(email, "https://www.googleapis.com/auth/devstorage.read_only", "federated")
	if err != nil {
		t.Fatal(err)
	}
	if token != "sa-token" {
		t.Errorf("token %q", token)
	}
	sentTo(t, rd, "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+email+
		":generateAccessToken")
	r := one(t, got)
	if r.Method != http.MethodPost || r.ContentType != "application/json" {
		t.Errorf("request %s, Content-Type %q", r.Method, r.ContentType)
	}
	if r.Authorization != "Bearer federated" {
		t.Errorf("Authorization %q, want the federated token", r.Authorization)
	}
	want := map[string]any{"scope": []any{"https://www.googleapis.com/auth/devstorage.read_only"}}
	if b := jsonBody(t, r.Body); !reflect.DeepEqual(b, want) {
		t.Errorf("body %v, want %v", b, want)
	}
}

func TestServiceAccountTokenEscapesEmail(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, `{"accessToken":"sa-token"}`)
	rd := redirectTo(t, srv)
	if _, err := ServiceAccountToken("a/b?c", DefaultGoogleScope, "federated"); err != nil {
		t.Fatal(err)
	}
	sentTo(t, rd, "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a%2Fb%3Fc"+
		":generateAccessToken")
}

func TestServiceAccountTokenErrors(t *testing.T) {
	email := "ca@project.iam.gserviceaccount.com"
	target := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + email +
		":generateAccessToken"
	srv, _ := serve(t, http.StatusOK, `{"expireTime":"2026-11-11T13:00:00Z"}`)
	redirectTo(t, srv)
	_, err := ServiceAccountToken(email, DefaultGoogleScope, "federated")
	if want := strconv.Quote(target) + ": the answer holds no accessToken"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
	answer := `{"error":{"code":403,"message":"Permission denied","status":"PERMISSION_DENIED"}}`
	srv, _ = serve(t, http.StatusForbidden, answer)
	redirectTo(t, srv)
	_, err = ServiceAccountToken(email, DefaultGoogleScope, "federated")
	if want := fmt.Sprintf("%q: 403 %q", target, answer); err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}

func TestEntraToken(t *testing.T) {
	srv, got := serve(t, http.StatusOK, `{"token_type":"Bearer","expires_in":3599,"access_token":"entra"}`)
	rd := redirectTo(t, srv)
	tenant := "00000000-0000-0000-0000-000000000001"
	token, err := EntraToken(tenant, "app-id", DefaultEntraScope, "the-jwt")
	if err != nil {
		t.Fatal(err)
	}
	if token != "entra" {
		t.Errorf("token %q", token)
	}
	sentTo(t, rd, "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token")
	r := one(t, got)
	if r.Method != http.MethodPost || r.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("request %s, Content-Type %q", r.Method, r.ContentType)
	}
	if r.Authorization != "" {
		t.Errorf("Authorization %q, want none", r.Authorization)
	}
	form, err := url.ParseQuery(string(r.Body))
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {"app-id"},
		"scope":                 {DefaultEntraScope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {"the-jwt"},
	}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("form %v, want %v", form, want)
	}
}

func TestEntraTokenEscapesTenant(t *testing.T) {
	srv, _ := serve(t, http.StatusOK, `{"access_token":"entra"}`)
	rd := redirectTo(t, srv)
	if _, err := EntraToken("a/b c", "app-id", DefaultEntraScope, "jwt"); err != nil {
		t.Fatal(err)
	}
	sentTo(t, rd, "https://login.microsoftonline.com/a%2Fb%20c/oauth2/v2.0/token")
}

func TestEntraTokenErrors(t *testing.T) {
	target := "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
	srv, _ := serve(t, http.StatusOK, `{"token_type":"Bearer"}`)
	redirectTo(t, srv)
	_, err := EntraToken("tenant", "app-id", DefaultEntraScope, "jwt")
	if want := strconv.Quote(target) + ": the answer holds no access_token"; err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
	srv, _ = serve(t, http.StatusUnauthorized,
		`{"error":"invalid_client","error_description":"AADSTS70021: No matching federated identity record found"}`)
	redirectTo(t, srv)
	_, err = EntraToken("tenant", "app-id", DefaultEntraScope, "jwt")
	want := fmt.Sprintf("%q: 401 %q", target, "AADSTS70021: No matching federated identity record found")
	if err == nil || err.Error() != want {
		t.Errorf("error %v, want %q", err, want)
	}
}
