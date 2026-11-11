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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skoszewski/simple-ca/pkg/client"
)

// useADC writes the credential file cred, points GOOGLE_APPLICATION_CREDENTIALS at it, and clears
// the access tokens; it restores oauthTokenURL after the test.
func useADC(t *testing.T, cred map[string]any) {
	b, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "")
	old := oauthTokenURL
	t.Cleanup(func() { oauthTokenURL, accessToken, quotaProject = old, "", "" })
}

func TestADCAuthorizedUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		want := map[string]string{"grant_type": "refresh_token", "client_id": "id-1", "client_secret": "secret-1",
			"refresh_token": "refresh-1"}
		for k, v := range want {
			if r.PostForm.Get(k) != v {
				t.Errorf("%s = %q, want %q", k, r.PostForm.Get(k), v)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "user-token", "expires_in": 3599})
	}))
	defer srv.Close()
	useADC(t, map[string]any{"type": "authorized_user", "client_id": "id-1", "client_secret": "secret-1",
		"refresh_token": "refresh-1", "quota_project_id": "quota-project"})
	oauthTokenURL = srv.URL
	if err := googleCredentials(""); err != nil {
		t.Fatal(err)
	}
	if accessToken != "user-token" || quotaProject != "quota-project" {
		t.Errorf("accessToken %q, quotaProject %q", accessToken, quotaProject)
	}
}

func TestADCServiceAccount(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var tokenURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if g := r.PostForm.Get("grant_type"); g != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type %q", g)
		}
		parts := strings.Split(r.PostForm.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Fatalf("assertion %q", r.PostForm.Get("assertion"))
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("signature: %v", err)
		}
		var header map[string]string
		var claims map[string]any
		b, _ := base64.RawURLEncoding.DecodeString(parts[0])
		json.Unmarshal(b, &header)
		b, _ = base64.RawURLEncoding.DecodeString(parts[1])
		json.Unmarshal(b, &claims)
		if header["alg"] != "RS256" || header["typ"] != "JWT" || header["kid"] != "key-1" {
			t.Errorf("header %v", header)
		}
		if claims["iss"] != "wif@lab-project.iam.gserviceaccount.com" || claims["aud"] != tokenURI ||
			claims["scope"] != client.DefaultGoogleScope || claims["exp"].(float64)-claims["iat"].(float64) != 3600 {
			t.Errorf("claims %v", claims)
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "sa-token"})
	}))
	defer srv.Close()
	tokenURI = srv.URL + "/token"
	useADC(t, map[string]any{"type": "service_account", "client_email": "wif@lab-project.iam.gserviceaccount.com",
		"private_key_id": "key-1", "token_uri": tokenURI,
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if err := googleCredentials(""); err != nil {
		t.Fatal(err)
	}
	if accessToken != "sa-token" {
		t.Errorf("accessToken %q", accessToken)
	}
}

func TestCredentialsChoice(t *testing.T) {
	useADC(t, map[string]any{"type": "external_account"})
	if err := googleCredentials(""); err == nil || !strings.Contains(err.Error(), "'external_account' is not supported") {
		t.Errorf("external_account: %v", err)
	}
	if err := googleCredentials("flag-token"); err != nil || accessToken != "flag-token" {
		t.Errorf("--access-token: %v, %q", err, accessToken)
	}
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "env-token")
	if err := googleCredentials(""); err != nil || accessToken != "env-token" {
		t.Errorf("GOOGLE_OAUTH_ACCESS_TOKEN: %v, %q", err, accessToken)
	}
	t.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	if err := googleCredentials(""); err == nil || !strings.Contains(err.Error(), "missing.json of GOOGLE_APPLICATION_CREDENTIALS does not exist") {
		t.Errorf("no file of GOOGLE_APPLICATION_CREDENTIALS: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	if err := googleCredentials(""); err == nil || !strings.Contains(err.Error(), "gcloud auth application-default login") {
		t.Errorf("no file of gcloud: %v", err)
	}
}
