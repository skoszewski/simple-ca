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
	"cmp"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/client"
)

// accessToken is the bearer token of the calls to Google, and quotaProject the project of
// their quota, sent as x-goog-user-project when it is set.
var accessToken, quotaProject string

// oauthTokenURL is the token endpoint of Google's authorization server.
var oauthTokenURL = "https://oauth2.googleapis.com/token"

// adcFile is the file name of Application Default Credentials in the gcloud configuration.
const adcFile = "application_default_credentials.json"

// googleCredentials sets accessToken to given, else to GOOGLE_OAUTH_ACCESS_TOKEN, else to the
// access token of the scope cloud-platform granted for the Application Default Credentials
// file: that of GOOGLE_APPLICATION_CREDENTIALS, else that of gcloud auth application-default
// login. The file of the type authorized_user gets it by its refresh token, and that of the
// type service_account by a JWT signed with its key; any other type is refused.
func googleCredentials(given string) error {
	if accessToken = cmp.Or(given, os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")); accessToken != "" {
		return nil
	}
	path := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	switch {
	case path != "":
	case runtime.GOOS == "windows":
		path = filepath.Join(os.Getenv("APPDATA"), "gcloud", adcFile)
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		path = filepath.Join(home, ".config", "gcloud", adcFile)
	}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "":
		return fmt.Errorf("the file %s of GOOGLE_APPLICATION_CREDENTIALS does not exist", path)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("no Google credentials: give --access-token or GOOGLE_OAUTH_ACCESS_TOKEN, or write %s "+
			"with gcloud auth application-default login", path)
	}
	if err != nil {
		return err
	}
	var cred struct {
		Type           string `json:"type"`
		ClientID       string `json:"client_id"`
		ClientSecret   string `json:"client_secret"`
		RefreshToken   string `json:"refresh_token"`
		ClientEmail    string `json:"client_email"`
		PrivateKey     string `json:"private_key"`
		PrivateKeyID   string `json:"private_key_id"`
		TokenURI       string `json:"token_uri"`
		QuotaProjectID string `json:"quota_project_id"`
	}
	if err := json.Unmarshal(b, &cred); err != nil {
		return fmt.Errorf("could not read %s: %w", path, err)
	}
	quotaProject = cred.QuotaProjectID

	target := oauthTokenURL
	var form url.Values
	switch cred.Type {
	case "authorized_user":
		form = url.Values{"grant_type": {"refresh_token"}, "client_id": {cred.ClientID},
			"client_secret": {cred.ClientSecret}, "refresh_token": {cred.RefreshToken}}
	case "service_account":
		target = cmp.Or(cred.TokenURI, oauthTokenURL)
		block, _ := pem.Decode([]byte(cred.PrivateKey))
		if block == nil {
			return fmt.Errorf("%s: no PEM block in private_key", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("%s: private_key: %w", path, err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%s: private_key is not an RSA key", path)
		}
		header, err := json.Marshal(struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
			Kid string `json:"kid,omitempty"`
		}{"RS256", "JWT", cred.PrivateKeyID})
		if err != nil {
			return err
		}
		now := time.Now().Unix()
		claims, err := json.Marshal(map[string]any{"iss": cred.ClientEmail, "scope": client.DefaultGoogleScope,
			"aud": target, "iat": now, "exp": now + 3600})
		if err != nil {
			return err
		}
		signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(signed))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			return err
		}
		form = url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion": {signed + "." + base64.RawURLEncoding.EncodeToString(sig)}}
	default:
		return fmt.Errorf("%s: the credential type '%s' is not supported: it must be authorized_user or "+
			"service_account, else give --access-token", path, cred.Type)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := client.Post(target, "application/x-www-form-urlencoded", "", []byte(form.Encode()), &result); err != nil {
		return err
	}
	if result.AccessToken == "" {
		return fmt.Errorf("%s: the answer holds no access_token", target)
	}
	accessToken = result.AccessToken
	return nil
}
