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

package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// UsersFile is the file of the root CA directory holding an oidcUsers.
const UsersFile = "oidc-users.json"

// oidcUsers are the token profiles of the OIDC sign-in and the rules giving them to users.
type oidcUsers struct {
	path     string
	Profiles []oidcProfile `json:"profiles"`
	Rules    []oidcRule    `json:"rules"`
}

// oidcProfile is a token profile: its name, its CA, empty for the root CA, and its token settings.
type oidcProfile struct {
	Name  string       `json:"name"`
	CA    string       `json:"ca"`
	Token profileToken `json:"token"`
}

// profileToken is the token of a profile: the settings of simpleca.TokensConfig, and localhost,
// which a profile gives its tokens itself, as token create --localhost does, and is never a
// default.
type profileToken struct {
	simpleca.TokensConfig
	Localhost bool `json:"localhost,omitempty"`
}

// oidcRule gives the profile Profile to the users of Users and to the members of Groups.
type oidcRule struct {
	Users   []string `json:"users,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Profile string   `json:"profile"`
}

// loadOIDCUsers reads and validates oidc-users.json of rootDir, empty when it does not exist.
func loadOIDCUsers(rootDir string) (*oidcUsers, error) {
	users := &oidcUsers{path: filepath.Join(rootDir, UsersFile)}
	b, err := os.ReadFile(users.path)
	if errors.Is(err, os.ErrNotExist) {
		return users, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(users); err != nil {
		return nil, fmt.Errorf("could not read %s: %w", users.path, err)
	}
	var names []string
	for i, p := range users.Profiles {
		switch {
		case !simpleca.KebabCaseRE.MatchString(p.Name):
			return nil, fmt.Errorf("profiles[%d] of %s: name '%s' is not a kebab-case name, such as ca-admin", i, users.path, p.Name)
		case slices.Contains(names, p.Name):
			return nil, fmt.Errorf("profiles[%d] of %s: the profile '%s' is given twice", i, users.path, p.Name)
		case p.Token.KeepExpired != "":
			return nil, fmt.Errorf("profile %s of %s: keep_expired belongs to the tokens section of simple-ca.json", p.Name, users.path)
		}
		names = append(names, p.Name)
	}
	for i, r := range users.Rules {
		switch {
		case len(r.Users) == 0 && len(r.Groups) == 0:
			return nil, fmt.Errorf("rules[%d] of %s: a rule needs users or groups", i, users.path)
		case !slices.Contains(names, r.Profile):
			return nil, fmt.Errorf("rules[%d] of %s: unknown profile '%s'", i, users.path, r.Profile)
		}
	}
	return users, nil
}
