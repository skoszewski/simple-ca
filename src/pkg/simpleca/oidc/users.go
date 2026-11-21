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
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
)

// UsersFile is the file of the root CA directory holding an oidcUsers.
const UsersFile = "oidc-users.json"

// oidcUsers are the profiles of the OIDC sign-in, the rules giving them to users, and the rule
// of the extended key usages of the types of their certificates, defaultUserEKUs without it.
type oidcUsers struct {
	path     string
	UserEKUs *ekuRule      `json:"user_ekus"`
	Profiles []oidcProfile `json:"profiles"`
	Rules    []oidcRule    `json:"rules"`
}

// userEKUs returns the rule of the extended key usages of the types of the certificates.
func (u *oidcUsers) userEKUs() *ekuRule {
	if u.UserEKUs == nil {
		return &defaultUserEKUs
	}
	return u.UserEKUs
}

// ekuRule is a node of user_ekus, a rule on the extended key usages of a certificate type, with
// exactly one key:
//
//   - require: every extended key usage of the list is one of the type;
//   - allow: every extended key usage of the type is one of the list;
//   - and: every node of the list holds;
//   - or: a node of the list holds;
//   - not: the node does not hold.
//
// An extended key usage is a name or a numeric OID, as cert.ParseUsages takes it, compared by its
// OID.
type ekuRule struct {
	Require []string  `json:"require"`
	Allow   []string  `json:"allow"`
	And     []ekuRule `json:"and"`
	Or      []ekuRule `json:"or"`
	Not     *ekuRule  `json:"not"`
}

// ekuRuleDepth is the deepest nesting of the nodes of user_ekus.
const ekuRuleDepth = 8

// defaultUserEKUs is the rule of user_ekus when oidc-users.json has none.
var defaultUserEKUs = ekuRule{Allow: []string{"clientAuth", "emailProtection", "codeSigning"}}

// check reports an error of the rule, a node at the nesting level depth: a node without exactly
// one key, an empty list, an extended key usage that does not parse, or a nesting deeper than
// ekuRuleDepth.
func (r *ekuRule) check(depth int) error {
	if depth > ekuRuleDepth {
		return fmt.Errorf("the rule is nested deeper than %d levels", ekuRuleDepth)
	}
	keys := 0
	for _, given := range []bool{r.Require != nil, r.Allow != nil, r.And != nil, r.Or != nil, r.Not != nil} {
		if given {
			keys++
		}
	}
	if keys != 1 {
		return errors.New("a node has exactly one key of require, allow, and, or and not")
	}
	switch {
	case r.Require != nil || r.Allow != nil:
		list := r.Require
		if list == nil {
			list = r.Allow
		}
		if len(list) == 0 {
			return errors.New("require and allow need an extended key usage")
		}
		_, err := cert.EKUOIDs(list)
		return err
	case r.Not != nil:
		return r.Not.check(depth + 1)
	}
	nodes := r.And
	if nodes == nil {
		nodes = r.Or
	}
	if len(nodes) == 0 {
		return errors.New("and and or need a node")
	}
	for i := range nodes {
		if err := nodes[i].check(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

// matches reports whether the rule, checked, holds for the extended key usages of a type, the
// OIDs cert.EKUOIDs gives.
func (r *ekuRule) matches(oids []string) bool {
	switch {
	case r.Require != nil:
		list, _ := cert.EKUOIDs(r.Require)
		return !slices.ContainsFunc(list, func(oid string) bool { return !slices.Contains(oids, oid) })
	case r.Allow != nil:
		list, _ := cert.EKUOIDs(r.Allow)
		return !slices.ContainsFunc(oids, func(oid string) bool { return !slices.Contains(list, oid) })
	case r.And != nil:
		return !slices.ContainsFunc(r.And, func(n ekuRule) bool { return !n.matches(oids) })
	case r.Or != nil:
		return slices.ContainsFunc(r.Or, func(n ekuRule) bool { return n.matches(oids) })
	case r.Not != nil:
		return !r.Not.matches(oids)
	}
	return false
}

// oidcProfile is a profile of users: its name, the CA of its token, empty for the root CA, the
// settings of its token and of its certificate. A profile gives a certificate when its
// Certificate names a CA, and a token when it has Token or gives no certificate.
type oidcProfile struct {
	Name        string              `json:"name"`
	CA          string              `json:"ca"`
	Token       *profileToken       `json:"token"`
	Certificate *profileCertificate `json:"certificate"`
}

// givesCertificate reports whether the profile gives its users a certificate.
func (p *oidcProfile) givesCertificate() bool { return p.Certificate != nil && p.Certificate.CA != nil }

// givesToken reports whether the profile gives its users a token.
func (p *oidcProfile) givesToken() bool { return p.Token != nil || !p.givesCertificate() }

// profileCertificate is the user certificate of a profile: the CA that signs it, empty for the
// root CA and none for no certificate, the certificate types it offers, each of the user name
// rules with extended key usages that meet user_ekus, its validity in days, days.cert of
// simple-ca.json without it, and the domains of its email address, any without them.
type profileCertificate struct {
	CA           *string  `json:"ca"`
	Types        []string `json:"types"`
	Days         int      `json:"days,omitempty"`
	EmailDomains []string `json:"email_domains,omitempty"`
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
		return nil, fmt.Errorf("could not read %q: %w", users.path, err)
	}
	if users.UserEKUs != nil {
		if err := users.UserEKUs.check(1); err != nil {
			return nil, fmt.Errorf("user_ekus of %q: %w", users.path, err)
		}
	}
	var names []string
	for i, p := range users.Profiles {
		switch {
		case !simpleca.KebabCaseRE.MatchString(p.Name):
			return nil, fmt.Errorf("profiles[%d] of %q: name %q is not a kebab-case name, such as ca-admin", i, users.path, p.Name)
		case slices.Contains(names, p.Name):
			return nil, fmt.Errorf("profiles[%d] of %q: the profile %q is given twice", i, users.path, p.Name)
		case p.Token != nil && p.Token.KeepExpired != "":
			return nil, fmt.Errorf("profile %s of %q: keep_expired belongs to the tokens section of simple-ca.json", p.Name, users.path)
		}
		names = append(names, p.Name)
	}
	for i, r := range users.Rules {
		switch {
		case len(r.Users) == 0 && len(r.Groups) == 0:
			return nil, fmt.Errorf("rules[%d] of %q: a rule needs users or groups", i, users.path)
		case !slices.Contains(names, r.Profile):
			return nil, fmt.Errorf("rules[%d] of %q: unknown profile %q", i, users.path, r.Profile)
		}
	}
	return users, nil
}
