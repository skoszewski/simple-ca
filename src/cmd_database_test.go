package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cert"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/database"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/oidc"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// dbHierarchy makes a root CA and its issuing CA servers with EC keys, and returns the root.
func dbHierarchy(t *testing.T) string {
	t.Helper()
	root := srvMakeCA(t, "")
	if err := cert.MakeCA(root, "Servers CA", 0, "servers", "", "ec"); err != nil {
		t.Fatal(err)
	}
	return root
}

// dbConfig writes simple-ca.json of root with the database section.
func dbConfig(t *testing.T, root, section string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, simpleca.ConfigFile), []byte(`{"database": `+section+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseRefusals(t *testing.T) {
	root := dbHierarchy(t)
	for _, c := range []struct {
		section string
		args    []string
		want    string
	}{
		{"", []string{"database", "setup"}, "names no table"},
		{"", []string{"database", "migrate", "tokens_db"}, "database.tokens_db"},
		{"", []string{"database", "migrate", "users"}, `unknown object "users"`},
		{`{"oidc_users": "oidc_users"}`, []string{"database", "migrate", "oidc_users"}, "does not exist"},
		{`{"tokens_db": "tokens"}`, []string{"database", "migrate", "tokens_db"}, "no tokens-db.json"},
	} {
		os.Remove(filepath.Join(root, simpleca.ConfigFile))
		if c.section != "" {
			dbConfig(t, root, c.section)
		}
		if err := run(append([]string{c.args[0], c.args[1], "--ca-dir", root}, c.args[2:]...)); err == nil ||
			!strings.Contains(err.Error(), c.want) {
			t.Errorf("%q with %s: %v, want %q", c.args, c.section, err, c.want)
		}
	}
	if err := run([]string{"database", "migrate", "--ca-dir", root}); err == nil {
		t.Error("database migrate without an object succeeded")
	}

	// A tokens-db.json beside a table is not read as an empty table.
	os.Remove(filepath.Join(root, simpleca.ConfigFile))
	servers := filepath.Join(root, "servers")
	if _, err := tokCapture(t, "token", "create", "--ca-dir", servers, "--scope", "certs", "keeper"); err != nil {
		t.Fatal(err)
	}
	dbConfig(t, root, `{"tokens_db": "tokens"}`)
	if _, err := tokCapture(t, "token", "list", "--ca-dir", servers); err == nil || !strings.Contains(err.Error(), "not migrated") {
		t.Errorf("token list beside a table: %v, want the file named as not migrated", err)
	}
}

// TestDatabaseMigrate runs against the PostgreSQL server of the SIMPLE_CA_DB_* variables when
// SIMPLE_CA_TEST_DB is 1, in a schema of its own that it drops.
func TestDatabaseMigrate(t *testing.T) {
	if os.Getenv("SIMPLE_CA_TEST_DB") != "1" {
		t.Skip("SIMPLE_CA_TEST_DB=1 and the SIMPLE_CA_DB_* variables run it against PostgreSQL")
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	rand.Read(b)
	schema := "simple_ca_test_" + hex.EncodeToString(b)
	t.Cleanup(func() { p.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE") })

	root := dbHierarchy(t)
	servers := filepath.Join(root, "servers")
	for _, dir := range []string{root, servers} {
		if _, err := tokCapture(t, "token", "create", "--ca-dir", dir, "--scope", "certs", "keeper"); err != nil {
			t.Fatal(err)
		}
	}
	users := `{"profiles": [{"name": "viewer", "token": {"scopes": ["certs"]}}], "rules": [{"users": ["alice"], "profile": "viewer"}]}`
	if err := os.WriteFile(filepath.Join(root, oidc.UsersFile), []byte(users), 0o600); err != nil {
		t.Fatal(err)
	}
	dbConfig(t, root, `{"schema": "`+schema+`", "tokens_db": "tokens", "oidc_users": "oidc_users"}`)
	for range 2 {
		if out, err := tokCapture(t, "database", "setup", "--ca-dir", root); err != nil || !strings.Contains(out, schema+`"."tokens"`) {
			t.Fatalf("database setup: %q, %v", out, err)
		}
	}

	out, err := tokCapture(t, "database", "migrate", "--ca-dir", root, "tokens_db")
	if err != nil || out != "/: 1 tokens\nservers: 1 tokens\n" {
		t.Fatalf("database migrate tokens_db: %q, %v", out, err)
	}
	for _, dir := range []string{root, servers} {
		if simpleca.FileExists(filepath.Join(dir, tokens.TokensFile)) || !simpleca.FileExists(filepath.Join(dir, tokens.TokensFile+".migrated")) {
			t.Errorf("tokens-db.json of %s is not renamed", dir)
		}
		if !tokens.Exists(dir) {
			t.Errorf("tokens.Exists(%s) is false after the migration", dir)
		}
	}

	// The tokens are read, made, revoked and locked through the table.
	if out, err := tokCapture(t, "token", "list", "--ca-dir", servers); err != nil || !strings.Contains(out, "keeper") {
		t.Errorf("token list of the table: %q, %v", out, err)
	}
	if _, err := tokCapture(t, "token", "create", "--ca-dir", servers, "--scope", "certs", "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := tokCapture(t, "token", "revoke", "--ca-dir", servers, "keeper"); err != nil {
		t.Fatal(err)
	}
	db, err := tokens.LoadTokens(servers)
	if err != nil || len(db.Tokens) != 2 || !db.Tokens["keeper"].Revoked() || db.Tokens["second"] == nil {
		t.Errorf("the tokens of servers in the table: %+v, %v", db, err)
	}
	unlock, err := tokens.LockTokens(servers)
	if err != nil {
		t.Fatal(err)
	}
	saved := simpleca.TokensLockWait
	simpleca.TokensLockWait = 0
	if _, err := tokCapture(t, "token", "create", "--ca-dir", servers, "--scope", "certs", "third"); err == nil ||
		!strings.Contains(err.Error(), "locked") {
		t.Errorf("token create while the tokens are locked: %v", err)
	}
	simpleca.TokensLockWait = saved
	unlock()

	// A second migration of a CA the table holds is refused, and moves nothing.
	os.Rename(filepath.Join(root, tokens.TokensFile+".migrated"), filepath.Join(root, tokens.TokensFile))
	if _, err := tokCapture(t, "database", "migrate", "--ca-dir", root, "tokens_db"); err == nil ||
		!strings.Contains(err.Error(), "already holds") || !simpleca.FileExists(filepath.Join(root, tokens.TokensFile)) {
		t.Errorf("a second database migrate tokens_db: %v, want it refused", err)
	}
	os.Remove(filepath.Join(root, tokens.TokensFile))

	if out, err := tokCapture(t, "database", "migrate", "--ca-dir", root, "oidc_users"); err != nil || out != "oidc-users.json: 1 profiles\n" {
		t.Fatalf("database migrate oidc_users: %q, %v", out, err)
	}
	var doc []byte
	if err := p.QueryRow(ctx, "SELECT document FROM "+pgx.Identifier{schema, "oidc_users"}.Sanitize()+" WHERE id = $1",
		database.OIDCUsersID).Scan(&doc); err != nil || !strings.Contains(string(doc), "viewer") {
		t.Errorf("the document of oidc_users: %s, %v", doc, err)
	}
	if !simpleca.FileExists(filepath.Join(root, oidc.UsersFile+".migrated")) {
		t.Error("oidc-users.json is not renamed")
	}
	if _, err := tokCapture(t, "database", "migrate", "--ca-dir", root, "oidc_users"); err == nil {
		t.Error("a second database migrate oidc_users succeeded")
	}
}
