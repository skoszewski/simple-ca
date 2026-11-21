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
	"context"
	"fmt"
	"slices"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/cli"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/database"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/oidc"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// ---- database commands ------------------------------------------------------

// databaseObjects are the objects database migrate moves, by their keys of the database section.
var databaseObjects = []string{"tokens_db", "oidc_users"}

// databaseConfig returns the root CA directory of --ca-dir and its simple-ca.json.
func databaseConfig(caDir string) (string, *simpleca.Config, error) {
	rootDir, _, err := simpleca.LocateCA(cli.ResolveCADir(caDir))
	if err != nil {
		return "", nil, err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	return rootDir, cfg, err
}

// runDatabaseSetup runs database setup.
func runDatabaseSetup(args []string) error {
	fs := cli.NewFlagSet("database setup", "",
		"Creates the schema of the database section of simple-ca.json of the root CA of --ca-dir, and\n"+
			"the tables it names that do not exist, in the database of the SIMPLE_CA_DB_* variables.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	if _, _, err := cli.ParseArgs(fs, args, 0, 0); err != nil {
		return err
	}
	_, cfg, err := databaseConfig(*caDir)
	if err != nil {
		return err
	}
	if cfg.Database.TokensDB == "" && cfg.Database.OIDCUsers == "" {
		return fmt.Errorf("the database section of %q names no table", cfg.Path)
	}
	tables, err := database.Setup(context.Background(), cfg.Database)
	if err != nil {
		return err
	}
	for _, t := range tables {
		fmt.Println(t)
	}
	return nil
}

// runDatabaseMigrate runs database migrate.
func runDatabaseMigrate(args []string) error {
	fs := cli.NewFlagSet("database migrate", "tokens_db|oidc_users",
		"Moves tokens-db.json of the root CA of --ca-dir and its issuing CAs (tokens_db), or its\n"+
			"oidc-users.json (oidc_users), to the table the database section of simple-ca.json names,\n"+
			"and renames each file moved to NAME.migrated.")
	caDir := fs.String("ca-dir", "", "CA `directory`, root or issuing CA")
	rest, _, err := cli.ParseArgs(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if !slices.Contains(databaseObjects, rest[0]) {
		return fmt.Errorf("unknown object %q; give tokens_db or oidc_users", rest[0])
	}
	rootDir, cfg, err := databaseConfig(*caDir)
	if err != nil {
		return err
	}
	count := 0
	if rest[0] == "oidc_users" {
		if count, err = oidc.MigrateUsers(rootDir, cfg); err != nil {
			return err
		}
		fmt.Printf("%s: %d profiles\n", oidc.UsersFile, count)
	} else {
		counts, err := tokens.Migrate(rootDir, cfg)
		if err != nil {
			return err
		}
		for _, m := range counts {
			fmt.Printf("%s: %d tokens\n", cmp.Or(m.CA, simpleca.AuditRootCA), m.Count)
			count += m.Count
		}
	}
	simpleca.Audit(rootDir, "database.migrate", "object", rest[0], "count", count, "via", "cli", "actor", simpleca.CLIActor())
	return nil
}
