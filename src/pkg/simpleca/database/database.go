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

// Package database connects simple-ca to the PostgreSQL database of the database section of
// simple-ca.json, with the settings of the SIMPLE_CA_DB_* variables, and creates its schema.
package database

import (
	"cmp"
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

// EnvPrefix starts the variables of the connection: SIMPLE_CA_DB_HOST is PGHOST of psql.
const EnvPrefix = "SIMPLE_CA_DB_"

// settings maps each variable of the connection, without EnvPrefix, to its connection string
// keyword: the PG* variables pgconn reads, without PG.
var settings = [][2]string{
	{"HOST", "host"}, {"PORT", "port"}, {"DATABASE", "dbname"}, {"USER", "user"}, {"PASSWORD", "password"},
	{"PASSFILE", "passfile"}, {"APPNAME", "application_name"}, {"CONNECT_TIMEOUT", "connect_timeout"},
	{"SSLMODE", "sslmode"}, {"SSLKEY", "sslkey"}, {"SSLCERT", "sslcert"}, {"SSLCERTMODE", "sslcertmode"},
	{"SSLSNI", "sslsni"}, {"SSLROOTCERT", "sslrootcert"}, {"SSLPASSWORD", "sslpassword"},
	{"SSLNEGOTIATION", "sslnegotiation"}, {"TARGETSESSIONATTRS", "target_session_attrs"}, {"SERVICE", "service"},
	{"SERVICEFILE", "servicefile"}, {"TZ", "timezone"}, {"OPTIONS", "options"},
	{"MINPROTOCOLVERSION", "min_protocol_version"}, {"MAXPROTOCOLVERSION", "max_protocol_version"},
	{"CHANNELBINDING", "channel_binding"}, {"REQUIREAUTH", "require_auth"},
}

// ConnString returns the keyword/value connection string of the SIMPLE_CA_DB_* variables getenv
// gives, each value quoted; without SIMPLE_CA_DB_PASSFILE it names no passfile, so that
// ~/.pgpass is not read.
func ConnString(getenv func(string) string) string {
	var parts []string
	for _, s := range settings {
		value := getenv(EnvPrefix + s[0])
		if value == "" && s[0] != "PASSFILE" {
			continue
		}
		parts = append(parts, s[1]+"='"+strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(value)+"'")
	}
	return strings.Join(parts, " ")
}

var (
	poolMu sync.Mutex
	pool   *pgxpool.Pool
)

// Pool returns the connection pool of the process, opened on first use with ConnString of the
// environment, after removing the PG* variables pgconn would read for the settings it leaves out.
func Pool(ctx context.Context) (*pgxpool.Pool, error) {
	poolMu.Lock()
	defer poolMu.Unlock()
	if pool != nil {
		return pool, nil
	}
	for _, s := range settings {
		os.Unsetenv("PG" + s[0])
	}
	cfg, err := pgxpool.ParseConfig(ConnString(os.Getenv))
	if err != nil {
		return nil, fmt.Errorf("the database settings of %s*: %w", EnvPrefix, err)
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the database: %w", err)
	}
	pool = p
	return pool, nil
}

// Table returns the quoted name of table in the schema of db, public when it names none.
func Table(db simpleca.DatabaseConfig, table string) string {
	return pgx.Identifier{cmp.Or(db.Schema, "public"), table}.Sanitize()
}

// LockKey returns the key of the advisory lock of the parts, such as a table and a CA.
func LockKey(parts ...string) int64 {
	h := fnv.New64a()
	h.Write([]byte(strings.Join(parts, "\x00")))
	return int64(h.Sum64())
}

// OIDCUsersID is the row of the table of oidc_users holding the document of oidc-users.json.
const OIDCUsersID = "oidc-users"

// Setup creates the schema of db, unless it is public, and the tables it names that do not exist,
// and returns the tables.
func Setup(ctx context.Context, db simpleca.DatabaseConfig) ([]string, error) {
	p, err := Pool(ctx)
	if err != nil {
		return nil, err
	}
	var statements, tables []string
	if s := cmp.Or(db.Schema, "public"); s != "public" {
		statements = append(statements, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{s}.Sanitize())
	}
	if db.TokensDB != "" {
		tables = append(tables, Table(db, db.TokensDB))
		statements = append(statements, "CREATE TABLE IF NOT EXISTS "+Table(db, db.TokensDB)+
			" (ca text NOT NULL, name text NOT NULL, token jsonb NOT NULL, PRIMARY KEY (ca, name))")
	}
	if db.OIDCUsers != "" {
		tables = append(tables, Table(db, db.OIDCUsers))
		statements = append(statements, "CREATE TABLE IF NOT EXISTS "+Table(db, db.OIDCUsers)+
			" (id text PRIMARY KEY, document jsonb NOT NULL)")
	}
	for _, s := range statements {
		if _, err := p.Exec(ctx, s); err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
	}
	return tables, nil
}
