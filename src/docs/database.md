---
title: Database
---

simple-ca keeps the tokens and the secrets of each CA and the OIDC profiles of the root CA in
PostgreSQL, in place of their JSON files, when the `database` section of `simple-ca.json` of the
root CA names a table for them:

- `tokens_db` - the tokens of `tokens-db.json` of the root CA and of each issuing CA;
- `secrets_db` - the [one-time secrets](secrets.md) of `secrets-db.json` of the root CA and of
  each issuing CA;
- `oidc_users` - the document of `oidc-users.json` of the root CA (see [OIDC sign-in](oidc.md)).

A table not named keeps its file. The commands and `serve` read and write the tables as they do
the files, so nothing else changes.

## Settings

```json
{
  "database": {
    "schema": "pki_lab",
    "tokens_db": "tokens",
    "secrets_db": "secrets",
    "oidc_users": "oidc_users"
  }
}
```

- `schema` - the schema of the tables, `public` without it. Several installations of simple-ca
  share one database, usually named `simple_ca`, each with a schema of its own. It is not taken
  without a table.
- `tokens_db` - the table of the tokens: a row of each token, with the ID of its CA, empty for the
  root CA, its name and the token as `jsonb`.
- `secrets_db` - the table of the secrets: a row of each secret, with the ID of its CA, empty for
  the root CA, its name and the secret, its value encrypted, as `jsonb`.
- `oidc_users` - the table of the OIDC profiles: one row, `oidc-users`, holding the document of
  `oidc-users.json` as `jsonb`.

Each name is made of lower-case letters, digits and `_`, starts with a letter or `_`, and has at
most 63 characters; a schema does not start with `pg_`, which PostgreSQL reserves.

## Connection

The connection is given by the `SIMPLE_CA_DB_*` variables, each standing for the variable of
`psql` of the same name with `PG` in place of `SIMPLE_CA_DB_`: `SIMPLE_CA_DB_HOST` is `PGHOST`,
`SIMPLE_CA_DB_DATABASE` is `PGDATABASE`, and so on.

```sh
export SIMPLE_CA_DB_HOST=db.example.com
export SIMPLE_CA_DB_DATABASE=simple_ca
export SIMPLE_CA_DB_USER=simple_ca
export SIMPLE_CA_DB_PASSFILE=/etc/simple-ca/pgpass
export SIMPLE_CA_DB_SSLMODE=verify-full
export SIMPLE_CA_DB_SSLROOTCERT=/etc/simple-ca/db-ca.pem
```

These are taken: `HOST`, `PORT`, `DATABASE`, `USER`, `PASSWORD`, `PASSFILE`, `APPNAME`,
`CONNECT_TIMEOUT`, `SSLMODE`, `SSLKEY`, `SSLCERT`, `SSLCERTMODE`, `SSLSNI`, `SSLROOTCERT`,
`SSLPASSWORD`, `SSLNEGOTIATION`, `TARGETSESSIONATTRS`, `SERVICE`, `SERVICEFILE`, `TZ`,
`OPTIONS`, `MINPROTOCOLVERSION`, `MAXPROTOCOLVERSION`, `CHANNELBINDING` and `REQUIREAUTH`, each
after `SIMPLE_CA_DB_`.

The `PG*` variables themselves are not read, nor `~/.pgpass`: a password file is read only when
`SIMPLE_CA_DB_PASSFILE` names one, and a service file only for `SIMPLE_CA_DB_SERVICE`. A setting
not given takes the default of `psql`, such as the port 5432 and the user of the operating system.
The default `sslmode` is `prefer`, which falls back to a connection without TLS; give
`verify-full` with the CA of the server for a database on another host.

## database setup

```sh
simple-ca database setup --ca-dir /etc/simple-ca
```

`database setup` creates the schema, unless it is `public`, and the tables the `database` section
names that do not exist, and prints them. It changes no table that exists, so it runs again after
a table is added. The user of the connection needs the right to create them; afterwards simple-ca
needs `SELECT`, `INSERT`, `DELETE` and `UPDATE` on them.

## database migrate

```sh
simple-ca database migrate --ca-dir /etc/simple-ca tokens_db
simple-ca database migrate --ca-dir /etc/simple-ca secrets_db
simple-ca database migrate --ca-dir /etc/simple-ca oidc_users
```

`database migrate` moves a file to its table, after `database setup`:

- `tokens_db` - the `tokens-db.json` of the root CA and of each issuing CA, under their locks, in
  one transaction, and prints the count of tokens of each CA, `/` for the root CA;
- `secrets_db` - the `secrets-db.json` of the root CA and of each issuing CA, in the same way,
  and prints the count of secrets of each CA;
- `oidc_users` - `oidc-users.json`, which must be valid as `serve` reads it, and prints the count
  of its profiles.

Each file moved is renamed to `tokens-db.json.migrated`, `secrets-db.json.migrated` or
`oidc-users.json.migrated`. A table that already holds the tokens or the secrets of one of the
CAs, or the document, is not changed and nothing is
moved. The migration is recorded in the [audit log](audit.md) as `database.migrate`, with the
`object` and the `count`.

Once a table is named, a file left beside it is not read as an empty table: a command or a request
on the tokens or the secrets of that CA fails, naming the file as not migrated, and the OIDC
sign-in reports it as an `oidc.users` error in the log and gives no profile.

## Changing the OIDC profiles

The document of the table is changed with `psql`, from a file of the form of `oidc-users.json`:

```sh
psql -h db.example.com -d simple_ca -U simple_ca -v doc="$(cat oidc-users.json)" <<'EOF'
UPDATE pki_lab.oidc_users SET document = :'doc'::jsonb WHERE id = 'oidc-users';
EOF
```

It applies at the next sign-in, as a change of the file does. A document `serve` cannot use is
reported as an `oidc.users` error in the log, and gives no profile.
