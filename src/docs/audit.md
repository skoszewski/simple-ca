---
title: Audit log
---

simple-ca records what changes a CA and who changed it in an audit log:

- every certificate issued or revoked, and every PFX bundle exported;
- every CRL written and CA created;
- every token created, renewed, revoked, removed or handed out, and every JWT of a token type
  issued;
- every credential `serve` refuses.

The commands and `serve` write it alike, and `serve` also copies each record to the systemd
journal or to its standard error.

## Records

Each record is one line of `key=value` pairs, written by Go's `log/slog`. The first field is the
time in UTC, with milliseconds, and the second the event:

```text
time=2026-11-03T20:39:18.913Z event=cert.issue ca=servers serial=39329B6FCA771219B381F5D53BF8DADC8B86D688 subject="/CN=api.example.org" type=server setup_code=false via=api actor=audit-tok client=127.0.0.1
```

A value with a space, a `"` or a `=` is quoted as a Go string, and an empty value is `""`.

The records have these keys:

- `ca` - the issuing CA, `""` for the root CA, in every record;
- `via` - how the change was made: `cli`, `api` (the signing API), `form` (the signing form),
  `webui` (the token and certificate pages), `acme`, `oidc`, `setup` (a setup code exchanged),
  or `serve` (its own removal of expired tokens);
- `actor` - who made it: the user of the operating system for `cli`, the token for `api`,
  `form` and `webui`, the account for `acme`, the user for `oidc`, and the token set up for
  `setup`; `serve` writes none for its own removal of expired tokens;
- `client` - the address of the client, after the trusted proxies, in the records of a request to
  `serve`; the commands and the removal of expired tokens by `serve` write none.

The `auth` events have no `via` or `actor`, only the `client`. A token made by the OIDC sign-in
also gives `oidc_user` on the token and certificate pages, in the signing API and in the signing
form. A record never holds a token, a setup code, an ID token, a key or a password.

| Event | Keys |
|---|---|
| `ca.create` | `subject`, `days`, `key_type`, `rsa` or `ec` |
| `cert.issue` | `serial`, `subject`, `type`; `setup_code` for the signing API and form |
| `cert.revoke` | `serial`, `reason` |
| `cert.pfx` | `file`, the certificate the bundle was made of; also when the certificate page makes a file to download |
| `crl.write` | `number` |
| `key.encrypt` | `files`, the comma-separated names of the keys of the CA that `key encrypt` encrypted |
| `key.decrypt` | `files`, the comma-separated names of the keys of the CA that `key decrypt` decrypted |
| `token.create` | `name`, `scopes`, `setup_code`; `federate` and `audience`, empty for that of the type, for a token with the scope `federate` |
| `token.renew` | `name`, `setup_code` |
| `token.issue` | `name`, the token of `/api/federation-token`, or the name of `token issue`, `token_type`, `audience`, `subject`, `jti`: a JWT of a token type, which is not stored; its claims are not written |
| `token.revoke` | `name` |
| `token.purge` | `name`, or `count` for a removal of all expired and revoked tokens |
| `token.setup` | `name`, the token a setup code was exchanged for |
| `token.oidc` | `name`, `user`, `issuer`, `profile`, `action`: `made`, `replaced` or `reused` |
| `auth.refused` | `route`, `reason`: a token, setup code or ID token refused with `401`, or a request without one |
| `auth.held` | `wait`: the client is held back, see [Refused credentials](signing-api.md#refused-credentials) |

A record is written once the change is made. A refused request writes no record, unless it is an
`auth` event.

## The file

The audit log is `audit.log` in the root CA directory, for the root CA and all its issuing CAs.
`audit.file` of [simple-ca.json](configuration.md) moves it, as an absolute path or one relative
to the root CA directory:

```json
{
  "audit": {
    "file": "/var/log/simple-ca/audit.log"
  }
}
```

The file is made with the private mode of [File modes and a shared CA](usage.md#file-modes-and-a-shared-ca),
by default 0600, readable by its owner alone. Each record is appended with one
write, so the commands and `serve` write it together without a lock. The file is opened for each
record, so `logrotate` can rename it, and the next record starts a new file:

```text
/etc/simple-ca/audit.log {
    monthly
    rotate 24
    compress
    missingok
    notifempty
}
```

A record that cannot be written, such as on a full disk, is reported on the standard error, and
the change is made all the same.

## The journal and containers

`serve` also writes each record to its [log](serve.md), in the same format as its other records,
on the standard error, where a container runtime collects it: `docker logs` and `kubectl logs`
show it.

Under systemd, `serve` sends each record of its log to the systemd journal instead, by the
journal's native protocol, with the priority `err` for errors, `warning` for warnings and `info`
for the others. The journal entry holds the line in `MESSAGE`, `SYSLOG_IDENTIFIER=simple-ca`,
and each key after `time` as a field named `SIMPLE_CA_` and the key in upper case, other
characters than letters and digits turned into `_`, so the journal can be searched by them:

```sh
journalctl -u simple-ca SIMPLE_CA_EVENT=cert.issue SIMPLE_CA_CA=servers
journalctl -u simple-ca SIMPLE_CA_ACTOR=deploy -o verbose
```

`serve` uses the journal when the standard error systemd gave it is the journal's, as
`$JOURNAL_STREAM` tells, and the standard error otherwise. Without the journal, the record goes
to the standard error.

The journal exists on Linux alone. On macOS and Windows, and in containers, `serve` writes the
standard error. The commands write the file alone on every platform, so their records do not
mix with their output.

## audit list

`audit list` prints the records of the audit log of the root CA of `--ca-dir`, as they are
written, those of its filters alone:

```sh
simple-ca audit list --ca-dir /etc/simple-ca --event token. --since 2026-11-01
simple-ca audit list --ca-dir /etc/simple-ca --ca servers --actor deploy
simple-ca audit list --ca-dir /etc/simple-ca --ca ""
```

- `--event` - an event, such as `cert.issue`, or the start of events ending in a dot, such as
  `token.`;
- `--ca` - an issuing CA, or `""` for the root CA;
- `--actor` - an actor;
- `--since` and `--until` - the records from a time on, and before a time, in RFC 3339 or as a
  date, such as `2026-11-03`.

## The audit page

With `--webui`, `serve` serves the audit page at `/audit/`, which a token with the scope `audit`
opens; the index page and the token and certificate pages link to it. The page shows the audit
log of the server, the root CA and all its issuing CAs together: the newest 1000 records, with the
time, the event, the CA, the actor, the way and the client. The Columns picker also offers a
column for each other key of the records shown, headed by the words of the key, such as Setup Code
for `setup_code`, and hides and shows any column; the columns shown are kept in the address as
`?columns=`, their keys separated by commas, while they differ from the six of the start, so a
reload or a link keeps them. An issuing CA token sees the records of its own CA alone. A search and
the filters of the event, the CA and the way pick the records, as on the token page. A refused
signing request
is a record of the CA in its URL; the `auth` events of the token, certificate and audit pages, of
the setup code exchange and of the OIDC sign-in are records of the root CA, as a refused credential
names no CA.

`GET /audit/api/entries?limit=N` answers with `{"entries": [...], "total": N}`: in `entries`, the
newest records first, 1000 without `limit`, each with `time`, `event`, `ca`, `fields`, its key and
value pairs in their order, and `line`; in `total`, the count of all the records the token sees. A
`limit` that is not a positive number is `400 Bad Request`.

## Reading the records

The records read as logfmt, with a quoted value read as a Go string. In Python:

```python
import shlex

def record(line):
    return dict(field.split("=", 1) for field in shlex.split(line))
```

`shlex` reads the quotes as a shell does, which is the same for values without a `\` escape.
