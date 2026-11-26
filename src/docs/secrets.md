---
title: One-time secrets
---

A secret of a CA is a value, such as a password, a key or a connection string, that `serve` shows
once to whoever has its one-time code. The holder of a token with the scope `secrets` creates it,
on the secret page, at its API or with `secret create`, and gets the code, which they hand to the
recipient over any channel. The recipient enters the code on the page "Get a secret", or sends it
to `/api/secret-get`, and sees the value once; the secret is removed then, and the code no longer
works. A secret whose code is not used expires with it.

The code has the form of a [setup code](signing-api.md#one-time-setup-codes),
`K7QF-M2XA-JP4D-W5ZR`, 80 random bits, taken in any letter case, with or without the dashes. The
server keeps only the SHA-256 of the code and the value encrypted with AES-256-GCM, under a key
derived from the code with HKDF-SHA-256 and a random salt of the secret, bound to the name and
the CA of the secret. Neither `secrets-db.json` nor the table of `database.secrets_db` discloses a
value without its code.

Each CA, the root CA and each issuing CA, keeps its own secrets, in `secrets-db.json` of its
directory, mode `0600`, or in the table [`database.secrets_db`](database.md) names. A token of
the root CA manages the secrets of every CA, a token of an issuing CA those of its own CA. The
scope `secrets` is a scope of [token create](signing-api.md#token-create-list-renew-revoke-and-purge)
and of the token page, and `*` stands for it.

A value is from 1 byte to 16 KiB, and the code is valid from 1 second to 30 days, 1 day by
default. A secret may be limited to the client addresses its code is used from, as a setup code
is with `--otc-network`. A name is a kebab-case name, such as `db-password`, unique in its CA
while its code is valid.

## secret create, list and revoke

```sh
simple-ca secret create [--ca-dir DIR] [--valid 1d] [--network PREFIXES]... [--file FILE] NAME
simple-ca secret list [--ca-dir DIR]
simple-ca secret revoke [--ca-dir DIR] NAME
```

`secret create` reads the value from `--file`, or from the standard input, as it is, with a last
line end if it has one, and prints the code. `--valid` is the validity of the code, minutes, or a
number with `h` or `d`, such as `30`, `8h` or `7d`. `--network` is a comma-separated list of
client prefixes the code is used from, and may be given several times; without it, any client.

```sh
printf '%s' 'hunter2' | simple-ca secret create --ca-dir ca/servers --valid 8h db-password
simple-ca secret create --ca-dir ca --file deploy-key.pem --network 192.168.1.0/24 deploy-key
```

`secret list` prints the secrets whose codes are not used and not expired: their name, creation,
expiry, the clients of the code, and the creator, without the values. `secret revoke` removes a
secret, and its code stops working at once.

## Secret page

With `--webui`, `serve` serves a web page at `/secrets/` for the secrets of the root CA and all its
issuing CAs; the index page links to it as "Secrets" once a valid token is signed in. It asks for
a token with the scope `secrets`, and signs in as the [token page](signing-api.md#token-page)
does. It shows one CA at a time, chosen in the CA selector, and on it you can:

- list the secrets whose codes are not used, with their name, creation, the expiry of the code,
  the clients it is used from, and the token that created them, and find them with the search;
- revoke a secret, confirming first;
- create a secret: its name, the validity of its code, 1 day at first, the value, and the
  clients the code is used from. The code is shown once, with a Copy button.

### API

Behind the page, with the token as its bearer token, below `/secrets/api/`:

| Request | Body | Answer |
|---|---|---|
| `GET /secrets/api/cas` | | the CAs, as `GET /tokens/api/cas` answers, with `defaults`, `valid`, the default validity of a code |
| `GET /secrets/api/secrets?ca=CA` | | `secrets`, each with `name`, `created`, `expires`, `clients`, as prefixes, empty for any, and `creator`, the name of the token that created it |
| `POST /secrets/api/secrets` | `ca`, `name`, `value`, `valid`, `networks` | `201 Created`, `name` and `code` |
| `POST /secrets/api/secrets/revoke` | `ca`, `name` | `name`, or `404 Not Found` for a secret that is not there |

`CA` is the name of an issuing CA, or empty for the root CA. An error is `{"error": "..."}`, as on
the token page. The API takes no defaults: a create gives `valid`.

```sh
curl -sS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"ca": "servers", "name": "db-password", "value": "hunter2", "valid": "8h", "networks": []}' \
  https://pki.example.com:8443/secrets/api/secrets
```

## Get a secret

`serve` shows a secret of the root CA or of any of its issuing CAs to the holder of its code at
`/api/secret-get`, with `--webui` or without it. A request is a `POST` with a JSON body of at most
1 KiB, and needs no token:

```json
{
  "code": "K7QF-M2XA-JP4D-W5ZR"
}
```

The answer is `{"ca": "servers", "name": "db-password", "secret": "hunter2"}`: the issuing CA of
the secret, empty for the root CA, its name and its value. A value that is not UTF-8 text is sent
in base64, with `"encoding": "base64"`. An error is `{"error": "..."}` with the status
`400 Bad Request` for a body that is not a JSON object with the code, `401 Unauthorized` for an
unknown, used or expired code, `403 Forbidden` for a client outside the networks of the secret,
`413 Request Entity Too Large` for a body larger than 1 KiB, `415 Unsupported Media Type` for a
body that is not `application/json`, and `429 Too Many Requests` for a client held back after
refused codes, which count as [refused credentials](signing-api.md#refused-credentials).

```sh
SERVER=http://pki.example.com:8080
CODE=K7QF-M2XA-JP4D-W5ZR
jq -n --arg code "$CODE" '{code: $code}' | curl -sS \
  -H 'Content-Type: application/json' --data @- "$SERVER/api/secret-get" | jq -r .secret
```

The page `/secret-get`, "Get a secret" on the index page and beside "Set up a token" on the token,
certificate, audit and secret pages, does the same in a browser: it asks for the code and shows
the value once, with a Copy button, or the error. Cancel, and Close once the value is shown,
return to the page of `serve` it was opened from, or to the index page; so does Escape.

## Audit

The [audit log](audit.md) records `secret.create`, `secret.get` and `secret.revoke`, with the name
of the secret and who acted, never the value or the code.
