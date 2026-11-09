---
title: Signing API
---

`serve` signs certificate signing requests sent by programs to `/api/sign`, and pasted by people
on the `/sign` page, for the tokens that `token create` makes. `serve` shows the clients how to
request a certificate at `/help/`.

## token create, list, renew, revoke and purge

`token create` creates the token `NAME` for the CA in the CA directory (root or issuing CA),
records it in that directory's `tokens-db.json` and prints it. The token is a JWT signed with the
CA key, RS256 for an RSA key and ES256 for an EC key (`ca create --key-type`), its header naming
the key by its `kid`, and is valid only for that CA. It is shown
only once, so copy it then.

`--scope` sets what the token opens; it may be specified multiple times, and defaults to `sign`:

| Scope | Opens |
|---|---|
| `sign` | the [signing API](#requests-and-responses) and the [signing form](#signing-form) |
| `tokens` | the [token page](#token-page) of `serve --webui` |
| `certs` | the [certificate page](usage.md#certificate-page) of `serve --webui` |
| `audit` | the [audit page](audit.md#the-audit-page) of `serve --webui` |
| `federate` | [`/api/federation-token`](#federation-tokens), the JWTs of a token type for workload identity federation |
| `*` | all of them, given alone |

A root CA token opens the pages for every CA; an issuing CA token opens only its own CA.

With the scope `sign`, these options set what the token may sign; each may be specified multiple
times:

- `--cert-type` - the certificate types, or `*`, given alone, for every type of
  `simple-ca.json`, also one added later; `server` by default; `--type` is its former name, still
  accepted;
- `--domain` - the domains, with their subdomains; `--domain '*'` allows any name, for a lab;
- `--ip` - the IP addresses: an address such as `192.0.2.10`, a prefix such as `10.0.0.0/8` or
  `2001:db8::/32`, or `*` for any address;
- `--localhost` - allows the name `localhost` and the IP address `127.0.0.1`, the same as
  `--domain localhost --ip 127.0.0.1`.

A `sign` token needs at least one `--domain`, `--ip` or `--localhost`. Without `sign`, these
options are refused.

`--host ADDRESS` and `--network PREFIXES` (a comma-separated list such as
`192.168.1.0/24,10.0.0.0/8`) limit the clients the token is accepted from; both may be specified
multiple times. A request from any other address gets `403 Forbidden`. Without them, any client
may use the token. Behind a trusted proxy, the client is the address in the `X-Forwarded-For`
header; see [serve](serve.md).

`--valid` is how long the token is valid, such as `30m`, `8h` or `720h`: one hour by default, and
at least one second. `NAME` is **kebab-case**: lower-case letters and digits joined by hyphens,
such as `web-deploy`. A name is used by one token of a CA at a time.

Options not given default to the `tokens` section of [simple-ca.json](configuration.md). For
example, with `"tokens": {"domains": ["*"], "networks": ["192.168.1.0/24"]}`, `token create NAME`
makes a lab token for any name, used from 192.168.1.0/24, and `--domain example.com` limits one
token to `example.com`. `--host` and `--network` together replace both `hosts` and `networks`.
The defaults of `--cert-type`, `--domain` and `--ip` apply only to tokens with the scope `sign`.
`--localhost` has no default: it is given for each token that allows it.

With the scope `federate`, these options set the JWTs the token gets at
[`/api/federation-token`](#federation-tokens), for workload identity federation:

- `--federate-type` - the token type of the JWTs, `google`, `azure` or a type of
  `federation.types` in `simple-ca.json`;
- `--audience` - their audience, in place of that of the type;
- `--claim NAME=VALUE` - a claim they carry, over those of the type; may be specified multiple
  times.

Without `federate`, these options are refused. A token with `federate`, or `*`, and no token type
gets no JWTs, and grants the scope `federate` on the [token page](#token-page). See
[Workload identity federation](workload-identity.md). `token issue` prints one such JWT on the CA
host, without a token.

### One-time setup codes

With `--otc`, `token create` prints a one-time setup code, such as `K7QF-M2XA-JP4D-W5ZR`, instead
of the token, so the token itself is not handed over. The token waits for the code, pending: it
has no JWT yet. The holder of the code exchanges it once for the token, with
[`/api/token-setup`](#setup-code-exchange) or the page `/token-setup`, or signs in with it on the
[token page](#token-page), the certificate page or the audit page, which show the token once. The
token is valid
for `--valid` from the exchange on. On the [signing form](#signing-form), the code signs one
certificate instead, and its token is revoked once it is issued, without ever leaving `serve`.

- `--otc-valid` is how long the code can be exchanged, 15 minutes by default;
- `--otc-network PREFIXES`, a comma-separated list that may be specified multiple times, limits
  the clients the code is exchanged from; without it, any client may exchange it.

Only the SHA-256 of the code is kept in `tokens-db.json`. The code is read in any letter case,
with or without its dashes. A code that has expired is not exchanged; its token stays, expired,
until it is purged.

```sh
simple-ca token create --ca-dir /tmp/ca/servers --otc --otc-network 192.168.1.0/24 \
  --valid 720h --domain example.com builder
```

`token list` lists the tokens of the CA: name, expiry (marked `(expired)`, `revoked`,
`setup until TIME` or `setup expired`), scopes, cert types, domains, IP prefixes, clients, the
token type of its JWTs with the scope `federate`, the number of certificates issued with the
scope `sign`, and the OIDC user it was made for. `-` marks what a token without `sign` or
`federate` does not have, and a token not made by the [OIDC sign-in](oidc.md).

`token describe NAME` prints the attributes of the token `NAME` of the CA, one per line: its
status (valid until, expired, revoked, or waiting for its setup code), when it was issued, its
scopes, for a token of the OIDC sign-in its OIDC user and issuer, with `sign` its cert types,
domains and IP addresses, with `federate` the token type, audience and claims of its JWTs, the
clients it is used from, for a setup
code the clients the code is usable from and the validity of the token after the exchange, and
with `sign` the serial numbers of the certificates issued with it.

`token describe --token-file FILE`, or `--stdin` for a token on the standard input, describes a
token itself, as its holder has it. Its JWT holds only its name, its scopes and its times, which
are shown, with a note that the signature is not checked. With `--ca-dir` as well, the signature
is checked against that CA, and the rest is read from its `tokens-db.json`; a token renewed,
revoked or removed there is shown as refused.

```sh
simple-ca token describe --ca-dir /etc/simple-ca/servers deploy
simple-ca token describe --stdin < deploy.token
simple-ca token describe --ca-dir /etc/simple-ca/servers --token-file deploy.token
```

```text
Name:          deploy
Status:        valid until 2026-11-03 09:07:28 UTC
Issued:        2026-11-03 08:07:28 UTC
Scopes:        sign
Cert types:    server
Domains:       example.com
IP addresses:  -
Used from:     192.168.1.0/24
Certificates:  0
```

`token revoke` revokes the token `NAME`: its JWT, or its setup code, stops working at once, for
the API and the web UIs. The token stays in `tokens-db.json`, without a JWT ID, so it can be
renewed. An entry without `scopes` has the scope `sign`.

`token renew` renews the token `NAME`, whether revoked, expired or still valid, and prints it; a
token waiting for a setup code that has not expired is refused, and is revoked first to be
renewed. It gets a new JWT, valid from now, with the
same scopes and limits; the old JWT stops working. It is valid for `--valid`, or else for as long
as before; a revoked token gets the default validity of `token create`, and a token whose setup
code has expired the validity it was to have from that code. Its certificate count
starts again from zero. With `--otc`, `--otc-valid` and `--otc-network`, as for `token create`,
it prints a setup code instead: the old JWT stops working at once, and the new one is made, valid
from then on, when the code is exchanged.

Revoked and expired tokens stay in `tokens-db.json`, and keep their names, until `token purge`
removes them. `token purge` removes all of them and prints how many; `token purge NAME` removes
only `NAME`, which must be revoked or expired. Removed tokens cannot be renewed. With
`tokens.keep_expired` in [simple-ca.json](configuration.md), a duration such as `720h`, `serve`
also removes tokens that have been expired or revoked for longer than that, for all its CAs, at
start and every 5 minutes.

```sh
simple-ca token create --ca-dir /tmp/ca/servers --valid 8h --cert-type server --domain example.com deploy
simple-ca token create --ca-dir /tmp/ca/servers --valid 720h --domain '*' --ip 10.0.0.0/8 lab
simple-ca token create --ca-dir /tmp/ca/servers --valid 720h --host 192.168.1.4 --domain '*' builder
simple-ca token create --ca-dir /tmp/ca/servers --localhost --network 192.168.1.0/24 dev
simple-ca token create --ca-dir /tmp/ca --valid 720h --scope tokens --scope certs admin
simple-ca token list --ca-dir /tmp/ca/servers
simple-ca token renew --ca-dir /tmp/ca/servers --valid 8h deploy
simple-ca token revoke --ca-dir /tmp/ca/servers deploy
simple-ca token purge --ca-dir /tmp/ca/servers deploy
simple-ca token purge --ca-dir /tmp/ca/servers
```

`builder` signs any name, but only for requests from 192.168.1.4. `dev` signs `localhost`
certificates for clients in 192.168.1.0/24. `admin` is a root CA token that opens the token and
certificate pages for every CA.

```text
NAME     EXPIRES                  SCOPES  CERT TYPES  DOMAINS      IPS         CLIENTS         FEDERATES  CERTS  OIDC USER
builder  2026-12-01 13:43:41 UTC  sign    server      *            -           192.168.1.4     -          0      -
deploy   2026-11-01 21:43:41 UTC  sign    server      example.com  -           any             -          1      -
dev      2026-11-01 14:43:41 UTC  sign    server      localhost    127.0.0.1   192.168.1.0/24  -          0      -
lab      2026-12-01 13:43:41 UTC  sign    server      *            10.0.0.0/8  any             -          0      -
```

The commands and `serve` change `tokens-db.json` under a lock: the file `tokens-db.json.lock`
next to it, holding the PID of the process that has the lock. Other processes wait up to 10
seconds, then fail and name that PID. If the process was killed, remove the lock file by hand
once the process is gone.

## Token page

With `--webui`, `serve` serves a web page at `/tokens/` for managing the tokens of the root CA
and all its issuing CAs; the index page links to it.

The page asks for a token with the scope `tokens`, or a
[setup code](#one-time-setup-codes) of one, and keeps the token for the browser tab. A setup
code is exchanged for its token, which the page shows once and signs in with once that dialog is
closed; a token without the scope of the page is shown once too, and the page then asks for
another. With the [OIDC sign-in](oidc.md), the dialog also has a "Sign in with LABEL" button,
and the token of the sign-in signs in when it has the scope of the page. A token without the
scope of the page, or not allowed from the client, stays kept for the other pages of the tab, and
another token given replaces it; an invalid token is forgotten. The page shows who is signed
in, with a Sign out button; the name opens a dialog of the attributes of the token, as
`token describe` prints them. The index page shows the name too, with Sign out, when the token
kept has the scope of one of the pages. A root CA token sees every CA; an issuing CA token sees only its
own CA. The page shows one CA at a time, chosen in the CA selector, starting with the
root CA. On it you can:

- list the tokens, as `token list` does, each name opening a dialog of the token as JSON, as
  `GET /tokens/api/tokens` answers with it, and find them with the search and the filters. The search
  shows the tokens holding every word of it, in any letter case, in their name, OIDC user,
  status, scopes, cert types, domains, IP addresses, clients, certificate serials, or the token
  type and audience of their JWTs with `federate`. The Federates column shows that token type,
  followed by the built-in type it is based on, such as `gcp-wif (google)`, as the choosers of the
  page show it; it opens a dialog of the token type, the audience and the claims. The filters are:
  - **Status**: active, waiting for a setup code, expired or revoked, one or more, showing the
    tokens of any status chosen;
  - **Scope**: sign, tokens, certs, audit or federate, one or more, showing the tokens having every
    scope chosen, by name or by `*`;
  - **Federates**: one or more token types, or none, the tokens without the scope `federate`;
  - **Made by**: the OIDC sign-in or another way.

  A count tells how many are shown. The search and the filters are kept in the address, as `?q=`,
  `?status=`, `?scope=`, `?federates=` and `?kind=`, several values separated by commas, so a
  reload or a link keeps them;
- renew a token, as `token renew` does, confirming first, for the validity of "Valid for", the
  one it had by default, with a setup code in place of its JWT when "One-time setup code" is
  checked in the question;
- revoke a token, or remove a revoked or expired one, or all of them, as `token purge` does,
  confirming first;
- create a token with the options of `token create`, in a dialog filled with the `tokens`
  defaults of [simple-ca.json](configuration.md), or a setup code of it with "One-time setup
  code", its validity, 15 minutes by default, and the networks it is exchanged from. The name,
  the validity, the scopes and the clients come first; the Signing group shows with the scope
  `sign`, and the Federation group with the scope `federate`, both with `*`. In the Federation
  group, Token type picks the token type of its JWTs, or `none`, for a token that only grants the
  scope `federate`; once a type is chosen, Audience shows the audience of the type, which a value typed
  replaces, or that the type needs one, and Claims takes one `name=value` a line. The page never
  shows a JWT of a token type.

A new or renewed token, or the setup code of a new one, is shown once, in a dialog with a Copy
button, and is gone from the page when the dialog closes. A token waiting for its setup code is
marked `setup code`; it is revoked, which cancels the code, but not renewed until the code has
expired. A CA whose key is
not in its directory has no create form, because its
tokens cannot be signed there.

A signed-in token can give new tokens the scope `sign` and its own scopes, but no others: a token
with only `tokens` can create `sign` and `tokens` tokens, but not `certs` tokens. A token with the
scope `*` can give every scope, `*` included. It can renew, revoke and remove only tokens whose
scopes it has, apart from `sign`; removing all expired and revoked tokens skips the others. Make
the first token with `token create` on the CA host:

```sh
simple-ca token create --ca-dir /etc/simple-ca --valid 720h --scope tokens admin
simple-ca serve --ca-dir /etc/simple-ca --webui
```

Tokens are accepted only from the clients they allow (`--host` and `--network` of
`token create`); behind a trusted proxy of `serve`, the client is the address in the
`X-Forwarded-For` header. Over plain HTTP, the tokens cross the network in clear, which is usually
acceptable on a lab network; `serve` mentions it at start for an address other than a loopback
one. With `--tls-cert` and `--tls-key`, the page is served over HTTPS. Every change is logged
with the name of the token that made it.

The API of the page, below `/tokens/api/`, answers with JSON and takes the token as the bearer
token of every request: `Authorization: Bearer TOKEN`.

- `400 Bad Request` - a body that is not a JSON object of the request, a field the request does
  not use, a field it needs left out, a `valid` or `otc_valid` that is not a duration, or a token
  that cannot be created, renewed, revoked or removed as asked, such as an invalid name;
- `401 Unauthorized` - no token, or an invalid, revoked, expired or unknown one; a request without
  a token is recorded as `auth.refused` in the [audit log](audit.md), as a refused token is;
- `403 Forbidden` - a token without the scope `tokens`, a client the token does not allow, or
  creating, renewing, revoking or removing a token with a scope the signed-in token does not have;
- `404 Not Found` - a CA the token does not open;
- `429 Too Many Requests` - a client held back after refused tokens, see
  [Refused credentials](#refused-credentials).

`CA` is the name of an issuing CA, or empty for the root CA. An error is `{"error": "..."}`. The
API takes no defaults, unlike `token create` and `token renew`: a create gives `valid` and
`scopes`, and `types` for the scope `sign`, a renew gives `valid`, and a setup code gives
`otc_valid`. The token page fills in the defaults of the commands, from `tokens` of
`simple-ca.json`; `localhost` is never a default.

| Request | Body | Answer |
|---|---|---|
| `GET /tokens/api/cas` | | `title`, the root CA's CN; `user`, the name of the token, `user_ca`, its CA, and `user_token`, the token, with the fields of a token of `GET /tokens/api/tokens`; `cas`, the CAs the token opens, each with `id`, empty for the root CA, `subject`, the attributes of its subject as type and value pairs, `has_key` and `theme`, the `light` and `dark` colours of its `theme.json` by role; `types`; `token_types`, the token types of the scope `federate`, each with `name`, `base`, the built-in type it is or is based on, empty for none, `audience`, `needs_audience`, true when a token of the type needs an audience given, `valid`, the validity of its JWTs, and `max_valid`, empty without a limit; `scopes`, the scopes the token can give; `defaults`, from `tokens` of `simple-ca.json`, with only the scopes of them the token can give, or `sign` without any, and `otc_valid`, always 15 minutes |
| `GET /tokens/api/tokens?ca=CA` | | `tokens`, each with `name`, `issued`, `expires`, the expiry of its setup code when it is `pending`, `valid`, the validity `token renew` keeps, empty for a revoked token, `revoked`, `expired`, `pending`, `scopes`, `types`, `domains`, `ips` and `clients`, as prefixes, `certs`, the serials of the certificates issued with it, `oidc`, the `issuer`, `subject` and `user` of the OIDC user it was made for, or null, and `federate`, the `type`, `audience`, empty for that of the type, and `claims` of its JWTs, or null |
| `POST /tokens/api/tokens` | `ca`, `name`, `valid`, `scopes`, `types`, `domains`, `ips`, `clients`, `localhost`; for the scope `federate`, `federate`, an object of `type`, `audience` and `claims`, an object of strings; for a setup code, `otc`, `otc_valid` and `otc_networks` | `201 Created`, `name` and `token`, the JWT, or `code`, the setup code |
| `POST /tokens/api/tokens/renew` | `ca`, `name`, `valid`; for a setup code, `otc`, `otc_valid` and `otc_networks` | `name` and `token`, the new JWT, or `code`, the setup code |
| `POST /tokens/api/tokens/revoke` | `ca`, `name` | `name` |
| `POST /tokens/api/tokens/purge` | `ca`, and `name` for one token | `removed`, the count |

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  'https://pki.example.com:8443/tokens/api/tokens?ca=servers'
```

## Setup code exchange

`serve` exchanges the [setup code](#one-time-setup-codes) of a token of the root CA or of any of
its issuing CAs for the token at `/api/token-setup`, with `--webui` or without it. A request is a
`POST` with a JSON body of at most 64 KiB, and needs no token:

```json
{
  "code": "K7QF-M2XA-JP4D-W5ZR"
}
```

The answer is `{"ca": "servers", "name": "builder", "token": "eyJ...", "scopes": ["sign"]}`: the
issuing CA of the token, empty for the root CA, its name, its JWT, valid for the `--valid` of
`token create` from now, and its scopes. The code works once. An error is `{"error": "..."}` with
the status `400 Bad Request` for a body that is not a JSON object with the code,
`401 Unauthorized` for an unknown, used or expired code, `403 Forbidden` for a client
outside `--otc-network`, `415 Unsupported Media Type` for a body that is not
`application/json`, and `429 Too Many Requests` for a client held back after refused codes.

```sh
SERVER=http://pki.example.com:8080
CODE=K7QF-M2XA-JP4D-W5ZR
answer=$(jq -n --arg code "$CODE" '{code: $code}' | curl -sS \
  -H 'Content-Type: application/json' --data @- "$SERVER/api/token-setup")
TOKEN=$(printf '%s' "$answer" | jq -er '.token // empty' 2>/dev/null) || printf '%s\n' "$answer" >&2
```

An answer without a token is printed, and leaves `TOKEN` empty.

The page `/token-setup`, "Set up a token" on the index page and the token, certificate and audit
pages, does the same in a browser: it asks
for the code and shows the token once, with a Copy button and its attributes, as
`token describe` prints them, or the error. With the [OIDC sign-in](oidc.md), it also has a
"Sign in with LABEL" button, and shows the token of the sign-in once in the same way. Cancel, and
Close once the token is shown, return to the page of `serve` it was opened from, or to the index
page, as on the [signing form](#signing-form).

## Describe a token

The page `/token-describe`, "Describe a token" beside "Set up a token", shows the attributes of a
token pasted into it, as `token describe --ca-dir` prints them with the CA that signed it: it
checks the token against the root CA and each issuing CA of the server, and names its CA. A token
renewed, revoked or removed is shown as refused. A value that is no token of a CA of the server is
refused, and counted as a refused token is. Cancel returns to the page of `serve` it was opened
from, or to the index page.

## Requests and responses

`serve` signs certificate signing requests sent to `/api/sign` for the root CA, and to
`/NAME/api/sign` for the issuing CA `NAME`. The CA's key and `tokens-db.json` must be in its
directory; otherwise the answer is `404 Not Found`. The index page shows the URL for each CA that
signs. A request is a `POST` with a `sign` token of that CA as the bearer token, and a JSON body
of at most 64 KiB:

```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "type": "server",
  "name": "web",
  "days": 90,
  "ku": [
    "digitalSignature"
  ],
  "eku": [
    "serverAuth"
  ]
}
```

The API takes no defaults, as `cert sign` takes them from its options:

- `csr` - the request in PEM;
- `type` - the certificate type, one of the types the token allows;
- `name` - the name of the certificate file, as `cert sign` takes the name of the request file:
  each run of characters other than letters, digits, hyphens and underscores becomes one `_`, so
  `web` is stored as `web_cert.pem`; the name `ca`, whose file is the CA certificate, is refused;
- `days` - the validity in days;
- `ku` and `eku` - key usages and extended key usages added to those of the type, as `--ku` and
  `--eku` of `cert sign` add them; either may be left out.

The names in the request are checked by the name rules of the type, `names` in
[simple-ca.json](configuration.md):

- the subject may hold only a CN and `emailAddress`, and the SANs only DNS names, email addresses
  and IP addresses;
- `server` rules: the CN, if any, is a hostname, a wildcard or an IP address; the token must allow
  the CN and every DNS name and IP address; at least one name or address is required, and no
  email address is allowed;
- `user` rules: the token must allow the domain of every email address; at least one email
  address is required, and no DNS name or IP address is allowed; the CN is free text.

The certificate gets the subject and the SANs of the request, and the key usages, extended key
usages, AIA and CRL Distribution Point URLs that `cert create` gives the type, with those of `ku`
and `eku`. It is stored in the CA directory as `NAME_cert.pem`, replacing the file of an earlier
certificate of the name, as the [directory layout](directory-layout.md) describes, recorded in
`index.txt`, and its serial number in the token's entry in `tokens-db.json`. The response is JSON:

```json
{
  "serial": "542458ED...",
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "chain": "..."
}
```

`chain` holds the certificate and, for an issuing CA, the issuing CA certificate. An error is
`{"error": "..."}` with one of these statuses:

- `400 Bad Request` - a malformed body or request, a field missing, a name that gives no file
  name or is `ca`, or a key usage or extended key usage that is not one;
- `401 Unauthorized` - the token is missing, belongs to another CA, which the error names, or is
  revoked, expired or unknown (as the old JWT of a renewed token is); a request without a token is
  recorded as `auth.refused` in the [audit log](audit.md), as a refused token is;
- `403 Forbidden` - the token has no scope `sign`, does not allow the type or a name, or is not
  accepted from the client, or the request breaks the name rules above, such as a subject
  attribute other than CN and `emailAddress`, or a SAN other than a DNS name, an email address
  or an IP address;
- `415 Unsupported Media Type` - the body is not `application/json`;
- `429 Too Many Requests` - the client is held back after refused tokens, see
  [Refused credentials](#refused-credentials).

`tokens-db.json` is read on every request, so a revoked token is refused at once. Like
[ACME](acme.md), the API needs `serve` to be able to write to the CA directories and read the CA
keys. Without `--tls-cert`, tokens are sent in clear.

```sh
TOKEN=$(simple-ca token create --ca-dir /tmp/ca/servers --domain example.com deploy)
openssl req -new -newkey rsa:2048 -nodes -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com -out web.csr
CA_URL=http://pki.example.com:8080/servers
jq -n --rawfile csr web.csr '{csr: $csr, type: "server", name: "web", days: 90}' |
  curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data @- \
  "$CA_URL/api/sign" | jq -r .certificate > web_cert.pem
```

[examples.md](examples.md) describes the API clients in `examples/` and `cmd/request-cert/`, in
Python, Node.js, Go and the shell. They make a key and a request, and write the key, the
certificate and its chain.

## Federation tokens

`serve` hands a token with the scope `federate` a new JWT of its token type at
`/api/federation-token` for the root CA, and `/NAME/api/federation-token` for the issuing CA
`NAME`, for [workload identity federation](workload-identity.md). A request is a `POST` with the
token as its bearer token and an empty body, or `{}`: the token alone decides what the JWT holds,
its token type, audience and claims, fixed by `token create --federate-type`, `--audience` and
`--claim`.

The answer is `{"token": "eyJ...", "token_type": "google", "audience": "...", "subject":
"deploy", "expires": "2026-11-08T21:53:50Z"}`. The JWT is valid for the `valid` of its type, one
hour by default, and never after the token expires. It is not stored: revoking the token stops
new JWTs, and those issued stay valid until they expire. simple-ca refuses such a JWT as a token.
Each JWT issued is recorded as `token.issue` in the [audit log](audit.md).

An error is `{"error": "..."}` with the status:

- `400 Bad Request` - a body other than empty or `{}`, a token type no longer in
  `simple-ca.json`, or a CA without an issuer;
- `401 Unauthorized` - no token, or an invalid, revoked, expired or unknown one, or one of another
  CA;
- `403 Forbidden` - a token without the scope `federate`, a token without a token type, or a
  client the token does not allow;
- `404 Not Found` - a CA without its key or `tokens-db.json`;
- `429 Too Many Requests` - the client is held back after refused tokens.

```sh
CA_URL=https://pki.example.com:8443/servers
TOKEN=$(cat deploy.token)
curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$CA_URL/api/federation-token" | jq -r .token
```

## Refused credentials

`serve` counts the tokens, setup codes and OIDC ID tokens it refuses with
`401 Unauthorized` for each client, an IPv6 client by its /64 prefix. This applies to the
signing API, the signing forms, `/api/token-setup`, `/token-setup`, `/api/oidc-token` and the
API of the token, certificate and audit pages. The first 5 refusals in a row are free; from the
6th:

- the client is held back for 1 second, a time that doubles with each further refusal, up to
  15 minutes;
- while held back, every request of the client that carries a credential is answered with
  `429 Too Many Requests` and a `Retry-After` header, the seconds left, without checking the
  credential, even a valid one;
- a request without a credential is not counted.

A request that succeeds forgets the refusals of its client, and so do 60 minutes without a
refusal. A request whose credential is valid but refused with another status, such as
`403 Forbidden` for a scope, a client or a name the token does not allow, neither counts nor
forgets. The count is kept in memory and starts again with `serve`. Behind a reverse proxy, name
it with `--trusted-proxy`, or every client counts as the proxy.

## Signing form

`/sign` for the root CA, and `/NAME/sign` for the issuing CA `NAME`, are pages with a form for the
[signing API](#requests-and-responses); the index page links to them for each CA with tokens and
its key. For
a CA without its key or without `tokens-db.json`, the page says so instead of showing the form,
and a form sent to it gets `403 Forbidden`. A `NAME` that is not an issuing CA gets
`404 Not Found`.

Paste the CSR in PEM, choose the certificate type (by default the token's first type, or `server`
for the type `*`), and enter the token, or a [setup code](#one-time-setup-codes), in the password
field. The checks are the same as the API's. A setup code signs this one certificate, with the
limits of its token, from a client of its `--otc-network`; the token is revoked once the
certificate is issued, so the code works no more, while a refused request leaves the code as it
was. The signed certificate downloads as a PEM file named by the
[file name rules](directory-layout.md): `web_cert.pem` for the CN `web.example.com`, or the serial
number for a request without a name. If the request is
refused, the form shows the error again, keeping the CSR and the type and clearing the token.
Cancel returns to the page of `serve` the form was opened from, also after a refused request or
an OIDC sign-in, or to the index page when it was opened otherwise.

With the [OIDC sign-in](oidc.md), the form has a "Sign in with LABEL" button. The CSR and the
type are kept while the browser is at the provider, and the token of the sign-in fills the token
field once it is back; it signs at the CA of its profile alone.
