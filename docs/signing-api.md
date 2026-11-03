# Signing API

`serve` signs certificate signing requests sent by programs to `/api/sign`, and pasted by people
on the `/sign` page, for the tokens that `token create` makes. `serve` shows the clients how to
request a certificate at `/help/`.

## token create, list, renew, revoke and purge

`token create` creates the token `NAME` for the CA in the CA directory (root or issuing CA),
records it in that directory's `tokens-db.json` and prints it. The token is a JWT signed with the
CA key (RS256) and is valid only for that CA. It is shown only once, so copy it then.

`--scope` sets what the token opens; it may be specified multiple times, and defaults to `sign`:

| Scope | Opens |
|---|---|
| `sign` | the [signing API](#requests-and-responses) and the [signing form](#signing-form) |
| `tokens` | the [token page](#token-page) of `serve --webui` |
| `certs` | the [certificate page](usage.md#certificate-page) of `serve --webui` |
| `*` | all of them, given alone |

A root CA token opens the pages for every CA; an issuing CA token opens only its own CA.

With the scope `sign`, these options set what the token may sign; each may be specified multiple
times:

- `--type` - the certificate types, or `*`, given alone, for every type of `simple-ca.json`,
  also one added later; `server` by default;
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
token to `example.com`. `--host` and `--network` together replace both `hosts` and `networks`, and
`--localhost=false` turns off a `localhost` default. The defaults of `--type`, `--domain`, `--ip`
and `--localhost` apply only to tokens with the scope `sign`.

`token list` lists the tokens of the CA: name, expiry (marked `(expired)`, or `revoked`), scopes,
types, domains, IP prefixes, clients and the number of certificates issued. `-` marks what a token
without `sign` does not have.

`token revoke` revokes the token `NAME`: its JWT stops working at once, for the API and the web
UIs. The token stays in `tokens-db.json`, without a JWT ID, so it can be renewed. An entry
without `scopes` has the scope `sign`.

`token renew` renews the token `NAME`, whether revoked, expired or still valid, and prints it. It
gets a new JWT, valid from now, with the same scopes and limits; the old JWT stops working. It is
valid for `--valid`, or else for as long as before; a revoked token gets the default validity of
`token create`. Its certificate count starts again from zero.

Revoked and expired tokens stay in `tokens-db.json`, and keep their names, until `token purge`
removes them. `token purge` removes all of them and prints how many; `token purge NAME` removes
only `NAME`, which must be revoked or expired. Removed tokens cannot be renewed. With
`tokens.keep_expired` in [simple-ca.json](configuration.md), a duration such as `720h`, `serve`
also removes tokens that have been expired or revoked for longer than that, for all its CAs, at
start and every 5 minutes.

```sh
simple-ca token create --ca-dir /tmp/ca/servers --valid 8h --type server --domain example.com deploy
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
NAME     EXPIRES                  SCOPES  TYPES   DOMAINS      IPS         CLIENTS         CERTS
builder  2026-12-01 13:43:41 UTC  sign    server  *            -           192.168.1.4     0
deploy   2026-11-01 21:43:41 UTC  sign    server  example.com  -           any             1
dev      2026-11-01 14:43:41 UTC  sign    server  localhost    127.0.0.1   192.168.1.0/24  0
lab      2026-12-01 13:43:41 UTC  sign    server  *            10.0.0.0/8  any             0
```

The commands and `serve` change `tokens-db.json` under a lock: the file `tokens-db.json.lock`
next to it, holding the PID of the process that has the lock. Other processes wait up to 10
seconds, then fail and name that PID. If the process was killed, remove the lock file by hand
once the process is gone.

## Token page

With `--webui`, `serve` serves a web page at `/tokens/` for managing the tokens of the root CA
and all its issuing CAs; the index page links to it.

The page asks for a token with the scope `tokens` and keeps it for the browser tab. It shows who
is signed in, with a Sign out button. A root CA token sees every CA; an issuing CA token sees
only its own CA. The page shows one CA at a time, chosen in the CA selector, starting with the
root CA. On it you can:

- list the tokens, as `token list` does;
- renew a token, as `token renew` does, confirming first if the token is still valid;
- revoke a token, or remove a revoked or expired one, or all of them, as `token purge` does,
  confirming first;
- create a token with the options of `token create`, in a dialog filled with the `tokens`
  defaults of [simple-ca.json](configuration.md).

A new or renewed token is shown once, in a dialog with a Copy button, and is gone from the page
when the dialog closes. A CA whose key is not in its directory has no create form, because its
tokens cannot be signed there.

A signed-in token can give new tokens the scope `sign` and its own scopes, but no others: a token
with only `tokens` can create `sign` and `tokens` tokens, but not `certs` tokens. A token with the
scope `*` can give every scope, `*` included. It can renew,
revoke and remove only tokens whose scopes it has, apart from `sign`; removing all expired and
revoked tokens skips the others. Make the first token with `token create` on the CA host:

```sh
simple-ca token create --ca-dir /etc/simple-ca --valid 720h --scope tokens admin
simple-ca serve --ca-dir /etc/simple-ca --webui
```

Tokens are accepted only from the clients they allow (`--host` and `--network` of
`token create`); behind a trusted proxy of `serve`, the client is the address in the
`X-Forwarded-For` header. Use `--tls-cert` and `--tls-key`: without them the page uses plain
HTTP, and on any address but a loopback one the tokens can be read on the network, which `serve`
warns about at start. Every change is logged with the name of the token that made it.

The API of the page, below `/tokens/api/`, answers with JSON and takes the token as the bearer
token of every request: `Authorization: Bearer TOKEN`.


- `401 Unauthorized` - no token, or an invalid, revoked, expired or unknown one;
- `403 Forbidden` - a token without the scope `tokens`, a client the token does not allow, or
  creating, renewing, revoking or removing a token with a scope the signed-in token does not have;
- `404 Not Found` - a CA the token does not open.

`CA` is the name of an issuing CA, or empty for the root CA. An error is `{"error": "..."}`.

| Request | Body | Answer |
|---|---|---|
| `GET /tokens/api/cas` | | `title`, the root CA's CN; `user`, the name of the token, and `user_ca`, its CA; `cas`, the CAs the token opens, each with `id`, `role`, `name` (the CN of its subject, or else the whole subject), `subject`, `subject_attributes` (type and value pairs), `label` and `has_key`; `types`; `scopes`, the scopes the token can give; `defaults`, from `tokens` of `simple-ca.json` |
| `GET /tokens/api/tokens?ca=CA` | | `tokens`, each with `name`, `expires`, `revoked`, `expired`, `scopes`, `types`, `domains`, `ips`, `clients` and `certs` |
| `POST /tokens/api/tokens` | `ca`, `name`, `valid`, `scopes`, `types`, `domains`, `ips`, `clients`, `localhost` | `201 Created`, `name` and `token`, the JWT |
| `POST /tokens/api/tokens/renew` | `ca`, `name` | `name` and `token`, the new JWT |
| `POST /tokens/api/tokens/revoke` | `ca`, `name` | `name` |
| `POST /tokens/api/tokens/purge` | `ca`, and `name` for one token | `removed`, the count |

```sh
curl -s -H "Authorization: Bearer $TOKEN" 'https://pki.example.com:8443/tokens/api/tokens?ca=servers'
```

## Requests and responses

`serve` signs certificate signing requests sent to `/api/sign` for the root CA, and to
`/NAME/api/sign` for the issuing CA `NAME`. The CA's key and `tokens-db.json` must be in its
directory; otherwise the answer is `404 Not Found`. The index page shows the URL for each CA that
signs. A request is a `POST` with a `sign` token of that CA as the bearer token, and a JSON body
of at most 64 KiB:

```json
{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "type": "server"}
```

`csr` is the request in PEM. `type` must be one of the types the token allows; it defaults to the
token's first type, or `server` for a token with the type `*`. The names in the request are
checked by the name rules of the type, `names` in [simple-ca.json](configuration.md):

- the subject may hold only a CN and `emailAddress`, and the SANs only DNS names, email addresses
  and IP addresses;
- `server` rules: the CN, if any, is a hostname, a wildcard or an IP address; the token must allow
  the CN and every DNS name and IP address; at least one name or address is required, and no
  email address is allowed;
- `user` rules: the token must allow the domain of every email address; at least one email
  address is required, and no DNS name or IP address is allowed; the CN is free text.

The certificate gets the subject and the SANs of the request, and the key usages, extended key
usages, AIA and CRL Distribution Point URLs that `cert create` gives the type. It is valid for
`days.cert` of `simple-ca.json`, or 365 days. It is recorded in `index.txt`, and its serial
number in the token's entry in `tokens-db.json`. The response is JSON:

```json
{"serial": "542458ED...", "certificate": "-----BEGIN CERTIFICATE-----\n...", "chain": "..."}
```

`chain` holds the certificate and, for an issuing CA, the issuing CA certificate. An error is
`{"error": "..."}` with one of these statuses:

- `400 Bad Request` - a malformed body or request;
- `401 Unauthorized` - the token is missing, belongs to another CA, or is revoked, expired or
  unknown (as the old JWT of a renewed token is);
- `403 Forbidden` - the token has no scope `sign`, does not allow the type or a name, or is not
  accepted from the client;
- `415 Unsupported Media Type` - the body is not `application/json`.

`tokens-db.json` is read on every request, so a revoked token is refused at once. Like
[ACME](acme.md), the API needs `serve` to be able to write to the CA directories and read the CA
keys. Without `--tls-cert`, tokens are sent in clear.

```sh
TOKEN=$(simple-ca token create --ca-dir /tmp/ca/servers --domain example.com deploy)
openssl req -new -newkey rsa:2048 -nodes -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com -out web.csr
jq -n --rawfile csr web.csr '{csr: $csr}' | curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data @- http://pki.example.com:8080/servers/api/sign |
  jq -r .certificate > web_cert.pem
```

[examples.md](examples.md) describes the API clients in `examples/` and `cmd/request-cert/`, in
Python, Node.js, Go and the shell. They make a key and a request, and write the key, the
certificate and its chain.

## Signing form

`/sign` for the root CA, and `/NAME/sign` for the issuing CA `NAME`, are pages with a form for the
[signing API](#requests-and-responses); the index page links to them for each CA with tokens. For
a CA without its key or without `tokens-db.json`, the page says so instead of showing the form,
and a form sent to it gets `403 Forbidden`. A `NAME` that is not an issuing CA gets
`404 Not Found`.

Paste the CSR in PEM, choose the certificate type (by default the token's first type, or `server`
for the type `*`), and enter the token in the password field. The checks are the same as the
API's. The signed certificate downloads as a PEM file named by the
[file name rules](directory-layout.md): `web_cert.pem` for the CN `web.example.com`, or the serial
number for a request without a name. If the request is
refused, the form shows the error again, keeping the CSR and the type and clearing the token.
