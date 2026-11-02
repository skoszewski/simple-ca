# Signing API

`serve` signs certificate signing requests sent by programs to `/api/sign`, and pasted by people
on the `/sign` page, for the tokens that `token create` makes. `serve` shows the clients how to
request a certificate at `/help/`.

## token create, list, renew, revoke and purge

`token create` creates the token `NAME` of the [signing API](#requests-and-responses) of the CA in
the CA directory, root or issuing CA, records it in `tokens-db.json` of that directory and prints
it. The token is a JWT signed with the CA key (RS256), so it is valid for that CA alone; it is
shown only once. It allows:

- the certificate types of `--type`, repeated for more, `server` by default;
- the names that are a `--domain`, repeated for more, or below one; `--domain '*'` allows any
  name, for a lab;
- the IP addresses of `--ip`, repeated for more: an address, such as `192.0.2.10`, a prefix, such
  as `10.0.0.0/8` or `2001:db8::/32`, or `*` for any address;
- with `--localhost`, the name `localhost` and the IP address `127.0.0.1`, as
  `--domain localhost --ip 127.0.0.1` do.

At least one `--domain`, `--ip` or `--localhost` is given. `--host ADDRESS`, repeated for more,
and `--network PREFIXES`, a comma-separated list such as `192.168.1.0/24,10.0.0.0/8`, limit the
clients the token is accepted from: a request from any other address is `403 Forbidden`. Without
them, the token is accepted from any client. The client is the address the request comes from,
or, behind a trusted proxy, the address its `X-Forwarded-For` header names; see
[serve](serve.md).

The token is valid for `--valid`, a duration such as `30m`, `8h` or `720h`, one hour by default,
and at least one second. `NAME` is a **kebab-case** name: words of lower-case letters and digits
joined by hyphens, such as `web-deploy`; it is held by one token of a CA at a time.

An option not given takes its default from `tokens` of [simple-ca.json](configuration.md): with
`"tokens": {"domains": ["*"], "networks": ["192.168.1.0/24"]}`, `token create NAME` makes a lab
token for any name used from 192.168.1.0/24, and `--domain example.com` narrows one token to
`example.com`. `--host` and `--network` replace `hosts` and `networks` together, and
`--localhost=false` turns off a `localhost` default.

`token list` lists the tokens of the CA, with their expiry, marked `(expired)` for a token not
purged yet, or `revoked` for a revoked one, types, domains, IP prefixes, clients and the count of
certificates issued with them. `token revoke` revokes the token `NAME`: its entry in
`tokens-db.json` loses its JWT ID and expires at once, and the API refuses its JWT from then on.
An entry without a JWT ID is a revoked token.

`token renew` renews the token `NAME`, revoked, expired or not, and prints it: the entry in
`tokens-db.json` gets a new JWT ID and is valid from now, for `--valid`, else for as long as it was
before or, revoked, for the default validity of `token create`, and it allows the types, names and
addresses, and is used from the clients, it was before.
The JWT the token had is refused from then on as an unknown token. The certificates issued with
it are counted anew.

A revoked or expired token stays in `tokens-db.json`, to be renewed, and holds its name, until
`token purge` removes it for good: `token purge` removes every revoked and expired token and prints
their count, and `token purge NAME` the token `NAME` alone, which must be revoked or expired. With
`tokens.keep_expired` of [simple-ca.json](configuration.md), a duration such as `720h`, `serve`
also removes, for all its CAs, the tokens expired, or revoked, for longer than that, when it starts
and every 5 minutes.

```sh
simple-ca token create --ca-dir /tmp/ca/servers --valid 8h --type server --domain example.com deploy
simple-ca token create --ca-dir /tmp/ca/servers --valid 720h --domain '*' --ip 10.0.0.0/8 lab
simple-ca token create --ca-dir /tmp/ca/servers --valid 720h --host 192.168.1.4 --domain '*' builder
simple-ca token create --ca-dir /tmp/ca/servers --localhost --network 192.168.1.0/24 dev
simple-ca token list --ca-dir /tmp/ca/servers
simple-ca token renew --ca-dir /tmp/ca/servers --valid 8h deploy
simple-ca token revoke --ca-dir /tmp/ca/servers deploy
simple-ca token purge --ca-dir /tmp/ca/servers deploy
simple-ca token purge --ca-dir /tmp/ca/servers
```

`builder` signs any name, for requests from 192.168.1.4 alone; `dev` signs `localhost`
certificates for the clients of 192.168.1.0/24.

```text
NAME     EXPIRES                  TYPES   DOMAINS      IPS         CLIENTS         CERTS
builder  2026-12-01 13:43:41 UTC  server  *            -           192.168.1.4     0
deploy   2026-11-01 21:43:41 UTC  server  example.com  -           any             1
dev      2026-11-01 14:43:41 UTC  server  localhost    127.0.0.1   192.168.1.0/24  0
lab      2026-12-01 13:43:41 UTC  server  *            10.0.0.0/8  any             0
```

The commands and `serve` change `tokens-db.json` under a lock, the file `tokens-db.json.lock` next
to it, which holds the PID of the process that has it. One process at a time creates the file and
removes it when done; any other waits for it up to 10 seconds, then fails with the PID. A lock
left by a process that was killed is removed by hand once that process is gone.

## token webui

`token webui` serves a web page managing the tokens of the root CA of the CA directory and of all
its issuing CAs, until it is stopped with Ctrl-C. The page shows one CA, chosen in its CA
selector, the root CA at first: it lists the tokens of the CA as `token list` does, renews a
token as `token renew` does, asking first for a token still accepted, revokes a token, removes a
revoked or expired token, or all of them, as `token purge` does, asking first, and creates a token
with the options of `token create`, in a dialog whose form is filled with the
`tokens` defaults of [simple-ca.json](configuration.md). A new or renewed token is shown once,
in a dialog with a Copy button; it leaves the page when the dialog closes, with Close, Escape or a
click beside it. A CA whose key is not in its directory has no form, as its tokens cannot be
signed there.

```sh
simple-ca token webui --ca-dir /etc/simple-ca
```

`--address` is the address of the interface it listens on, `127.0.0.1` by default, and `--port`
the TCP port, 8081 by default. At the start it prints the URL of the page with a random key as
its `?key=` query; the key is valid until `token webui` stops. The page reads the key from that
URL, or asks for it, keeps it for the browser tab, and draws the tokens from the API of
`token webui`, sending the key in the `Authorization` header. `--tls-cert` and `--tls-key`, as
for `serve`, serve the page over HTTPS with the certificate chain and the key of those PEM files;
without them it is served over plain HTTP, so on any address but a loopback one the key can be
read on the network, which it warns of. Each request is logged to the standard error, as `serve`
logs them.

The API answers with JSON, and takes the key as the bearer token of every request,
`Authorization: Bearer KEY`; a request without it, or with another key, is `401 Unauthorized`.
`CA` is the name of an issuing CA, or empty for the root CA; an error is `{"error": "..."}`.

| Request | Body | Answer |
|---|---|---|
| `GET /api/cas` | | `title`, the root CA's CN; `cas`, each with `id`, `role`, `name`, the CN of its subject or else the whole subject, `subject`, `subject_attributes`, each a type and a value, `label` and `has_key`; `types`; `defaults`, from `tokens` of `simple-ca.json` |
| `GET /api/tokens?ca=CA` | | `tokens`, each with `name`, `expires`, `revoked`, `expired`, `types`, `domains`, `ips`, `clients` and `certs` |
| `POST /api/tokens` | `ca`, `name`, `valid`, `types`, `domains`, `ips`, `clients`, `localhost` | `201 Created`, `name` and `token`, the JWT |
| `POST /api/tokens/renew` | `ca`, `name` | `name` and `token`, the new JWT |
| `POST /api/tokens/revoke` | `ca`, `name` | `name` |
| `POST /api/tokens/purge` | `ca`, and `name` for one token | `removed`, the count |

```sh
curl -s -H "Authorization: Bearer $KEY" 'http://127.0.0.1:8081/api/tokens?ca=servers'
```

## Requests and responses

`serve` signs certificate signing requests sent to `/api/sign` for the root CA and to
`/NAME/api/sign` for the issuing CA `NAME`, for a CA whose key and `tokens-db.json` are in its
directory; for any other it is `404 Not Found`. The index page shows the URL of each such CA. A
request is a `POST` with a token of [token create](#token-create-list-renew-revoke-and-purge) of that
CA as a bearer token, and a JSON body of at most 64 KiB:

```json
{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "type": "server"}
```

`csr` is the request in PEM. `type`, the first type of the token by
default, is one of the types the token allows. The names of the request are checked by the name
rules of the type, `names` of [simple-ca.json](configuration.md):

- the subject holds only a CN and `emailAddress`, and the SANs only DNS names, email addresses
  and IP addresses;
- `server` rules: the CN, when there is one, is a hostname, a wildcard or an IP address; the CN
  and every DNS name and IP address are allowed by the domains and the IP addresses of the token;
  at least one name or address is there, and no email address;
- `user` rules: the domain of every email address is one the token allows; at least one is
  there, and neither a DNS name nor an IP address; the CN is free text.

The certificate has the subject and the SANs of the request, and the key usages, extended key
usages, AIA and CRL Distribution Point URLs of `cert create` for the type; it is valid for
`days.cert` of `simple-ca.json`, 365 days without it. It is recorded in `index.txt`, and its
serial number in the entry of the token in `tokens-db.json`. The response is JSON:

```json
{"serial": "542458ED...", "certificate": "-----BEGIN CERTIFICATE-----\n...", "chain": "..."}
```

`chain` holds the certificate and, from an issuing CA, the issuing CA certificate. An error is
`{"error": "..."}` with the status `400 Bad Request` for a malformed body or request,
`401 Unauthorized` for a token that is missing, of another CA, revoked, expired or unknown, as the
JWT a renewed token had is, `403 Forbidden` for a type or a name the token does not allow and for a client it is
not accepted from, and `415 Unsupported Media Type` for a body that is not `application/json`.
`tokens-db.json` is read on each request, so a token revoked by `token revoke` is refused at once.
Like [ACME](acme.md), the API needs `serve` to write to the CA directories and read the CA keys; a
token is sent in clear without `--tls-cert`.

```sh
TOKEN=$(simple-ca token create --ca-dir /tmp/ca/servers --domain example.com deploy)
openssl req -new -newkey rsa:2048 -nodes -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com -out web.csr
jq -n --rawfile csr web.csr '{csr: $csr}' | curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data @- http://pki.example.com:8080/servers/api/sign |
  jq -r .certificate > web_cert.pem
```

[examples.md](examples.md) describes the clients of the API in `examples/` and
`cmd/request-cert/`, in Python, Node.js, Go and the shell, which make a key and a request and
write the key, the certificate and its chain.

## Signing form

`/sign` for the root CA and `/NAME/sign` for the issuing CA `NAME` are a page with a form of the
[signing API](#requests-and-responses); the index page links to it from each CA with tokens. For
a CA without its key or without `tokens-db.json`, the page says so in place of the form, and a
form sent to it is `403 Forbidden`; a `NAME` that is not an issuing CA is `404 Not Found`. The
CSR is pasted in PEM, the certificate type is chosen from the types of `simple-ca.json`, the first
type of the token by default, and the token is entered in a password field. The checks are those
of the API. The signed certificate is downloaded as a PEM file named by the
[file name rules](directory-layout.md), `web_cert.pem` for the CN `web.example.com`, or after its
serial number for a request without a name. A refused request shows the form again with the
error, the CSR and the type kept, and the token cleared.
