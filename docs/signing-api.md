# Signing API

`serve` signs certificate signing requests sent by programs to `/api/sign`, and pasted by people
on the `/sign` page, for the tokens that `token create` makes.

## token create, list, revoke and purge

`token create` creates the token `NAME` of the [signing API](#requests-and-responses) of the CA in
the CA directory, root or issuing CA, records it in `tokens-db.json` of that directory and prints
it. The token is a JWT signed with the CA key (RS256), so it is valid for that CA alone; it is
shown only once. It allows the certificate types of `--type`, repeated for more, `server` by
default, and the names that are a `--domain`, repeated for more, or below one. It is valid for
`--valid`, a duration such as `30m`, `8h` or `720h`, one hour by default, and at least one second.
A name is made of letters, digits, `.`, `-` and `_`, and is held by one token of a CA at a time.

`token list` lists the tokens of the CA, with their status (`valid` or `expired`), expiry, types,
domains and the count of certificates issued with them. `token revoke` revokes the token `NAME` by
removing it from `tokens-db.json`; the API refuses it from then on as an unknown token. Its name
can be given to a new token, which has a new JWT ID, so the revoked token stays refused.
`token purge` removes the expired tokens from `tokens-db.json` and prints their count; `serve`
does the same for all its CAs when it starts and every 5 minutes.

```sh
simple-ca token create --ca-dir /tmp/ca/servers --valid 8h --type server --domain example.com deploy
simple-ca token list --ca-dir /tmp/ca/servers
simple-ca token revoke --ca-dir /tmp/ca/servers deploy
simple-ca token purge --ca-dir /tmp/ca/servers
```

```text
NAME    STATUS  EXPIRES                  TYPES   DOMAINS      CERTS
deploy  valid   2026-10-31 21:43:41 UTC  server  example.com  1
```

The commands and `serve` change `tokens-db.json` under a lock, the file `tokens-db.json.lock` next
to it, which holds the PID of the process that has it. One process at a time creates the file and
removes it when done; any other waits for it up to 10 seconds, then fails with the PID. A lock
left by a process that was killed is removed by hand once that process is gone.

## Requests and responses

`serve` signs certificate signing requests sent to `/api/sign` for the root CA and to
`/NAME/api/sign` for the issuing CA `NAME`, for a CA whose key and `tokens-db.json` are in its
directory; for any other it is `404 Not Found`. The index page shows the URL of each such CA. A
request is a `POST` with a token of [token create](#token-create-list-revoke-and-purge) of that
CA as a bearer token, and a JSON body of at most 64 KiB:

```json
{"csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "type": "server"}
```

`csr` is the request in PEM. `type`, the first type of the token by
default, is one of the types the token allows. The names of the request are checked by the name
rules of the type, `names` of [simple-ca.json](configuration.md):

- the subject holds only a CN and `emailAddress`, and the SANs only DNS names and email addresses;
- `server` rules: the CN, when there is one, and every DNS name are hostnames or wildcards that
  the token allows; at least one is there, and no email address;
- `user` rules: the domain of every email address is one the token allows; at least one is
  there, and no DNS name; the CN is free text.

The certificate has the subject and the SANs of the request, and the key usages, extended key
usages, AIA and CRL Distribution Point URLs of `cert create` for the type; it is valid for
`days.cert` of `simple-ca.json`, 365 days without it. It is recorded in `index.txt`, and its
serial number in the entry of the token in `tokens-db.json`. The response is JSON:

```json
{"serial": "542458ED...", "certificate": "-----BEGIN CERTIFICATE-----\n...", "chain": "..."}
```

`chain` holds the certificate and, from an issuing CA, the issuing CA certificate. An error is
`{"error": "..."}` with the status `400 Bad Request` for a malformed body or request,
`401 Unauthorized` for a token that is missing, of another CA, expired or unknown, as a revoked
token is, `403 Forbidden` for a type or a name the token does not allow, and
`415 Unsupported Media Type` for a body that is not `application/json`. `tokens-db.json` is read
on each request, so a token revoked by `token revoke` is refused at once. Like [ACME](acme.md), the
API needs `serve` to write to the CA directories and read the CA keys; a token is sent in clear
without `--tls-cert`.

```sh
TOKEN=$(simple-ca token create --ca-dir /tmp/ca/servers --domain example.com deploy)
openssl req -new -newkey rsa:2048 -nodes -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com -out web.csr
jq -n --rawfile csr web.csr '{csr: $csr}' | curl -s -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data @- http://pki.example.com:8080/servers/api/sign |
  jq -r .certificate > web_cert.pem
```

[examples.md](examples.md) describes the clients of the API in `examples/`, in Python, Node.js, Go
and the shell, which make a key and a request and write the key, the certificate and its chain.

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
