---
title: Requesting a certificate
---

This CA signs certificate signing requests (CSRs) sent with a token from its administrator. The
token says which names and addresses it may sign, and may be valid for a short time only.

## What you need

- The URL of the signing API of the CA: `/api/sign` of the root CA, or `/NAME/api/sign` of the
  issuing CA `NAME`. The index page of this server lists the URL of each CA that signs requests.
- A token, given to you by the administrator of the CA, in a file such as `token.txt`, or a
  one-time setup code, which you exchange for the token, as below.
- `request-cert`, or else `openssl`, `curl` and `jq`.

## With a setup code

A setup code, such as `K7QF-M2XA-JP4D-W5ZR`, is exchanged once, before it expires, for your
token, at `/api/token-setup` of this server; the administrator may allow it from your network
only. Keep the token it gives you, as it is shown only once:

```sh
SERVER=http://pki.example.com:8080
CODE=K7QF-M2XA-JP4D-W5ZR
answer=$(jq -n --arg code "$CODE" '{code: $code}' | curl -sS \
  -H 'Content-Type: application/json' --data @- "$SERVER/api/token-setup")
(umask 077; printf '%s' "$answer" | jq -er .token > token.txt) 2>/dev/null ||
  { rm -f token.txt; printf '%s\n' "$answer" >&2; }
```

An answer without a token is printed, and leaves no `token.txt`. A used, unknown or expired code
is `401 Unauthorized`, and a code from another network
`403 Forbidden`. In a browser, "Set up a token" on the pages of the server, `/token-setup`, does
the same and shows the token once. `request-cert` exchanges the code itself, as below. For a single
certificate, the code is entered in place of a token on the
[signing form](#without-the-command-line): it signs that one certificate and works no more.

## With request-cert

`request-cert` makes the key and the request, sends them, and saves the certificate, in one
command. It is in the release archives of simple-ca, `simple-ca-X.Y.Z-<platform>`, on
[GitHub](https://github.com/skoszewski/simple-ca/releases), beside `simple-ca`; with Go
installed, `go install github.com/skoszewski/simple-ca/cmd/request-cert@latest` installs it.

```sh
request-cert --token-file token.txt http://pki.example.com:8080/servers/api/sign \
  web.example.com www.example.com
```

The first name is the CN of the certificate and its first DNS name; the names after it are its
other DNS names. The token must allow every one of them. It writes, in the working directory or
the one `--out-dir` names:

- `web.example.com_key.pem` - the key, an EC P-256 key, mode 0600;
- `web.example.com_cert.pem` - the certificate;
- `web.example.com_chain.pem` - the certificate and, from an issuing CA, the certificate of the
  issuing CA.

The token is read from the file of `--token-file`, or from the environment variable
`SIMPLE_CA_TOKEN`, never from the command line. With `--setup-code`, it exchanges the setup code
for the token first, and writes the token to `--token-file`, a new file, for later requests:

```sh
request-cert --setup-code K7QF-M2XA-JP4D-W5ZR --token-file token.txt \
  http://pki.example.com:8080/servers/api/sign web.example.com
```
 `--type` names the certificate type, when the
token allows more than one; without it, the first type of the token is used. An existing key is
never overwritten, and a refused request prints the status and the error, as listed under
[Errors](#errors), and exits with 1. `request-cert -h` lists the options.

## With openssl, curl and jq

These commands do the same step by step, and also make certificates with IP addresses, or sign
a request made elsewhere. They use these shell variables; replace the URL and the file with your
own:

```sh
API=http://pki.example.com:8080/servers/api/sign
TOKEN=$(cat token.txt)
```

### Create a key and a request

A request for a server certificate holds the name of the server as its CN and as a DNS name, and
may hold more DNS names and IP addresses. The token must allow every one of them.

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com,DNS:www.example.com,IP:192.0.2.10 \
  -out web.csr
```

The subject holds a CN and, for a user certificate, an `emailAddress`, and nothing else.

### Send the request

The request is a `POST` of JSON with the CSR, and the token as a bearer token:

```sh
jq -n --rawfile csr web.csr '{csr: $csr}' |
  curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    --data @- "$API" > web.json
```

`type` names the certificate type, when the token allows more than one; without it, the first
type of the token is used:

```sh
jq -n --rawfile csr web.csr '{csr: $csr, type: "server"}'
```

### Save the certificate

The answer holds the serial number, the certificate, and the chain: the certificate followed by
the certificate of the issuing CA.

```sh
jq -r .certificate web.json > web_cert.pem
jq -r .chain web.json > web_chain.pem
jq -r .serial web.json
```

Check the certificate against the CA bundle of this server:

```sh
curl -s http://pki.example.com:8080/ca_bundle.pem > ca_bundle.pem
openssl verify -CAfile ca_bundle.pem web_cert.pem
openssl x509 -in web_cert.pem -noout -subject -ext subjectAltName -enddate
```

## Errors

A refused request is answered with `{"error": "..."}`, which `request-cert` prints with the
status, and `jq -r .error web.json` prints from the answer saved above:

| Status | Meaning |
|---|---|
| `400 Bad Request` | the body is not JSON with `csr` and `type`, or the CSR does not read |
| `401 Unauthorized` | the token is missing, expired, revoked, or of another CA |
| `403 Forbidden` | the token does not allow a name, an address or the type, whose error names the types it allows, or your address |
| `404 Not Found` | the CA does not sign requests here |
| `415 Unsupported Media Type` | the `Content-Type` header is not `application/json` |
| `429 Too Many Requests` | too many refused tokens or codes from your address; retry after the seconds of `Retry-After` |

## Without the command line

`/sign` of the root CA, or `/NAME/sign` of the issuing CA `NAME`, is a form: paste the CSR,
choose the type, enter the token or a setup code, and the certificate is downloaded as a PEM
file. A setup code signs this one certificate only; a refused request leaves it usable.
