---
title: Requesting a certificate
---

This CA signs certificate signing requests (CSRs) sent with a token from its administrator. The
token says which names and addresses it may sign, and may be valid for a short time only.

## What you need

- The URL of the signing API of the CA: `/api/sign` of the root CA, or `/NAME/api/sign` of the
  issuing CA `NAME`. The index page of this server lists the URL of each CA that signs requests.
- A token, given to you by the administrator of the CA.
- `openssl`, `curl` and `jq`.

The examples below use these shell variables; replace the URL and the file with your own:

```sh
API=http://pki.example.com:8080/servers/api/sign
TOKEN=$(cat token.txt)
```

## Create a key and a request

A request for a server certificate holds the name of the server as its CN and as a DNS name, and
may hold more DNS names and IP addresses. The token must allow every one of them.

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout web_key.pem -subj /CN=web.example.com \
  -addext subjectAltName=DNS:web.example.com,DNS:www.example.com,IP:192.0.2.10 \
  -out web.csr
```

The subject holds a CN and, for a user certificate, an `emailAddress`, and nothing else.

## Send the request

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

## Save the certificate

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

A refused request is answered with `{"error": "..."}`, which `jq -r .error web.json` prints:

| Status | Meaning |
|---|---|
| `400 Bad Request` | the body is not JSON with `csr` and `type`, or the CSR does not read |
| `401 Unauthorized` | the token is missing, expired, revoked, or of another CA |
| `403 Forbidden` | the token does not allow a name, an address or the type, or your address |
| `404 Not Found` | the CA does not sign requests here |
| `415 Unsupported Media Type` | the `Content-Type` header is not `application/json` |

## Without the command line

`/sign` of the root CA, or `/NAME/sign` of the issuing CA `NAME`, is a form: paste the CSR,
choose the type, enter the token, and the certificate is downloaded as a PEM file.
