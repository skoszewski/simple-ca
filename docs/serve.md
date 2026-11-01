# serve

Serves the certificates and CRLs of the root CA of the CA directory, and of all its issuing CAs,
over HTTP, until it is stopped with Ctrl-C. `--address` is the address of the interface it
listens on, `127.0.0.1` by default and `0.0.0.0` for all interfaces (`::` also works), and
`--port` the TCP port, 8080 by default. With `--tls-cert` and `--tls-key`, PEM files of a
certificate chain and its key, it serves HTTPS instead, as [ACME](acme.md) clients require; the
certificate can be one of the CA itself.

Behind a reverse proxy, `--trusted-proxy`, an address or a prefix repeated for more, names the
proxies whose `X-Forwarded-For` header gives the client of a request to the
[signing API](signing-api.md), whose tokens can be limited to client addresses; without it,
`serve.trusted_proxies` of [simple-ca.json](configuration.md) does. For a request from a trusted
proxy, the client is the last address of `X-Forwarded-For` that is not a trusted proxy, so an
address a client puts in the header itself is not taken. The header of any other peer is not
read, and without trusted proxies the client is always the address the request comes from.

```sh
simple-ca serve --ca-dir /etc/simple-ca --trusted-proxy 127.0.0.1
```

| URL | File | Content type |
|---|---|---|
| `/` | an index page of the CAs, with links to their files | `text/html` |
| `/ca_cert.crt` | `ca_cert.pem` of the root CA, as DER | `application/pkix-cert` |
| `/ca_cert.pem` | `ca_cert.pem` of the root CA | `application/x-pem-file` |
| `/crl.crl` | `crl.pem` of the root CA, as DER | `application/pkix-crl` |
| `/crl.pem` | `crl.pem` of the root CA | `application/x-pem-file` |
| `/ca_bundle.pem` | `ca_bundle.pem` | `application/x-pem-file` |
| `/ca_bundle.p7b` | the certificates of `ca_bundle.pem`, as PKCS#7 | `application/x-pkcs7-certificates` |
| `/NAME/...` | the same four files of the issuing CA `NAME` | |
| `/NAME`, `/NAME/` | a redirect (`302 Found`) to `/#NAME`, the issuing CA `NAME` on the index page | |
| `/acme/directory` | the ACME directory of the root CA, see [ACME](acme.md) | `application/json` |
| `/NAME/acme/directory` | the ACME directory of the issuing CA `NAME` | `application/json` |
| `/api/sign` | the [signing API](signing-api.md) of the root CA, `POST` | `application/json` |
| `/NAME/api/sign` | the signing API of the issuing CA `NAME`, `POST` | `application/json` |
| `/sign` | the [signing form](signing-api.md#signing-form) of the root CA | `text/html` |
| `/NAME/sign` | the signing form of the issuing CA `NAME` | `text/html` |

The index page lists the root CA and all its issuing CAs, also when `--ca-dir` is an issuing CA,
each with its subject, issuer, serial number, validity period, days left before it expires,
marked when fewer than 30 are left, key and SHA-256 fingerprint, and its current CRL, with its
number, the count of revoked certificates and its next update, marked when overdue. The CA bundle
is offered at the top of the page, above the CAs, as P7B, which Windows opens and imports with
all its certificates, and as PEM; each CA links to its certificate and CRL, in DER and PEM. The
page is styled with the browser build of Tailwind CSS 4.3.3, embedded in the executable and
served at `/assets/tailwindcss-browser-4.3.3.js`, so the page loads nothing from other sites.

The files are read on each request, so a CRL written by `crl create` is served at once; a file that
does not exist is `404 Not Found`. No other file is served. Each
request is logged to the standard error.

The URLs are those `--ca-url` writes into the certificates, so with the base URL set
to the address of the server, the AIA and CRL Distribution Point URLs of the certificates are
served:

```sh
simple-ca ca create --ca-dir /tmp/ca --ca-url http://pki.example.com:8080 "My Root CA"
simple-ca serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8080
```
