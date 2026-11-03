# serve

Serves the certificates and CRLs of the root CA of the CA directory, and of all its issuing CAs,
over HTTP, until it is stopped with Ctrl-C. `--address` is the address of the interface it
listens on, `127.0.0.1` by default and `0.0.0.0` for all interfaces (`::` also works), and
`--port` the TCP port, 8080 by default. With `--tls-cert` and `--tls-key`, PEM files of a
certificate chain and its key, it serves HTTPS instead, as [ACME](acme.md) clients require; the
certificate can be one of the CA itself. Without them, `SIMPLE_CA_TLS_CERT` and
`SIMPLE_CA_TLS_KEY` name the two files; either way, the two are given together. With `--docs`,
it also shows the guides of `simple-ca`, the files of `docs/`, at `/docs/`.

With `--webui`, it also serves the [token page](signing-api.md#token-page) at `/tokens/` and the
[certificate page](usage.md#certificate-page) at `/certificates/`, linked from the index page.
They ask for a token with the scope `tokens` or `certs`. Over plain HTTP, the tokens cross the
network in clear, which `serve` mentions at start for an address other than a loopback one;
`--tls-cert` and `--tls-key` serve the pages over HTTPS where that matters. The names `help`, `docs`, `tokens` and `certificates` cannot be issuing CA names,
because the pages use those paths.

Behind a reverse proxy, `--trusted-proxy` (an address or a prefix; it may be specified multiple
times) names the proxies whose `X-Forwarded-For` header gives the client of a request to the
[signing API](signing-api.md) and the token and certificate pages, whose tokens can be limited to
client addresses; without it, `serve.trusted_proxies` of [simple-ca.json](configuration.md) does.
For a request from a trusted proxy, the client is the last address of `X-Forwarded-For` that is
not a trusted proxy, so an address a client puts in the header itself is not taken. The header
of any other peer is not read, and without trusted proxies the client is always the address the
request comes from.

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
| `/NAME`, `/NAME/` | a redirect (`302 Found`) to `/#NAME`, the index page with the dialog of the issuing CA `NAME` | |
| `/acme/directory` | the ACME directory of the root CA, see [ACME](acme.md) | `application/json` |
| `/NAME/acme/directory` | the ACME directory of the issuing CA `NAME` | `application/json` |
| `/api/sign` | the [signing API](signing-api.md) of the root CA, `POST` | `application/json` |
| `/NAME/api/sign` | the signing API of the issuing CA `NAME`, `POST` | `application/json` |
| `/sign` | the [signing form](signing-api.md#signing-form) of the root CA | `text/html` |
| `/NAME/sign` | the signing form of the issuing CA `NAME` | `text/html` |
| `/help/` | the help of the signing API for its clients | `text/html` |
| `/help` | a redirect (`307 Temporary Redirect`) to `/help/` | |
| `/docs/` | with `--docs`, the guides of `simple-ca`, from `usage.md` | `text/html` |
| `/docs` | with `--docs`, a redirect (`307 Temporary Redirect`) to `/docs/` | |

The index page lists the root CA and all its issuing CAs, also when `--ca-dir` is an issuing CA,
each with its name, the CN of its subject, or the whole subject without one, whose popup lists
the attributes of the subject, its role, Root CA or Subordinate CA, and its expiry, with the days
left, marked when fewer than 30 are left, and a link to its signing form when it signs requests.
The Info button of a CA opens a dialog of its subject, issuer, serial number, validity period, key
and SHA-256 fingerprint, its current CRL, with
its number, the count of revoked certificates and its next update, marked when overdue, the URLs
of its ACME directory and signing API, and links to its certificate and CRL, in DER and PEM;
`/#NAME` opens the dialog of the issuing CA `NAME`. The CA bundle is offered at the top of the
page, above the CAs, as P7B, which Windows opens and imports with all its certificates, and as
PEM. The
page and the signing forms follow the light or dark theme of the browser. They are styled with
the browser build of Tailwind CSS 4.3.3, embedded in the executable and served at
`/assets/tailwindcss-browser-4.3.3.js`; the index page opens its dialogs with the script
`/assets/webui/index.js`, and the signing forms choose the certificate type with the scripts
`/assets/webui/picker.js` and `/assets/webui/sign.js`, so the pages load nothing from
other sites.

The files are read on each request, so a CRL written by `crl create` is served at once; a file that
does not exist is `404 Not Found`. No other file is served. Each
request is logged to the standard error.

`/help/` shows the clients of the [signing API](signing-api.md) how to request a certificate with
`request-cert`, step by step with `openssl`, `curl` and `jq`, or with the signing form:
`help/index.md`, embedded in the
executable, as a page drawn by the `render` package of
[serve-markdown](https://github.com/skoszewski/serve-markdown), with an outline of its headings;
the index page and the signing forms link to it. The page's browser files are those of the
serve-markdown release `go.mod` names, which the release builds and the `Dockerfile` embed. An
executable built without them, as `go install` builds it, has no `/help/` page: the route is
`404 Not Found` and nothing links to it.

With `--docs`, `/docs/` shows the guides of `simple-ca`, the files of `docs/` embedded in the
executable, drawn the same way, with a menu of the guides and an outline of the headings, and
the index page links to them as "Documentation"; `/docs/` opens `usage.md`. An executable built
without the page's browser files refuses `--docs`.

```sh
simple-ca serve --ca-dir /etc/simple-ca --docs
```

The URLs are those `--ca-url` writes into the certificates, so with the base URL set
to the address of the server, the AIA and CRL Distribution Point URLs of the certificates are
served:

```sh
simple-ca ca create --ca-dir /tmp/ca --ca-url http://pki.example.com:8080 "My Root CA"
simple-ca serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8080
```
