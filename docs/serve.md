---
title: serve
---

Serves the certificates and CRLs of the root CA of the CA directory, and of all its issuing CAs,
over HTTP, until it is stopped with Ctrl-C. `--address` is the address of the interface it
listens on, `127.0.0.1` by default and `0.0.0.0` for all interfaces (`::` also works), and
`--port` the TCP port, 8080 by default. With `--tls-cert` and `--tls-key`, PEM files of a
certificate chain and its key, it serves HTTPS instead, as [ACME](acme.md) clients require; the
certificate can be one of the CA itself. Without them, `SIMPLE_CA_TLS_CERT` and
`SIMPLE_CA_TLS_KEY` name the two files; either way, the two are given together. When the key or
a CA key is [encrypted](usage.md#encrypted-private-keys), `serve` gets the passphrase at start,
from `SIMPLE_CA_KEY_PASSWORD` or `SIMPLE_CA_KEY_PASSWORD_FILE`, else at the prompt of its
terminal, and does not start without it. With `--docs`,
it also shows the guides of `simple-ca`, the files of `docs/`, at `/docs/`.

With `--webui`, it also serves the [token page](signing-api.md#token-page) at `/tokens/`, the
[certificate page](usage.md#certificate-page) at `/certificates/` and the
[audit page](audit.md#the-audit-page) at `/audit/`. They ask for a token with the scope `tokens`,
`certs` or `audit`, or for the [OIDC sign-in](oidc.md) when `simple-ca.json` sets it up. Over
plain HTTP, the tokens cross the network in clear, which `serve` mentions at start for an address
other than a loopback one; `--tls-cert` and `--tls-key` serve the pages over HTTPS where that
matters. The names `help`, `docs`, `tokens`, `certificates`, `audit`, `downloads` and `apt` cannot
be issuing CA names, because the pages use those paths.

The index page draws the links of its header from `/api/links`. A request without a token gets
those of the public pages: "Set up a token", "Describe a token", and "Downloads" and "Apt" when
they are served. A request with a valid token of the root CA or an issuing CA as its bearer
token, used from a client the token allows, also gets "Tokens", "Certificates" and "Audit log"
with `--webui`, and the name of the token. A refused token is answered as the pages answer it,
and counts as a [refused credential](signing-api.md#refused-credentials). With `--webui`, the
index page has a Login button where it shows who is signed in. It opens the login dialog of the
pages:

- **Login with token:** takes a token, or a setup code, which is exchanged and its token shown
  once.
- **Sign in with LABEL:** the OIDC sign-in, when it is set up.
- **Cancel:** closes the dialog.

The token is kept for the browser tab, which the pages share, and Sign out forgets it.

With `--downloads DIR`, it lists the files of `DIR` for the clients at `/downloads/`, see
[Downloads](#downloads), and with `--packages DIR` it serves the apt repository in `DIR` at
`/apt/`, see [apt repository](#apt-repository). Both are public, like the files of the CAs.

`serve` logs in one format, the lines of key=value pairs of its [audit records](audit.md), each
starting with `time=` and `event=`: the start, with the version, the root CA, the origin and
whether requests are logged, a `serve.page` record for each page with its URL, warnings, errors,
the audit records and, with `--request-log` or `serve.request_log` of
[simple-ca.json](configuration.md), an `http.request` record of each request with its method,
path, status and client. The log goes to the systemd journal when `serve` runs under systemd,
else to the standard error; the audit records also go to the audit log.

```text
time=2026-11-03T21:07:02.529Z event=serve.start version=v1.9.0 root=/etc/simple-ca origin=http://127.0.0.1:8080 request_log=true
time=2026-11-03T21:07:02.529Z event=serve.page page=index url=http://127.0.0.1:8080/
time=2026-11-03T21:07:03.565Z event=http.request method=GET path=/ca_cert.pem status=200 client=127.0.0.1
```

Behind a reverse proxy, `--trusted-proxy` (an address or a prefix; it may be specified multiple
times) names the proxies whose `X-Forwarded-For` header gives the client of a request: the client
that the tokens of the [signing API](signing-api.md) and of the pages and the setup codes are
limited to, that [ACME](acme.md) and the [OIDC sign-in](oidc.md) see, that refused credentials
are [counted for](signing-api.md#refused-credentials), and that the log and the audit records
name; without it, `serve.trusted_proxies` of [simple-ca.json](configuration.md) does.
For a request from a trusted proxy, the client is the last address of `X-Forwarded-For` that is
not a trusted proxy, so an address a client puts in the header itself is not taken. The header
of any other peer is not read, and without trusted proxies the client is always the address the
request comes from.

The `X-Forwarded-Proto` header of a trusted proxy gives the scheme the client used, so that a
proxy that terminates HTTPS and forwards plain HTTP to `serve` gets `https://` URLs on the index
page, in the [ACME](acme.md) directory and on the apt page: its last value, `http` or `https`,
is taken. Without it, and for any other peer, the scheme is `https` when `serve` itself serves
HTTPS, and `http` otherwise. nginx sends the header with
`proxy_set_header X-Forwarded-Proto $scheme;`.

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
| `/api/sign` | the [signing API](signing-api.md) of the root CA, `POST`; `GET` is `405 Method Not Allowed`, with `Allow: POST` | `application/json` |
| `/NAME/api/sign` | the signing API of the issuing CA `NAME`, `POST` | `application/json` |
| `/sign` | the [signing form](signing-api.md#signing-form) of the root CA | `text/html` |
| `/NAME/sign` | the signing form of the issuing CA `NAME` | `text/html` |
| `/token-setup` | the exchange of a [setup code](signing-api.md#setup-code-exchange) for its token | `text/html` |
| `/api/token-setup` | the exchange of a setup code, `POST` | `application/json` |
| `/api/links` | the links of the index page: the public pages, and with a valid bearer token also the pages of `--webui`, with the name of the token | `application/json` |
| `/token-describe` | the attributes of a token pasted into it, see [Describe a token](signing-api.md#describe-a-token) | `text/html` |
| `/api/federation-token` | a JWT of the token type of a token of the root CA with the scope `federate`, `POST`, see [Federation tokens](signing-api.md#federation-tokens) | `application/json` |
| `/NAME/api/federation-token` | the same for a token of the issuing CA `NAME` | `application/json` |
| `/.well-known/openid-configuration` | the OpenID Connect discovery document of the tokens of the root CA, `404 Not Found` without an issuer, see [Workload identity federation](workload-identity.md) | `application/json` |
| `/jwks.json` | the JSON Web Key Set verifying the tokens of the root CA, `404 Not Found` without an issuer | `application/json` |
| `/NAME/.well-known/openid-configuration`, `/NAME/jwks.json` | the same of the issuing CA `NAME` | `application/json` |
| `/api/oidc` | the settings of the [OIDC sign-in](oidc.md), `404 Not Found` when it is off, `502 Bad Gateway` when the discovery document of the provider cannot be read | `application/json` |
| `/api/oidc-token` | the exchange of an ID token for the token of its user, `POST` | `application/json` |
| `/oidc-callback` | the page the OIDC provider sends the browser back to, its redirect URI | `text/html` |
| `/help/` | the help of the signing API for its clients | `text/html` |
| `/help` | a redirect (`307 Temporary Redirect`) to `/help/` | |
| `/docs/` | with `--docs`, the guides of `simple-ca`, from `usage.md` | `text/html` |
| `/docs` | with `--docs`, a redirect (`307 Temporary Redirect`) to `/docs/` | |
| `/downloads/` | with `--downloads`, the page of the files whose SHA-256 matches their sum file | `text/html` |
| `/downloads/FILE` | a file of the page, as an attachment | `application/octet-stream` |
| `/downloads/FILE.sha256` | the sum file of a file of the page | `text/plain` |
| `/downloads` | with `--downloads`, a redirect (`307 Temporary Redirect`) to `/downloads/` | |
| `/apt/` | with `--packages`, the page telling how to set up the apt repository | `text/html` |
| `/apt/...` | with `--packages`, the files and the subdirectory listings of the apt repository | |

The index page lists the root CA and all its issuing CAs, also when `--ca-dir` is an issuing CA,
each with its name, the CN of its subject, or the whole subject without one, whose popup lists
the attributes of the subject, its role, Root CA or Subordinate CA, and its expiry, with the days
left, marked when fewer than 30 are left, and in the Sign Form Link column the URL of its
[signing form](signing-api.md#signing-form) when its key is on the server, `-` without it; the
copy button after the URL copies it to the clipboard.
The Info button of a CA opens a dialog of its subject, issuer, serial number, validity period, key
and SHA-256 fingerprint, its current CRL, with
its number, the count of revoked certificates and its next update, marked when overdue, the URLs
of its ACME directory and signing API, and links to its certificate and CRL, in DER and PEM;
`/#NAME` opens the dialog of the issuing CA `NAME`. The CA bundle is offered at the top of the
page, above the CAs, as P7B, which Windows opens and imports with all its certificates, and as
PEM.

Every page of `serve` follows the light or dark theme of the browser, or the one chosen with the
theme button below the page. Its icon shows the choice, a screen for the theme of the system, a
sun for light and a moon for dark; a click goes to the next, and the browser keeps the choice for
all the pages. The
pages are styled with the browser build of Tailwind CSS 4.3.3, embedded in the executable and
served at `/assets/tailwindcss-browser-4.3.3.js`; `/assets/webui/theme.js` sets the theme,
`/assets/webui/picker.js` draws the dropdown choosers, the index page opens its dialogs with the
script `/assets/webui/index.js`, the copy buttons of the index and downloads pages copy with
`/assets/webui/copy.js`, the signing forms choose the certificate type with
`/assets/webui/sign.js`, and `/token-setup` shows the token with `/assets/webui/setup.js`, so the
pages load nothing from other sites. The
[OIDC sign-in](oidc.md), `/assets/webui/oidc.js`, sends the browser to the provider, and the page
`/oidc-callback` redeems the code at the token endpoint of the provider.

The files are read on each request, so a CRL written by `crl create` is served at once; a file that
does not exist is `404 Not Found`. No other file is served, but those of `--downloads` and
`--packages`.

`/help/` shows the clients of the [signing API](signing-api.md) how to request a certificate with
`request-cert`, step by step with `openssl`, `curl` and `jq`, or with the signing form:
`help/index.md`, embedded in the
executable, as a page drawn by the `render` package of
[serve-markdown](https://github.com/skoszewski/serve-markdown), with an outline of its headings;
the index page, the token, certificate and audit pages, the signing forms and `/token-setup` link
to it as "Signing help" below the page, beside the version and the theme button, opening it in a
new tab. The page's
browser files are those of the
serve-markdown release `go.mod` names, which the release builds and the `Dockerfile` embed. An
executable built without them, as `go install` builds it, has no `/help/` page: the route is
`404 Not Found` and nothing links to it.

With `--docs`, `/docs/` shows the guides of `simple-ca`, the files of `docs/` embedded in the
executable, drawn the same way, with a menu of the guides and an outline of the headings; the
same pages as for `/help/` link to them as "Documentation" below the page, beside "Signing help",
also in a new tab, and `/docs/` opens `usage.md`. An executable built
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

## Downloads

`/downloads/` lists the files of the `--downloads` directory, with the size and the SHA-256 of
each; the name links to the file, the SHA-256 to its sum file, and the copy button after the
SHA-256 copies it to the clipboard. A file is listed when `NAME.sha256` beside it holds the line
`sha256sum NAME` writes, with the SHA-256 of the file and its name; a file without it, or whose
SHA-256 does not match, is left out, with a `serve.warning` record for the mismatch, and its
URL is `404 Not Found`. Subdirectories and files whose names start with `.` are not listed, and
a symbolic link is followed only within the directory. The directory is read on each request,
and a file is hashed again after it or its sum file changes. The index page links to
`/downloads/` as "Downloads" in its header, and every page below the page.

```sh
DOWNLOADS=/srv/simple-ca/downloads
NAME=request-cert-linux-amd64

cp "bin/$NAME" "$DOWNLOADS/"
(cd "$DOWNLOADS" && sha256sum "$NAME" > "$NAME.sha256")
simple-ca serve --ca-dir /etc/simple-ca --downloads "$DOWNLOADS"
```

In a checkout of simple-ca, `./build.mjs sums` writes the sum files of a directory, of all its
files or of those matching a glob, see [Development](development.md#building):

```sh
DOWNLOADS=/srv/simple-ca/downloads
GLOB='request-cert-*'

./build.mjs sums "$DOWNLOADS" "$GLOB"
```

A client checks a file it downloaded with its sum file:

```sh
BASE_URL=https://pki.example.com:8443
NAME=request-cert-linux-amd64

curl -fsSLO "$BASE_URL/downloads/$NAME"
curl -fsSLO "$BASE_URL/downloads/$NAME.sha256"
sha256sum -c "$NAME.sha256"
```

## apt repository

`/apt/` serves the files of the `--packages` directory as they are, and a listing of each of its
subdirectories. `serve` builds no index; `./build.mjs apt` builds a signed flat repository of the
Debian packages, see [Development](development.md#building), whose files are copied to the
directory:

```sh
PACKAGES=/srv/simple-ca/apt

./build.mjs apt --key apt-signing-key.asc
rsync -a --delete apt/ "pki.example.com:$PACKAGES/"
simple-ca serve --ca-dir /etc/simple-ca --packages "$PACKAGES"
```

`/apt/` itself is the apt page, built into `serve`, which tells the admin of a Debian or Ubuntu
machine how to set up the repository: the commands below with `BASE_URL` set to the address the
page was opened at, a copy button for them, and the packages, the names of the `Package:` lines
of `Packages`. It warns when the repository has no `key.asc`, and when the page is served over
plain HTTP, which behind a proxy that terminates HTTPS needs its `X-Forwarded-Proto`, as
described above. The index page links to it as "Apt" in its header, beside "Downloads", and every
page below the page.

A client trusts the key of the repository, `key.asc`, and adds the repository as a flat one,
whose suite is `./`:

```sh
BASE_URL=https://pki.example.com:8443

sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL -o /etc/apt/keyrings/simple-ca.asc "$BASE_URL/apt/key.asc"
echo "deb [signed-by=/etc/apt/keyrings/simple-ca.asc] $BASE_URL/apt ./" |
  sudo tee /etc/apt/sources.list.d/simple-ca.list
sudo apt-get update
sudo apt-get install simple-ca-lite
```

The key is fetched over HTTPS from a server the client trusts; a key fetched over plain HTTP
can be replaced on the way.
