# Simple CA

[![build](https://github.com/skoszewski/simple-ca/actions/workflows/build.yml/badge.svg)](https://github.com/skoszewski/simple-ca/actions/workflows/build.yml)

`simple-ca` creates and manages a simple Certificate Authority for testing and development: a
root CA, issuing CAs, server and user certificates, PKCS#12 bundles, revocation and CRLs. It is a
single executable using Go's native cryptography, and runs no other program. `simple-ca serve`
publishes the CA certificates and CRLs over HTTP, and is an ACME server and a certificate signing
API for the CAs.

![The index page of simple-ca serve, listing a root CA and its servers subordinate CA](demo_ca.png)

The index page of `simple-ca serve` for a root CA and one subordinate CA, `servers`, which signs
requests.

## Installation

Download the archive for your platform from the
[releases](https://github.com/skoszewski/simple-ca/releases) and put `simple-ca` on your `PATH`;
the archive also holds `request-cert`, the Go client of the signing API.
With Go installed:

```sh
go install github.com/skoszewski/simple-ca@latest
```

An executable installed with `go install` has no `/help/` page of `serve`; the releases have it.

## Quick start

```sh
mkdir -p /tmp/ca
simple-ca ca create --ca-dir /tmp/ca "My Root CA"
simple-ca cert create --ca-dir /tmp/ca web.example.com
openssl verify -CAfile /tmp/ca/ca_bundle.pem /tmp/ca/web_cert.pem
simple-ca serve --ca-dir /tmp/ca
```

The commands are in groups, `ca`, `cert`, `crl` and `token`, and `serve` is a command of its own;
`simple-ca -h` lists them.

## Documentation

- [Usage](docs/usage.md) - the commands: CAs, certificates, signing requests, PFX bundles,
  revocation and CRLs.
- [Directory layout](docs/directory-layout.md) - the files of a CA, their names, and the
  certificate database shared with `openssl ca`.
- [Configuration](docs/configuration.md) - `simple-ca.json`: publish URL, default validity
  periods, certificate types and ACME.
- [serve](docs/serve.md) - the HTTP server of the CA certificates, CRLs and the index page.
- [ACME](docs/acme.md) - the ACME server of `serve`.
- [Signing API](docs/signing-api.md) - tokens, the `/api/sign` API and the signing form.
- [Signing API clients](docs/examples.md) - the clients in `examples/` and `cmd/request-cert/`,
  in Python, Node.js, Go and the shell.
- [Trust stores](docs/trust.md) - `simple-ca-trust`, which adds the CAs to the trust store of
  Windows, macOS or Linux.
- [systemd](docs/systemd.md) - units for `serve` and the daily CRLs.
- [Docker](docs/docker.md) - the container image.
- [Simple CA Mini](docs/simple-ca-mini.md) - `simple-ca-mini.py`, a single Python 3 script that
  drives the `openssl` command, for the CAs, certificates, PFX bundles and `serve`.
- [Development](docs/development.md) - building, testing and releasing.

The documentation reads in a browser with
[serve-markdown](https://github.com/skoszewski/serve-markdown), also by the author of
`simple-ca`.

## Licence

MIT, see [LICENSE](LICENSE).

`assets/tailwindcss-browser-4.3.3.js` is `dist/index.global.js` of the npm package
`@tailwindcss/browser` 4.3.3, copyright Tailwind Labs, Inc., under the MIT licence of
[assets/tailwindcss-browser-LICENSE](assets/tailwindcss-browser-LICENSE).

The browser files of the `/help/` page, downloaded into `assets/markdown/`, are those of
serve-markdown, bundled with the libraries its `LICENSES.md` names, each under its own licence.
