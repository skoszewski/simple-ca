# Changelog

## 1.3.0

update: simple-ca and simple-ca-mini group their commands under ca, cert, crl and token, a Dockerfile builds an image of simple-ca, and the documentation is in docs/.

- The commands of `simple-ca` are `simple-ca GROUP COMMAND`, and the old names are refused:
  `make-ca` is `ca create`, `info` is `ca show` for a CA and `cert show FILE` for a file,
  `make-cert` is `cert create`, `sign` is `cert sign`, `make-pfx` is `cert pfx`, `revoke-cert`
  is `cert revoke`, `list` is `cert list`, `make-crl` is `crl create`, and `make-token`,
  `list-tokens`, `revoke-token` and `purge-tokens` are `token create`, `token list`,
  `token revoke` and `token purge`; `serve` stays.
- `simple-ca GROUP` and `simple-ca GROUP -h` list the commands of a group.
- `simple-ca-mini.py` has `ca create`, `cert create`, `cert pfx` and `serve`, in place of
  `make-ca`, `make-cert` and `make-pfx`.
- `systemd/simple-ca-crl.service` runs `simple-ca crl create --all`; an installed copy of the
  unit is replaced with this one.
- `Dockerfile` builds an image of `simple-ca` on distroless, run as a non-root user, with the CA
  directory `/data` on a volume; it runs `serve` on port 8080 by default.
- The README holds the overview, installation and a quick start; the guides are in `docs/`:
  `usage.md`, `directory-layout.md`, `configuration.md`, `serve.md`, `acme.md`,
  `signing-api.md`, `examples.md` (the former `examples/README.md`), `systemd.md`, `docker.md`,
  `simple-ca-mini.md` and `development.md`.

## 1.2.0

feature: serve signs certificate signing requests at /api/sign and on the /sign page for JWT tokens made with make-token.

- `serve` signs a CSR sent as JSON in a `POST` to `/api/sign` (root CA) or `/NAME/api/sign`
  (issuing CA `NAME`), authenticated by a bearer token of that CA, and returns the certificate
  and its chain as JSON; the certificate is recorded in `index.txt`.
- A token allows certificate types and domains: the CN, DNS names and email domains of the
  request must be a domain of the token or below one; other subject attributes and other SANs
  are refused.
- `make-token` creates a token, a JWT signed with the CA key, valid for `--valid`, one hour by
  default, and records it in `tokens-db.json` of the CA directory; `list-tokens` lists the tokens
  and `revoke-token` revokes one by removing it from `tokens-db.json`.
- `purge-tokens` removes the expired tokens from `tokens-db.json`; `serve` removes those of all
  its CAs when it starts and every 5 minutes.
- The commands and `serve` change `tokens-db.json` under the lock file `tokens-db.json.lock`.
- `/sign` and `/NAME/sign` are a form that takes a pasted CSR, a certificate type and a token,
  and downloads the signed certificate as `NAME_cert.pem`; for a CA without tokens or without
  its key, the page says so in place of the form.
- The index page shows the signing API URL of each CA with tokens, and links to its form.
- `examples/` holds clients of the signing API in Python, Node.js, Go and the shell, which make
  an EC P-256 key and a request and write the key, the certificate and its chain; they read the
  token from `SIMPLE_CA_TOKEN` or from the file `SIMPLE_CA_TOKEN_FILE` names.
- `/NAME` and `/NAME/` of an issuing CA redirect to its section of the index page, `/#NAME`,
  instead of `404 Not Found`.

## 1.1.0

feature: simple-ca-mini.py, a Python 3 version of simple-ca driving the openssl command.

- `simple-ca-mini.py` creates root and issuing CAs (`make-ca`), server, user and none
  certificates (`make-cert`) and PKCS#12 bundles (`make-pfx`) in the directory layout of
  `simple-ca`, using the Python standard library and `openssl`.
- `simple-ca-mini.py serve` serves the CA certificates, as PEM and DER, and the CA bundle over
  HTTP, with an index page of the CAs.
- `systemd/simple-ca-mini.service` runs `simple-ca-mini serve` for a CA in `/etc/simple-ca`.
- `docs/simple-ca-mini.md` describes Simple CA Mini, and the README points to it.

## 1.0.3

fix: make-cert and sign write safe certificate file names, and release.mjs publishes with --push only.

- `make-cert` names the files of a user certificate after its whole CN, and replaces each run of
  characters other than letters, digits, `-` and `_` with one `_`: `Alice Example` is written as
  `Alice_Example_cert.pem`; a CN that gives no file name, such as `...`, is refused.
- `sign` names the certificate after the request file by the same rule: `my web.v2.csr` is
  written as `my_web_v2_cert.pem`; a request file that gives no name, such as `+.csr`, is refused.
- `release.mjs` only commits the newest entry, with its summary line as the message, which marks
  the entry as released; the next change needs a new entry.
- `release.mjs --push` tags `dev`, moves `main` and pushes `dev`, `main` and the tag; the release
  notes are the entries since the last tagged one. `--no-push` and `-m` are gone.

## 1.0.2

fix: the releases have no Debian packages, and the release workflow runs no tests.

- The Debian packages are dropped: the releases hold the executables alone, and
  `./build.mjs package` is gone.
- The release workflow checks the formatting and runs `go vet`, without running the tests.

## 1.0.1

fix: release.mjs no longer runs the build and the tests.

- `release.mjs` commits, tags and pushes without running `build.mjs check`; the release workflow
  checks the sources.

## 1.0.0

feature: initial release

- `make-ca` creates a root CA or an issuing CA, each with an empty first CRL; `--write-conf`
  writes an `openssl ca` configuration.
- `make-cert` issues server, user and none certificates, with hostname, IP, email and numeric
  OID SANs; `--ku` and `--eku` add key usages and extended key usages to those of the type.
- `sign` signs a CSR, copying only its subject and SANs, after confirmation or with `--force`.
- `make-pfx` writes a PKCS#12 bundle encrypted with AES-256.
- `revoke-cert` and `make-crl` revoke certificates, with an optional `--reason`, and write CRLs
  with the reason codes; `make-crl --all` writes the CRLs of a root CA and all its issuing CAs.
- `info` shows a CA or the certificates of a file, and `list` the certificates a CA issued.
- `serve` serves the CA certificates, CRLs and the CA bundle, as PEM and P7B, over HTTP or HTTPS,
  with an index page of the CAs.
- `serve` is an ACME server for each CA, with the http-01 and dns-01 challenges, for the names
  under `acme.domains` of `simple-ca.json`.
- `simple-ca.json` holds the publish base URL for AIA and CRL Distribution Point extensions,
  default validity periods, and certificate types.
- The certificates are recorded in an OpenSSL-compatible `index.txt`, shared with `openssl ca`.
- systemd units for `serve` and for a daily `make-crl` of every CA in `/etc/simple-ca`.
- Release builds for Linux, macOS and Windows on amd64 and arm64, and Debian packages for amd64
  and arm64.
