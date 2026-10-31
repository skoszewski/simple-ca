# Changelog

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
