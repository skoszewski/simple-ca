---
title: Signing API clients
---

Each of these programs requests a server certificate from the [signing API](signing-api.md) of
`simple-ca serve`, the same way in Python, Node.js, Go and the shell; the Go one is a command of
the module, in `cmd/request-cert/`, and the others are in `examples/`:

| File | Language | Requirements |
|---|---|---|
| `examples/request_cert.py` | Python 3 | the `openssl` command |
| `examples/request-cert.mjs` | Node.js 18 or later | the `openssl` command |
| `cmd/request-cert/main.go` | Go | none, the standard library |
| `examples/request-cert.sh` | Bash | `openssl`, `curl` and `jq` |

```text
SIMPLE_CA_TOKEN=TOKEN request-cert CA_URL CN [DNS_NAME ...]
SIMPLE_CA_TOKEN_FILE=FILE request-cert CA_URL CN [DNS_NAME ...]
[SIMPLE_CA_TOKEN_FILE=NEW_FILE] request-cert --setup-code CODE CA_URL CN [DNS_NAME ...]
```

- `CA_URL` is the URL of a CA, `https://pki.example.com` for the root CA or
  `https://pki.example.com/NAME` for the issuing CA `NAME`; the program adds `/api/sign`, and takes
  a URL that already ends in it too.
- `SIMPLE_CA_TOKEN` is a token of `simple-ca token create` for that CA, or `SIMPLE_CA_TOKEN_FILE`
  names a file holding it, such as a systemd credential or a container secret; the whitespace
  around the token in the file is left out. One of them is set, not both, and an empty file is an
  error. The token is read from the environment or the file, so it does not show in the process
  list; the shell version hands it to `curl` in a file of its private temporary directory.
- `--setup-code CODE`, the first argument, is a
  [one-time setup code](signing-api.md#one-time-setup-codes) in place of the token: the program
  exchanges it first at `/api/token-setup` of the server of `CA_URL`, then requests the
  certificate with the token. With `SIMPLE_CA_TOKEN_FILE` also set, the token is written to that
  file, mode 0600, for later requests; the file must not exist yet, which is checked before the
  code is used. It is not given together with `SIMPLE_CA_TOKEN`.
- `SIMPLE_CA_TYPE` is the certificate type, `server` without it, and `SIMPLE_CA_DAYS` the validity
  in days, 365 without it, as `cert sign` defaults them; the signing API takes no defaults, so the
  programs send them. The CA keeps its copy of the certificate under the name the files written
  here have, the CN, or `wildcard.NAME` for `*.NAME`.
- `CN` is the CN of the certificate and its first DNS name; the `DNS_NAME`s are its other DNS
  names. All of them must be domains of the token or below them.

The program makes an EC P-256 key and a certificate signing request, sends it, and writes, in the
working directory:

- `CN_key.pem` - the key, PKCS#8, mode 0600;
- `CN_cert.pem` - the certificate;
- `CN_chain.pem` - the certificate and, from an issuing CA, the issuing CA certificate.

A wildcard CN `*.NAME` gives the files `wildcard.NAME_...`. The key is written only once the
certificate is signed, and an existing key is never overwritten. A refused request prints the
status and the error of the API, such as
`403 the token does not allow 'web.example.org'`, and exits with 1.

Python, Node.js and the shell make the key and the request with `openssl`, as their standard
libraries cannot make a certificate signing request; Go makes them with `crypto/x509`.

## Options of the Go command

The Go `request-cert` also takes options, each of which replaces its environment variable:

```text
SIMPLE_CA_TOKEN=TOKEN request-cert [options] CA_URL CN [DNS_NAME ...]
request-cert --token-file FILE [options] CA_URL CN [DNS_NAME ...]
request-cert --setup-code CODE [--token-file NEW_FILE] [options] CA_URL CN [DNS_NAME ...]
```

- `--token-file FILE` - the file holding the token, or, with `--setup-code`, the new file the
  token is written to, `SIMPLE_CA_TOKEN_FILE` by default. The token is read only from
  `SIMPLE_CA_TOKEN` or the file, never from the command line.
- `--setup-code CODE` - a one-time setup code, exchanged for the token; with the Go command it may
  come anywhere among the options.
- `--type TYPE` - the certificate type, `SIMPLE_CA_TYPE` by default, else `server`.
- `--days DAYS` - the validity in days, `SIMPLE_CA_DAYS` by default, else 365.
- `--name NAME` - the name of the copy of the certificate the CA keeps, `NAME_cert.pem`; the CN of
  the files written here by default.
- `--out-dir DIR` - the directory of the three files, the working directory by default.
- `--version` prints the version, and `-h` the usage. Wrong arguments print the usage and exit
  with 2.

## Examples

```sh
(umask 077; simple-ca token create --ca-dir /etc/simple-ca/servers --domain example.com deploy \
  > deploy.token)
export SIMPLE_CA_TOKEN_FILE=deploy.token

CA_URL=https://pki.example.com:8443/servers
examples/request_cert.py "$CA_URL" web.example.com www.example.com
examples/request-cert.mjs "$CA_URL" api.example.com
examples/request-cert.sh "$CA_URL" '*.apps.example.com'
go run ./cmd/request-cert --out-dir /etc/ssl/db "$CA_URL" db.example.com
```

With a setup code, the administrator hands out the code of `token create --otc`, and the first
request exchanges it and keeps the token in a new file, which the later requests read:

```sh
simple-ca token create --ca-dir /etc/simple-ca/servers --otc --domain example.com web

CA_URL=https://pki.example.com:8443/servers
CODE=K7QF-M2XA-JP4D-W5ZR
export SIMPLE_CA_TOKEN_FILE=web.token
request-cert --setup-code "$CODE" "$CA_URL" web.example.com
request-cert "$CA_URL" www.example.com
```

The commands run from the repository root. `./build.mjs` builds the Go program as
`build/request-cert` beside `build/simple-ca`, `request-cert.exe` on Windows, and
`./build.mjs build <goos>/<goarch>` as `build/request-cert-<goos>-<goarch>` (see
[Development](development.md)). The release archives of
`simple-ca` hold it too. With Go installed, it is also installed on its own:

```sh
go install github.com/skoszewski/simple-ca/cmd/request-cert@latest
```

## Exchanging a setup code alone

The Go command `token-setup`, in `cmd/token-setup/`, and `examples/token_setup.py`, in Python 3
with its standard library, exchange a
[one-time setup code](signing-api.md#one-time-setup-codes) for its token and print it. `--url`,
or else `SIMPLE_CA_URL`, is the URL of the server, the same for a code of an issuing CA as for one
of the root CA:

```sh
export SIMPLE_CA_URL=https://pki.example.com:8443
CODE=K7QF-M2XA-JP4D-W5ZR
TOKEN=$(token-setup "$CODE")
TOKEN=$(examples/token_setup.py "$CODE")
```

An error goes to the standard error, and the program exits with status 1.

Both leave out a path of the URL, so the URL of a CA such as
`https://pki.example.com:8443/servers` works too. `--token-file`, or else
`SIMPLE_CA_TOKEN_FILE`, makes `token-setup` write the token to that file, mode 0600, in place of
printing it; the file must not exist yet, which is checked before the code is used. `--version`
prints its version.

`./build.mjs` builds it as `build/token-setup` beside `build/simple-ca`, and the release archives
and the container image hold it too. With Go installed, it is also installed on its own:

```sh
go install github.com/skoszewski/simple-ca/cmd/token-setup@latest
```

## HTTPS with the CA's own certificate

When `serve` uses a certificate of the CA itself, the clients must trust the root CA. Each of them
reads a CA file from the environment, without changes to the programs:

| Client | Variable |
|---|---|
| Python (OpenSSL) | `SSL_CERT_FILE=ca_bundle.pem` |
| Node.js | `NODE_EXTRA_CA_CERTS=ca_bundle.pem` |
| Go (Linux and other Unix systems) | `SSL_CERT_FILE=ca_bundle.pem` |
| curl | `CURL_CA_BUNDLE=ca_bundle.pem` |

`ca_bundle.pem` is served at `/ca_bundle.pem`. `SSL_CERT_FILE` replaces the system trust store
for that run, so the bundle must hold every CA the program connects to.
