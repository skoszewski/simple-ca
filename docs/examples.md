# Signing API clients

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
SIMPLE_CA_TOKEN=TOKEN request-cert API_URL CN [DNS_NAME ...]
SIMPLE_CA_TOKEN_FILE=FILE request-cert API_URL CN [DNS_NAME ...]
```

- `API_URL` is the API of a CA, `https://pki.example.com/api/sign` for the root CA or
  `https://pki.example.com/NAME/api/sign` for the issuing CA `NAME`.
- `SIMPLE_CA_TOKEN` is a token of `simple-ca token create` for that CA, or `SIMPLE_CA_TOKEN_FILE`
  names a file holding it, such as a systemd credential or a container secret; the whitespace
  around the token in the file is left out. One of them is set, not both, and an empty file is an
  error. The token is read from the environment or the file, so it does not show in the process
  list; the shell version hands it to `curl` in a file of its private temporary directory.
- `SIMPLE_CA_TYPE` is the certificate type; without it, the first type of the token.
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
SIMPLE_CA_TOKEN=TOKEN request-cert [options] API_URL CN [DNS_NAME ...]
request-cert --token-file FILE [options] API_URL CN [DNS_NAME ...]
```

- `--token-file FILE` - the file holding the token, `SIMPLE_CA_TOKEN_FILE` by default. The token
  itself is read only from `SIMPLE_CA_TOKEN` or the file, never from the command line.
- `--type TYPE` - the certificate type, `SIMPLE_CA_TYPE` by default.
- `--out-dir DIR` - the directory of the three files, the working directory by default.
- `--version` prints the version, and `-h` the usage. Wrong arguments print the usage and exit
  with 2.

## Examples

```sh
(umask 077; simple-ca token create --ca-dir /etc/simple-ca/servers --domain example.com deploy \
  > deploy.token)
export SIMPLE_CA_TOKEN_FILE=deploy.token

examples/request_cert.py https://pki.example.com:8443/servers/api/sign web.example.com www.example.com
examples/request-cert.mjs https://pki.example.com:8443/servers/api/sign api.example.com
examples/request-cert.sh https://pki.example.com:8443/servers/api/sign '*.apps.example.com'
go run ./cmd/request-cert --out-dir /etc/ssl/db https://pki.example.com:8443/servers/api/sign db.example.com
```

The commands run from the repository root. `./build.mjs` builds the Go program as `request-cert`
beside `simple-ca`, `request-cert.exe` on Windows, and `./build.mjs build <goos>/<goarch>` as
`request-cert-<goos>-<goarch>` (see [Development](development.md)). The release archives of
`simple-ca` hold it too. With Go installed, it is also installed on its own:

```sh
go install github.com/skoszewski/simple-ca/cmd/request-cert@latest
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
