---
title: Simple CA Lite
---

`simple-ca-lite` is the Go program with the certificate commands of `simple-ca` alone: it creates
root and issuing CAs, issues and signs certificates, writes PKCS#12 bundles, revokes certificates,
writes CRLs and encrypts or decrypts the private keys. Its commands are those of `simple-ca`, the
same code, so they take the same options, print the same help and write the same files and audit
records. Like `simple-ca`, it uses Go's native cryptography and runs no other program.

It leaves out everything that is not a certificate command:

- `serve`, and with it the HTTP server of the CA certificates and CRLs, ACME, the signing API,
  the web pages, the OIDC sign-in and the `/help/` and `/docs/` pages;
- the `token` and `audit` groups;
- the session: run without arguments, `simple-ca-lite` prints its usage.

## Installation

The [releases](https://github.com/skoszewski/simple-ca/releases) hold the archive of each
platform, `simple-ca-lite-X.Y.Z-<goos>-<goarch>.tar.gz`, a `.zip` for Windows, with
`simple-ca-lite` alone, which goes on the `PATH`:

```sh
VERSION=1.18.0
PLATFORM=linux-amd64

tar -xzf "simple-ca-lite-$VERSION-$PLATFORM.tar.gz"
sudo install -m 755 simple-ca-lite /usr/local/bin/simple-ca-lite
```

They also hold the Debian package `simple-ca-lite` for amd64 and arm64,
`simple-ca-lite_X.Y.Z-1_<arch>.deb`, which `./build.mjs deb` builds too, as
[Development](development.md#building) describes. It installs `/usr/bin/simple-ca-lite` and this
guide, in `/usr/share/doc/simple-ca-lite/`, and has no systemd units and no system user:

```sh
DEB=simple-ca-lite_1.18.0-1_amd64.deb

sudo dpkg -i "$DEB"
```

## Commands

| Command | Does |
|---|---|
| `ca create` | creates the root CA, or an issuing CA with `--issuing-ca` |
| `ca show` | shows the CA in the CA directory |
| `cert create` | creates a key and a certificate signed by the CA |
| `cert sign` | signs a certificate signing request |
| `cert list` | lists the certificates the CA issued |
| `cert show` | shows the certificates of a file |
| `cert revoke` | marks a certificate revoked |
| `cert pfx` | writes the PKCS#12 bundle of a certificate |
| `crl create` | writes the CRL of the CA, or of every CA with `--all` |
| `key encrypt` | encrypts the private keys of the CA, or of every CA with `--all` |
| `key decrypt` | writes the private keys of the CA unencrypted |

The options, the defaults and the behaviour of each command are those of `simple-ca`, described in
[Usage](usage.md). `simple-ca-lite -h` lists the groups, `simple-ca-lite GROUP -h` the commands of
a group, `simple-ca-lite GROUP COMMAND -h` the options of a command, and
`simple-ca-lite --version` prints the version.

The CA directory is `--ca-dir`, else `SIMPLE_CA_DIR`, else the working directory. The passphrase
of [encrypted private keys](usage.md#encrypted-private-keys) is `SIMPLE_CA_KEY_PASSWORD` or the
content of the file `SIMPLE_CA_KEY_PASSWORD_FILE` names, and setting both is an error; with
neither, it is asked for on a terminal.

A root CA and an issuing CA with certificates:

```sh
CA_DIR=/tmp/ca
CA_URL=http://pki.example.com
ROOT_CA="My Root CA"
ISSUING_CA=servers
ISSUING_CA_NAME="My Servers CA"
HOST=web.example.com
IP=192.0.2.1
USER_EMAIL=alice@example.com

mkdir -p "$CA_DIR"
simple-ca-lite ca create --ca-dir "$CA_DIR" --ca-url "$CA_URL" "$ROOT_CA"
simple-ca-lite ca create --ca-dir "$CA_DIR" --issuing-ca "$ISSUING_CA" "$ISSUING_CA_NAME"
simple-ca-lite cert create --ca-dir "$CA_DIR/$ISSUING_CA" "$HOST" "$IP"
simple-ca-lite cert create --ca-dir "$CA_DIR/$ISSUING_CA" --type user "$USER_EMAIL"
simple-ca-lite ca show --ca-dir "$CA_DIR/$ISSUING_CA"
simple-ca-lite cert list --ca-dir "$CA_DIR/$ISSUING_CA"
```

A request signed without the question, and its certificate shown:

```sh
CA_DIR=/tmp/ca/servers
CSR=app.csr
CERT=/tmp/ca/servers/app_cert.pem

simple-ca-lite cert sign --ca-dir "$CA_DIR" --force "$CSR"
simple-ca-lite cert show "$CERT"
```

A PKCS#12 bundle, a revocation and the CRL:

```sh
CA_DIR=/tmp/ca/servers
CERT=/tmp/ca/servers/web_cert.pem
PFX_PASSWORD=s3cr3t
REASON=superseded

simple-ca-lite cert pfx --ca-dir "$CA_DIR" --password "$PFX_PASSWORD" "$CERT"
simple-ca-lite cert revoke --ca-dir "$CA_DIR" --reason "$REASON" "$CERT"
simple-ca-lite crl create --ca-dir "$CA_DIR"
```

The keys of the root CA and all its issuing CAs encrypted:

```sh
CA_DIR=/tmp/ca
export SIMPLE_CA_KEY_PASSWORD_FILE=/etc/simple-ca/key-password

simple-ca-lite key encrypt --ca-dir "$CA_DIR" --all
```

## Shared with simple-ca

A CA directory of `simple-ca-lite` is one of `simple-ca`, so either program works on the same
CA, and a CA made by one is served, listed or changed by the other:

- the files of the CA, `index.txt` among them, are those of
  [Directory layout](directory-layout.md);
- the settings of [simple-ca.json](configuration.md) of the root CA apply alike: `days`, `types`
  and `ca_publish_base_url`, and the option values of the contexts of a `simple-ca` session, which
  apply on the command line of both programs;
- the commands write the same records to the [audit log](audit.md), `audit.log` of the root CA,
  which `simple-ca audit list` reads;
- an issuing CA cannot take the names of the pages of `simple-ca serve`, as with `simple-ca`.

```sh
CA_DIR=/tmp/ca
ISSUING_CA=servers

simple-ca cert list --ca-dir "$CA_DIR/$ISSUING_CA"
simple-ca audit list --ca-dir "$CA_DIR"
simple-ca serve --ca-dir "$CA_DIR"
```
