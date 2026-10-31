# Simple CA

[![build](https://github.com/skoszewski/simple-ca/actions/workflows/build.yml/badge.svg)](https://github.com/skoszewski/simple-ca/actions/workflows/build.yml)

`simple-ca` creates and manages a simple Certificate Authority for testing and development: a
root CA, issuing CAs, server and user certificates, PKCS#12 bundles, revocation and CRLs. It is a
single executable using Go's native cryptography, and runs no other program.

## Installation

Download the archive for your platform from the
[releases](https://github.com/skoszewski/simple-ca/releases) and put `simple-ca` on your `PATH`.
With Go installed:

```sh
go install github.com/skoszewski/simple-ca@latest
```

## Directory layout

```text
CA_DIR/
  simple-ca.json           settings (optional)
  ca_cert.pem              root CA certificate
  ca_key.pem               root CA private key
  ca_bundle.pem            root and all issuing CA certificates concatenated
  index.txt                certificates issued by the root CA
  index.txt.attr           attributes of index.txt
  crlnumber                next CRL number of the root CA
  crl.pem                  root CA CRL (make-crl)
  openssl.cnf              configuration of openssl ca (make-ca --write-conf)
  acme.json                ACME accounts and orders of the root CA (serve)
  {name}_cert.pem          certificate issued by the root CA
  {name}_key.pem           key of a certificate issued by the root CA
  {name}.pfx               PKCS#12 bundle (make-pfx)
  {issuing_ca}/
    ca_cert.pem            issuing CA certificate
    ca_key.pem             issuing CA private key
    index.txt              certificates issued by the issuing CA
    index.txt.attr         attributes of index.txt
    crlnumber              next CRL number of the issuing CA
    crl.pem                issuing CA CRL (make-crl)
    openssl.cnf            configuration of openssl ca (make-ca --write-conf)
    acme.json              ACME accounts and orders of the issuing CA (serve)
    {name}_cert.pem        certificate issued by the issuing CA
    {name}_key.pem         key of a certificate issued by the issuing CA
```

`{name}` is the CN of a server certificate up to its first dot, the CN of a user certificate, or
the part of the emailAddress before the `@` when there is no CN. Each run of characters other than
letters, digits, hyphens and underscores becomes one `_`, without a leading or trailing `_`:
`web.example.com` is written as `web_cert.pem`, `Alice Example` as `Alice_Example_cert.pem` and
`a.example@example.org` as `a_example_cert.pem`.

Use `ca_bundle.pem` with `openssl verify -CAfile CA_DIR/ca_bundle.pem`; this works the same on
Linux, macOS and Windows without hash symlinks.

## Commands

```sh
simple-ca make-ca     [--ca-dir DIR] [--days N] [--ca-publish-base-url URL]
                      [--issuing-ca NAME] [--write-conf] CA_NAME
simple-ca make-cert   [--ca-dir DIR] [--cert-dir DIR] [--days N] [--type server|user|none]
                      [--ku USAGES] [--eku USAGE ...] CN|EMAIL [EMAIL|CN] [SAN ...]
simple-ca sign        [--ca-dir DIR] [--cert-dir DIR] [--days N] [--type server|user|none]
                      [--ku USAGES] [--eku USAGE ...] [--force] CSR_FILE
simple-ca make-pfx    [--ca-dir DIR] [--password PASS] CERT_PATH
simple-ca make-crl    [--ca-dir DIR] [--days N] [--all]
simple-ca revoke-cert [--ca-dir DIR] [--reason REASON] CERT_PATH
simple-ca info        [--ca-dir DIR]
simple-ca info        CERT_FILE
simple-ca list        [--ca-dir DIR] [--valid] [--revoked] [--expired]
simple-ca serve       [--ca-dir DIR] [--address ADDRESS] [--port PORT]
                      [--tls-cert FILE --tls-key FILE]
simple-ca --version
```

Options come before the arguments, and take one dash or two: `-days 30` and `--days 30` are
the same. `simple-ca COMMAND -h` lists the options of a command.

The CA directory is `--ca-dir`, else `SIMPLE_CA_DIR`, else the working directory. It must exist,
and it holds the CA a command works with. A CA whose certificate is self-signed is a root CA;
any other is an issuing CA, and its root CA is in the directory above it.

### make-ca

Without `--issuing-ca`, creates the root CA in the CA directory. With `--issuing-ca NAME`,
creates an issuing CA in `CA_DIR/NAME/`, signed by the root CA in the CA directory, and adds it
to `ca_bundle.pem` and to `index.txt` of the root CA. The CA directory must not hold an issuing
CA. A CA that exists is left as it is. `--days` defaults to 3650.

A new CA starts with an empty CRL, number 1, valid for `days.crl` of `simple-ca.json`, 30 days
without it, so the CRL Distribution Point URL of its certificates has a CRL to serve from the
start. `make-crl` renews it before its next update.

`--ca-publish-base-url URL` is stored in `simple-ca.json` and embeds AIA (Authority Information
Access) and CRL Distribution Point extensions in the issuing CAs and certificates issued from
then on: `URL/ca_cert.crt` and `URL/crl.pem` for the root CA, `URL/NAME/ca_cert.crt` and
`URL/NAME/crl.pem` for the issuing CA `NAME`.

`--write-conf` also writes `openssl.cnf`, a configuration of `openssl ca`, to the directory of the
CA, the root CA or the issuing CA `--issuing-ca`; for a CA that exists, it writes the file again.
With it, `openssl ca` signs requests into the same `index.txt`, and simple-ca and `openssl ca`
can be used side by side:

- the `simple_ca` section names the files of the CA, uses random serials as simple-ca does, takes
  `default_days` and `default_crl_days` from `days` of `simple-ca.json` (365 and 30 without
  them), copies the extensions of a request, its subject alternative names among them, and keeps
  only the commonName and emailAddress of its subject;
- an `ext_TYPE` section for each certificate type holds its key usages and extended key usages,
  and the AIA and CRL Distribution Point URLs of the CA; `ext_server` is the default;
- the configuration of a root CA also has `ext_issuing_ca`, for an issuing CA.

`openssl ca` does not check the name rules of the type; the names are those of the request.

```sh
simple-ca make-ca --ca-dir /tmp/ca --issuing-ca servers --write-conf "My Servers CA"
openssl ca -config /tmp/ca/servers/openssl.cnf -extensions ext_user \
  -in alice.csr -out alice_cert.pem
openssl ca -config /tmp/ca/servers/openssl.cnf -gencrl -out /tmp/ca/servers/crl.pem
```

### make-cert

The type sets the key usages and extended key usages of the certificate:

| `--type` | Key usage | Extended key usage |
|---|---|---|
| `server` (default) | digitalSignature, keyEncipherment | serverAuth, clientAuth |
| `user` | digitalSignature, contentCommitment | clientAuth, emailProtection, codeSigning |
| `none` | none | none |

`types` of `simple-ca.json` changes these types and defines others; see
[simple-ca.json](#simple-cajson).

`--type server` creates a TLS certificate, and `--type none` a certificate with no key usages of
its own, both named the same way:

```sh
simple-ca make-cert [--type none] CN [SAN ...]
```

- `CN` is a hostname or an FQDN, and is also the first DNS name SAN.
- A `SAN` is a hostname, an FQDN, an IPv4 or IPv6 address, or a numeric OID.

`--type user` creates a certificate for a person:

```sh
simple-ca make-cert --type user CN|EMAIL [EMAIL|CN] [SAN ...]
```

- The first argument is the CN or the emailAddress of the subject; an argument with an `@` and a
  dot after it is an email address, anything else a CN.
- The second argument, when given, is the other of the two: the emailAddress after a CN, the CN
  after an emailAddress.
- The emailAddress is also the first email address SAN.
- A `SAN`, allowed once both the CN and the emailAddress are given, is an email address or a
  numeric OID.

A numeric OID, such as `1.3.6.1.4.1.99999.1`, is a registeredID SAN. An argument that is an IPv4
address, such as `1.2.3.4`, is an IP address SAN of a server or none certificate, not an OID. A hostname
or FQDN is made of labels of letters, digits and hyphens, and its last label is not all digits;
the addresses of email address SANs are ASCII.

The certificate is signed by the CA in the CA directory, the root CA or an issuing CA, and
written to that directory, or to `--cert-dir`, named as described under
[Directory layout](#directory-layout); a CN that gives no file name, such as `...`, is refused.
A certificate that exists is left as it is. `--days` defaults to 365.

`--ku USAGES` adds key usages to those of the type, as a comma-separated list, and `--eku USAGE`
adds an extended key usage; both are repeated for more, and a usage the type has already is not
added again. The names are in any letter case:

- key usages: `digitalSignature`, `contentCommitment`, `keyEncipherment`, `dataEncipherment`,
  `keyAgreement`, `cRLSign`, `encipherOnly` and `decipherOnly`; `keyCertSign` belongs to CA
  certificates and is refused;
- extended key usages: a numeric OID, or `serverAuth`, `clientAuth`, `codeSigning`,
  `emailProtection`, `timeStamping`, `OCSPSigning`, `ipsecEndSystem`, `ipsecTunnel`,
  `ipsecUser`, `msSGC`, `nsSGC`, `msCodeCom`, `msKernelCodeSigning` and `any`.

A `none` certificate without `--ku` and `--eku` has neither a key usage nor an extended key usage
extension.

```sh
simple-ca make-cert web.example.com web 192.0.2.1 2001:db8::1 1.3.6.1.4.1.99999.1
simple-ca make-cert --type user alice@example.com "Alice Example" a.example@example.org
simple-ca make-cert --type user --ku keyEncipherment "Alice Example" alice@example.com
simple-ca make-cert --eku 1.3.6.1.4.1.99999.10 device01.example.com
simple-ca make-cert --type none --ku digitalSignature,keyAgreement --eku clientAuth \
  device02.example.com
```

### sign

Signs the certificate signing request in `CSR_FILE`, a PEM or DER file whose signature must be
valid, with the CA in the CA directory, and records the certificate in `index.txt` of that CA.
Only the subject and the subject alternative names of the request are copied, as they are; the
name rules of the type are not checked. The key usages and extended key usages are those of the
type, with `--ku` and `--eku` added as for [make-cert](#make-cert), and the other extensions of
the request are left out. The AIA and CRL Distribution Point URLs are those of the CA.

The certificate is written to the CA directory, or to `--cert-dir`, named after the request file
without its extension, with each run of characters other than letters, digits, hyphens and
underscores replaced by one `_`, without a leading or trailing `_`: `web.csr` is written as
`web_cert.pem` and `my web.v2.csr` as `my_web_v2_cert.pem`. A request file that gives no name,
such as `+.csr`, and a certificate that exists are errors. `--type` defaults
to `server` and `--days` to 365.

The certificate is shown, with the fields of [info](#info), and `sign` asks
`Sign this certificate? [y/N]`. It is written and recorded after `y` or `yes`; any other answer,
or no input, leaves it unsigned and exits with status 1. `--force` signs without asking.

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout web_key.pem -out web.csr -subj "/O=Example/CN=web.example.com" \
  -addext "subjectAltName=DNS:web.example.com,IP:192.0.2.1"
simple-ca sign --ca-dir /tmp/ca/servers web.csr
simple-ca sign --ca-dir /tmp/ca/servers --type user --cert-dir . --force alice.csr
```

### make-pfx

Creates `{name}.pfx` next to `CERT_PATH` from the certificate, its key and the chain of the CA in
the CA directory, which signed it: the root CA, and the issuing CA when the CA directory holds
one. The password defaults to `changeit`. The bundle is encrypted with PBES2 (AES-256-CBC).

### revoke-cert and make-crl

`revoke-cert` marks the certificate at `CERT_PATH` as revoked in `index.txt` of the CA in the CA
directory, which signed it. An issuing CA is revoked from the root CA directory, with its
`ca_cert.pem` as `CERT_PATH`.

`--reason` records why, in any letter case: `unspecified`, `keyCompromise`, `CACompromise`,
`affiliationChanged`, `superseded` or `cessationOfOperation`. Without it, no reason is recorded.
The reason is stored in `index.txt` as `openssl ca -crl_reason` stores it, and the CRL gives it
as the reason code of the entry; for `unspecified` and for no reason, the entry has no reason
code. The reasons `openssl ca` records for revocations of its own, `certificateHold`,
`removeFromCRL` and those of `-crl_hold` and `-crl_compromise`, are listed in the CRL as well.

`make-crl` writes `crl.pem` of the CA in the CA directory, listing every revoked certificate,
with the number in `crlnumber`, and raises the number. `--days` defaults to 30. With `--all`, it
writes the CRLs of the root CA of the CA directory and of each of its issuing CAs whose key is
there; a CA that fails does not stop the others, and the command then fails.

### info

Without `CERT_FILE`, shows the CA in the CA directory: whether it is the root CA or an issuing
CA, the fields of its certificate, how many of the certificates it issued are valid, revoked
and expired, its current CRL and the number of the next one. For a root CA it also names the
issuing CAs.

With `CERT_FILE`, shows the fields of any X.509 certificate in the file, which is PEM or DER.
Every certificate of a PEM file is shown, so `info ca_bundle.pem` shows the whole chain.
`--ca-dir` does not apply to a file.

The fields of a certificate: subject and issuer in the one-line form of OpenSSL
(`/CN=.../emailAddress=...`), serial, validity period and whether it is valid, expired or not yet
valid, signature algorithm, key, whether it is a CA and its path length, key usage, extended key
usage, DNS, IP, email, URI and registered ID subject alternative names, subject and authority key
IDs, AIA and CRL Distribution Point URLs, and the SHA-256 fingerprint. A field the certificate
does not have is left out.

```text
Subject:                 /CN=web.example.com
Issuer:                  /CN=Servers CA
Serial:                  22AECF2AC0EE6D9185176A6CCEE9FC743F12EB9A
Valid from:              2026-10-30 21:51:52 UTC
Valid until:             2027-10-30 21:51:52 UTC
Validity:                valid
Signature algorithm:     SHA256-RSA
Key:                     RSA 4096 bits
CA:                      no
Key usage:               digitalSignature, keyEncipherment
Extended key usage:      serverAuth, clientAuth
DNS name:                web.example.com
Authority key ID:        D5:22:EF:64:C5:3E:9D:79:27:C0:0D:14:A8:BB:1E:0A:FB:46:BD:2B
AIA CA issuers:          http://pki.example.com/servers/ca_cert.crt
CRL distribution point:  http://pki.example.com/servers/crl.pem
SHA-256 fingerprint:     81:02:F1:BB:D7:4D:5E:94:25:D9:A6:61:8C:F4:93:41:80:74:B9:9E:F9:EC:75:E8:03:31:6C:22:85:26:18:27
```

### list

Lists the certificates the CA in the CA directory issued, with their status, expiry, revocation
date and reason, serial and subject; those of a root CA include its issuing CAs. `--valid`,
`--revoked` and `--expired` choose the certificates listed, and can be combined; without any of
them every certificate is listed. A certificate is expired from its expiry on. The times are UTC.

```text
STATUS   EXPIRES                  REVOKED                  REASON         SERIAL                                    SUBJECT
valid    2027-10-30 21:51:52 UTC  -                        -              22AECF2AC0EE6D9185176A6CCEE9FC743F12EB9A  /CN=web.example.com
revoked  2027-10-30 21:51:52 UTC  2026-10-30 21:51:52 UTC  keyCompromise  12193ECDF2A38AF35B12C657CD52BC5C4CC7626D  /CN=alice.example.com
```

### serve

Serves the certificates and CRLs of the root CA of the CA directory, and of all its issuing CAs,
over HTTP, until it is stopped with Ctrl-C. `--address` is the address of the interface it
listens on, `127.0.0.1` by default and `0.0.0.0` for all interfaces (`::` also works), and
`--port` the TCP port, 8080 by default. With `--tls-cert` and `--tls-key`, PEM files of a
certificate chain and its key, it serves HTTPS instead, as [ACME](#acme) clients require; the
certificate can be one of the CA itself.

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
| `/acme/directory` | the ACME directory of the root CA, see [ACME](#acme) | `application/json` |
| `/NAME/acme/directory` | the ACME directory of the issuing CA `NAME` | `application/json` |

The index page lists the root CA and all its issuing CAs, also when `--ca-dir` is an issuing CA,
each with its subject, issuer, serial number, validity period, days left before it expires,
marked when fewer than 30 are left, key and SHA-256 fingerprint, and its current CRL, with its
number, the count of revoked certificates and its next update, marked when overdue. The CA bundle
is offered at the top of the page, above the CAs, as P7B, which Windows opens and imports with
all its certificates, and as PEM; each CA links to its certificate and CRL, in DER and PEM. The
page is styled with the browser build of Tailwind CSS 4.3.3, embedded in the executable and
served at `/assets/tailwindcss-browser-4.3.3.js`, so the page loads nothing from other sites.

The files are read on each request, so a CRL written by `make-crl` is served at once; a file that
does not exist is `404 Not Found`. No other file is served. Each
request is logged to the standard error.

The URLs are those `--ca-publish-base-url` writes into the certificates, so with the base URL set
to the address of the server, the AIA and CRL Distribution Point URLs of the certificates are
served:

```sh
simple-ca make-ca --ca-dir /tmp/ca --ca-publish-base-url http://pki.example.com:8080 "My Root CA"
simple-ca serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8080
```

### ACME

With `acme.domains` in `simple-ca.json`, `serve` is also an ACME server (RFC 8555) for each CA
whose key is in its directory: the root CA at `/acme/directory` and the issuing CA `NAME` at
`/NAME/acme/directory`. The index page shows the directory URL of each CA. Any client that
reaches the server may register an account; certificates are issued only for DNS names that are
one of `acme.domains` or below one of them, and whose challenge is met:

- `http-01` - the server fetches `http://NAME/.well-known/acme-challenge/TOKEN` on port 80;
- `dns-01` - the server looks up the TXT record `_acme-challenge.NAME` with the system resolver;
  a wildcard name, `*.NAME`, is offered this challenge alone.

A certificate is of the type `server`, valid for `acme.days` of `simple-ca.json`, 90 days
without it, with the first name of the order as the CN and all its names as DNS names; the key usages,
extended key usages, AIA and CRL Distribution Point URLs are those of `make-cert`. It is recorded
in `index.txt` like any other. The chain returned holds the certificate and, from an issuing CA,
the issuing CA certificate. A certificate is revoked by the account it was issued to, or with its
key, for a reason from 0 to 5, as for `revoke-cert`; `make-crl` writes the CRL listing it.

The accounts, the orders and the authorizations of a CA are kept in `acme.json` of its directory,
so `serve` needs to write to the CA directories and read the CA keys. An order and its
authorizations expire 7 days after they are made. Nonces are kept in memory; after a restart, a
client retries a request with a new nonce.

The ACME clients require HTTPS, so `serve` is run with a certificate of the CA, which the clients
must trust. With [lego](https://go-acme.github.io/lego/), `LEGO_CA_CERTIFICATES` names the root CA
certificate:

```sh
simple-ca make-cert --ca-dir /tmp/ca --cert-dir /tmp pki.example.com
simple-ca serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8443 \
  --tls-cert /tmp/pki_cert.pem --tls-key /tmp/pki_key.pem
LEGO_CA_CERTIFICATES=/tmp/ca/ca_cert.pem lego run --accept-tos --email admin@example.com \
  --server https://pki.example.com:8443/servers/acme/directory --domains web.example.com --http
```

## simple-ca.json

The settings of the root CA and its issuing CAs, in the root CA directory; a command working with
an issuing CA reads the file of its root CA. The file is optional: `make-ca --ca-publish-base-url`
writes it, and it can be written or edited by hand. A setting not described here is an error.

```json
{
  "ca_publish_base_url": "http://pki.example.com",
  "days": {"cert": 90, "crl": 7},
  "types": {
    "device": {
      "key_usage": ["digitalSignature"],
      "ext_key_usage": ["clientAuth", "1.3.6.1.4.1.99999.10"]
    },
    "person": {
      "names": "user",
      "key_usage": ["digitalSignature", "keyEncipherment"],
      "ext_key_usage": []
    },
    "user": {"key_usage": ["digitalSignature", "contentCommitment", "keyEncipherment"]}
  },
  "acme": {"domains": ["example.com", "lab.example.org"], "days": 30}
}
```

- `ca_publish_base_url` - base URL for the AIA and CRL Distribution Point extensions.
- `acme` - the [ACME](#acme) server of `serve`:
  - `domains` - the domains whose names and the names below them it issues certificates for;
    without them, `serve` has no ACME server;
  - `days` - the validity of its certificates, 90 days by default.
- `days` - defaults for `--days`: `ca`, `cert`, `crl`.
- `types` - certificate types for `make-cert --type` and `sign --type`, by name, of letters, digits and
  underscores. A type named `server`, `user` or `none` redefines the built-in type, and any
  other name defines a new type. Each type has:
  - `names` - the name rules of the subject and SANs, `server` or `user`, as described under
    [make-cert](#make-cert); a new type has the server rules without it;
  - `key_usage` - its key usages;
  - `ext_key_usage` - its extended key usages, names or numeric OIDs.

  The names are those of `--ku` and `--eku`. A field left out keeps its value of the built-in
  type, none for a new type, and `[]` gives the type none. `--ku` and `--eku` add to the usages of
  the type.

## Certificate database

Every CA directory holds the database of `openssl ca`, so the directory can also be used with
`openssl ca` and `openssl ocsp -index`:

- `index.txt` - one line per certificate the CA issued, the issuing CAs included in that of the
  root CA, with six tab-separated fields: status (`V` valid, `R` revoked), expiry, revocation
  date, serial in hex, file name (`unknown`) and subject. The dates are UTCTime,
  `YYMMDDHHMMSSZ`; an expiry from 2050 on is GeneralizedTime, `YYYYMMDDHHMMSSZ`.
- `index.txt.attr` - `unique_subject = no`, so a subject can be issued again.
- `crlnumber` - the number of the next CRL, in hex.

```text
V	271030213502Z		57926D0E17563988B2B8B0CCD8301FD9C2895CF8	unknown	/CN=web.example.com
R	271030213502Z	261030213502Z	1A4793AE63C220A5B05D59EBCB19B0B0C2AA8E65	unknown	/CN=alice.example.com
```

`make-ca --write-conf` writes a configuration of `openssl ca` for the CA directory, `openssl.cnf`.

## Example

```sh
mkdir -p /tmp/ca
simple-ca make-ca --ca-dir /tmp/ca "My Root CA"
simple-ca make-ca --ca-dir /tmp/ca --issuing-ca servers "My Servers CA"

export SIMPLE_CA_DIR=/tmp/ca/servers

simple-ca make-cert web.example.com web.example.com 192.168.1.1
simple-ca make-cert alice.example.com
simple-ca make-pfx  --password s3cr3t /tmp/ca/servers/web_cert.pem

simple-ca revoke-cert /tmp/ca/servers/alice_cert.pem
simple-ca make-crl

simple-ca info
simple-ca info /tmp/ca/servers/web_cert.pem
simple-ca list --revoked
simple-ca list --ca-dir /tmp/ca
```

## systemd

`systemd/` holds units for a CA in `/etc/simple-ca` and the executable in
`/usr/local/bin/simple-ca`, both run as the user `simple-ca`:

- `simple-ca.service` runs `serve` on all interfaces, port 8080, with write access to
  `/etc/simple-ca` for [ACME](#acme); `--tls-cert` and `--tls-key` are added to its command with
  `systemctl edit simple-ca.service`;
- `simple-ca-crl.service` runs `make-crl --all`, for the root CA in `/etc/simple-ca` and its
  issuing CAs;
- `simple-ca-crl.timer` starts `simple-ca-crl.service` daily, and on boot when a run was missed.

`systemd/simple-ca-mini.service` runs the `serve` command of [Simple CA Mini](#simple-ca-mini)
instead; its installation is in [docs/simple-ca-mini.md](docs/simple-ca-mini.md#systemd).

```sh
sudo install -m 755 simple-ca /usr/local/bin/simple-ca
sudo useradd --system --home-dir /etc/simple-ca --no-create-home \
  --shell /usr/sbin/nologin simple-ca
sudo install -d -o simple-ca -g simple-ca -m 750 /etc/simple-ca
sudo -u simple-ca simple-ca make-ca --ca-dir /etc/simple-ca \
  --ca-publish-base-url http://ca.example.com:8080 "My Root CA"
sudo -u simple-ca simple-ca make-ca --ca-dir /etc/simple-ca --issuing-ca servers "My Servers CA"
sudo cp systemd/simple-ca.service systemd/simple-ca-crl.service systemd/simple-ca-crl.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now simple-ca.service simple-ca-crl.timer
```

The CRL is renewed daily, well within `days.crl`, 30 days by default. Other settings, such as
the port, are changed with `systemctl edit simple-ca.service`.

## Simple CA Mini

`simple-ca-mini.py` is a single Python 3 script, using the standard library and the `openssl`
command, that creates root and issuing CAs, certificates and PFX bundles in the same directory
layout, and serves the CA certificates over HTTP. See [docs/simple-ca-mini.md](docs/simple-ca-mini.md).

## Building

`./build.mjs` needs Node.js and Go; the tests need `openssl` on the `PATH`.

```sh
./build.mjs                    # build simple-ca for the host
./build.mjs build linux/arm64  # build simple-ca-linux-arm64
./build.mjs test               # run the tests
./build.mjs check              # check formatting, vet and run the tests
./build.mjs clean              # remove the built executables
```

The release workflow checks the formatting and runs `go vet`, but does not run the tests; they
are run with `./build.mjs test` or `./build.mjs check`.

## Releasing

`CHANGELOG.md` holds every release, newest first: a `## x.y.z` heading, a summary line between
blank lines, and the changes as a list. An entry is released once a commit on `dev` has its
summary line as the message; the newest entry not yet released collects the changes made since
the last release.

`./release.mjs`, run on `dev`, releases the newest entry, without pushing anything: it commits
everything with the entry's summary line as the message. Releases made this way stay on the
machine; each next one needs a new entry, with a new version.

`./release.mjs --push` publishes the newest entry:

1. commits everything with the entry's summary line as the message, when the entry is not
   released yet;
2. makes the annotated tag `vx.y.z` on `dev`; its message, which the workflow publishes as the
   release notes, is the entry followed by the entries released since the last tagged one, each
   under its own heading;
3. fast-forwards `main` to `dev`;
4. pushes `dev`, `main` and the tag in one atomic push; the tag builds and publishes the release.

```sh
./release.mjs                  # release the newest CHANGELOG.md entry, but push nothing
./release.mjs --push           # publish the newest CHANGELOG.md entry
./release.mjs -n               # print the commands instead of running them
```

It refuses to commit changes for a released entry, and to publish an entry whose tag is on
GitHub; the next change needs a new entry. Only a tag is built: pushing `dev` or `main` runs no
workflow.

## Licence

MIT, see [LICENSE](LICENSE).

`assets/tailwindcss-browser-4.3.3.js` is `dist/index.global.js` of the npm package
`@tailwindcss/browser` 4.3.3, copyright Tailwind Labs, Inc., under the MIT licence of
[assets/tailwindcss-browser-LICENSE](assets/tailwindcss-browser-LICENSE).
