# Usage

The commands of `simple-ca` for CAs, certificates and CRLs. The token commands are described in
[signing-api.md](signing-api.md), `serve` in [serve.md](serve.md), and the files the commands
write in [directory-layout.md](directory-layout.md).

```sh
simple-ca ca create    [--ca-dir DIR] [--days N] [--ca-url URL]
                       [--issuing-ca NAME] [--write-conf] CA_NAME
simple-ca ca show      [--ca-dir DIR]

simple-ca cert create  [--ca-dir DIR] [--cert-dir DIR] [--days N] [--type server|user|none]
                       [--ku USAGES] [--eku USAGE ...] CN|EMAIL [EMAIL|CN] [SAN ...]
simple-ca cert sign    [--ca-dir DIR] [--cert-dir DIR] [--days N] [--type server|user|none]
                       [--ku USAGES] [--eku USAGE ...] [--force] CSR_FILE
simple-ca cert pfx     [--ca-dir DIR] [--password PASS] CERT_PATH
simple-ca cert revoke  [--ca-dir DIR] [--reason REASON] CERT_PATH
simple-ca cert list    [--ca-dir DIR] [--valid] [--revoked] [--expired]
simple-ca cert show    CERT_FILE
simple-ca cert webui   [--ca-dir DIR] [--address ADDRESS] [--port PORT]

simple-ca crl create   [--ca-dir DIR] [--days N] [--all]

simple-ca token create [--ca-dir DIR] [--valid DURATION] [--type TYPE ...]
                       --domain DOMAIN [--domain DOMAIN ...] NAME
simple-ca token list   [--ca-dir DIR]
simple-ca token renew  [--ca-dir DIR] [--valid DURATION] NAME
simple-ca token revoke [--ca-dir DIR] NAME
simple-ca token purge  [--ca-dir DIR] [NAME]
simple-ca token webui  [--ca-dir DIR] [--address ADDRESS] [--port PORT]

simple-ca serve        [--ca-dir DIR] [--address ADDRESS] [--port PORT]
                       [--tls-cert FILE --tls-key FILE]
simple-ca --version
```

The commands are in groups, `ca`, `cert`, `crl` and `token`, and `serve` stands alone.
`simple-ca -h` lists the groups, `simple-ca GROUP -h` the commands of a group, and
`simple-ca GROUP COMMAND -h` the options of a command. Options come before the arguments, and take
one dash or two: `-days 30` and `--days 30` are the same.

The CA directory is `--ca-dir`, else `SIMPLE_CA_DIR`, else the working directory. It must exist,
and it holds the CA a command works with. A CA whose certificate is self-signed is a root CA;
any other is an issuing CA, and its root CA is in the directory above it.

## ca create

Without `--issuing-ca`, creates the root CA in the CA directory. With `--issuing-ca NAME`,
creates an issuing CA in `CA_DIR/NAME/`, signed by the root CA in the CA directory, and adds it
to `ca_bundle.pem` and to `index.txt` of the root CA. `NAME` is a **kebab-case** name: words of
lower-case letters and digits joined by hyphens, such as `servers` or `lab-servers`, but not
`help` or `docs`, the routes of the pages of [serve](serve.md). The CA directory must not hold an issuing
CA. A CA that exists is left as it is. `--days` defaults to
3650.

A new CA starts with an empty CRL, number 1, valid for `days.crl` of `simple-ca.json`, 30 days
without it, so the CRL Distribution Point URL of its certificates has a CRL to serve from the
start. `crl create` renews it before its next update.

`--ca-url URL` is stored in `simple-ca.json` and embeds AIA (Authority Information
Access) and CRL Distribution Point extensions in the issuing CAs and certificates issued from
then on: `URL/ca_cert.crt` and `URL/crl.pem` for the root CA, `URL/NAME/ca_cert.crt` and
`URL/NAME/crl.pem` for the issuing CA `NAME`. Its former name, `--ca-publish-base-url`, is still
accepted.

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
simple-ca ca create --ca-dir /tmp/ca --issuing-ca servers --write-conf "My Servers CA"
openssl ca -config /tmp/ca/servers/openssl.cnf -extensions ext_user \
  -in alice.csr -out alice_cert.pem
openssl ca -config /tmp/ca/servers/openssl.cnf -gencrl -out /tmp/ca/servers/crl.pem
```

## cert create

The type sets the key usages and extended key usages of the certificate:

| `--type` | Key usage | Extended key usage |
|---|---|---|
| `server` (default) | digitalSignature, keyEncipherment | serverAuth, clientAuth |
| `user` | digitalSignature, contentCommitment | clientAuth, emailProtection, codeSigning |
| `none` | none | none |

`types` of `simple-ca.json` changes these types and defines others; see
[simple-ca.json](configuration.md).

`--type server` creates a TLS certificate, and `--type none` a certificate with no key usages of
its own, both named the same way:

```sh
simple-ca cert create [--type none] CN [SAN ...]
```

- `CN` is a hostname or an FQDN, and is also the first DNS name SAN.
- A `SAN` is a hostname, an FQDN, an IPv4 or IPv6 address, or a numeric OID.

`--type user` creates a certificate for a person:

```sh
simple-ca cert create --type user CN|EMAIL [EMAIL|CN] [SAN ...]
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
[Directory layout](directory-layout.md); a CN that gives no file name, such as `...`, is refused.
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
simple-ca cert create web.example.com web 192.0.2.1 2001:db8::1 1.3.6.1.4.1.99999.1
simple-ca cert create --type user alice@example.com "Alice Example" a.example@example.org
simple-ca cert create --type user --ku keyEncipherment "Alice Example" alice@example.com
simple-ca cert create --eku 1.3.6.1.4.1.99999.10 device01.example.com
simple-ca cert create --type none --ku digitalSignature,keyAgreement --eku clientAuth \
  device02.example.com
```

## cert sign

Signs the certificate signing request in `CSR_FILE`, a PEM or DER file whose signature must be
valid, with the CA in the CA directory, and records the certificate in `index.txt` of that CA.
Only the subject and the subject alternative names of the request are copied, as they are; the
name rules of the type are not checked. The key usages and extended key usages are those of the
type, with `--ku` and `--eku` added as for [cert create](#cert-create), and the other extensions of
the request are left out. The AIA and CRL Distribution Point URLs are those of the CA.

The certificate is written to the CA directory, or to `--cert-dir`, named after the request file
without its extension, with each run of characters other than letters, digits, hyphens and
underscores replaced by one `_`, without a leading or trailing `_`: `web.csr` is written as
`web_cert.pem` and `my web.v2.csr` as `my_web_v2_cert.pem`. A request file that gives no name,
such as `+.csr`, and a certificate that exists are errors. `--type` defaults
to `server` and `--days` to 365.

The certificate is shown, with the fields of [cert show](#ca-show-and-cert-show), and
`cert sign` asks `Sign this certificate? [y/N]`. It is written and recorded after `y` or `yes`;
any other answer, or no input, leaves it unsigned and exits with status 1. `--force` signs without
asking.

```sh
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout web_key.pem -out web.csr -subj "/O=Example/CN=web.example.com" \
  -addext "subjectAltName=DNS:web.example.com,IP:192.0.2.1"
simple-ca cert sign --ca-dir /tmp/ca/servers web.csr
simple-ca cert sign --ca-dir /tmp/ca/servers --type user --cert-dir . --force alice.csr
```

## cert pfx

Creates `{name}.pfx` next to `CERT_PATH` from the certificate, its key and the chain of the CA in
the CA directory, which signed it: the root CA, and the issuing CA when the CA directory holds
one. The password defaults to `changeit`. The bundle is encrypted with PBES2 (AES-256-CBC).

## cert revoke and crl create

`cert revoke` marks the certificate at `CERT_PATH` as revoked in `index.txt` of the CA in the CA
directory, which signed it. An issuing CA is revoked from the root CA directory, with its
`ca_cert.pem` as `CERT_PATH`.

`--reason` records why, in any letter case: `unspecified`, `keyCompromise`, `CACompromise`,
`affiliationChanged`, `superseded` or `cessationOfOperation`. Without it, no reason is recorded.
The reason is stored in `index.txt` as `openssl ca -crl_reason` stores it, and the CRL gives it
as the reason code of the entry; for `unspecified` and for no reason, the entry has no reason
code. The reasons `openssl ca` records for revocations of its own, `certificateHold`,
`removeFromCRL` and those of `-crl_hold` and `-crl_compromise`, are listed in the CRL as well.

`crl create` writes `crl.pem` of the CA in the CA directory, listing every revoked certificate,
with the number in `crlnumber`, and raises the number. `--days` defaults to 30. With `--all`, it
writes the CRLs of the root CA of the CA directory and of each of its issuing CAs whose key is
there; a CA that fails does not stop the others, and the command then fails.

## ca show and cert show

`ca show` shows the CA in the CA directory: whether it is the root CA or an issuing CA, the
fields of its certificate, how many of the certificates it issued are valid, revoked and expired,
its current CRL and the number of the next one. For a root CA it also names the issuing CAs.

`cert show CERT_FILE` shows the fields of any X.509 certificate in the file, which is PEM or DER.
Every certificate of a PEM file is shown, so `cert show ca_bundle.pem` shows the whole chain.

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

## cert list

Lists the certificates the CA in the CA directory issued, with their status, expiry, revocation
date and reason, serial and subject; those of a root CA include its issuing CAs. `--valid`,
`--revoked` and `--expired` choose the certificates listed, and can be combined; without any of
them every certificate is listed. A certificate is expired from its expiry on. The times are UTC.

```text
STATUS   EXPIRES                  REVOKED                  REASON         SERIAL                                    SUBJECT
valid    2027-10-30 21:51:52 UTC  -                        -              22AECF2AC0EE6D9185176A6CCEE9FC743F12EB9A  /CN=web.example.com
revoked  2027-10-30 21:51:52 UTC  2026-10-30 21:51:52 UTC  keyCompromise  12193ECDF2A38AF35B12C657CD52BC5C4CC7626D  /CN=alice.example.com
```

## cert webui

Serves a web page managing the certificates of the root CA of the CA directory and of all its
issuing CAs, until it is stopped with Ctrl-C; it is the commands above on a page, and offers no
file to download. The page shows one CA, chosen in its CA selector, the root CA at first:

- its certificates, with their status, subject, expiry and revocation, and its current CRL, with
  its number and next update, marked when overdue;
- **Show**: the fields of a certificate, as `cert show` writes them, in a dialog naming the file
  they are read from: a certificate file of the CA directory, `NAME_cert.pem`, or for the root CA
  the `ca_cert.pem` of an issuing CA. A certificate whose file a later certificate of the same name
  replaced, or which is not in the CA directory, cannot be shown;
- **Create a certificate**: a dialog of `cert create`, with the type, the subject and the other
  names, the days, and the key usages and extended key usages added to those of the type; the
  certificate and its key are written to the CA directory;
- **Sign a request**: a dialog of `cert sign`, with the type, the name of the certificate file,
  the request in PEM, the days and the usages; the certificate is written to the CA directory as
  `NAME_cert.pem`, `NAME` cleaned as `cert sign` cleans the name of the request file;
- **Revoke**: revokes a certificate, as `cert revoke` does, for the reason chosen in the dialog
  asking first;
- **Write the CRL**: writes a new CRL, as `crl create` does, valid for the days given in the dialog
  asking first.

A CA whose key is not in its directory can only be looked at. The days start from `days.cert` and
`days.crl` of [simple-ca.json](configuration.md).

```sh
simple-ca cert webui --ca-dir /etc/simple-ca
```

`--address` is the address of the interface it listens on, `127.0.0.1` by default, and `--port`
the TCP port, 8082 by default. Like [token webui](signing-api.md#token-webui), it prints the URL
of the page with a random key as its `?key=` query, valid until it stops; the page reads the key
from that URL, or asks for it, and draws the certificates from its API, below `/api/`, sending
the key in the `Authorization` header. Each request is logged to the standard error, as `serve`
logs them.

| Request | Body | Answer |
|---|---|---|
| `GET /api/cas` | | `title`, `cas`, `types`, `names`, the name rules of each type, `reasons` and `defaults`, `days` and `crl_days` |
| `GET /api/certs?ca=CA` | | `certs`, each with `serial`, `subject`, `status`, `expires`, `revoked` and `reason`; `crl`, with `number`, `next_update` and `overdue`, or null |
| `GET /api/certs/show?ca=CA&serial=SERIAL` | | `file`, the file holding the certificate, relative to the CA directory; `fields`, each a name and its value, as `cert show` writes them; `404 Not Found` when no file holds it |
| `POST /api/certs` | `ca`, `type`, `subject`, `sans`, `days`, `ku`, `eku` | `201 Created`, `subject` |
| `POST /api/certs/sign` | `ca`, `type`, `name`, `csr`, `days`, `ku`, `eku` | `201 Created`, `file`, the name of the certificate file |
| `POST /api/certs/revoke` | `ca`, `serial`, `reason` | `serial` |
| `POST /api/crl` | `ca`, `days` | `ca` |

`CA` is the name of an issuing CA, or empty for the root CA. A create whose certificate and key
files exist already is `409 Conflict`, as `cert create` leaves such a certificate.

## Example

```sh
mkdir -p /tmp/ca
simple-ca ca create --ca-dir /tmp/ca "My Root CA"
simple-ca ca create --ca-dir /tmp/ca --issuing-ca servers "My Servers CA"

export SIMPLE_CA_DIR=/tmp/ca/servers

simple-ca cert create web.example.com web.example.com 192.168.1.1
simple-ca cert create alice.example.com
simple-ca cert pfx --password s3cr3t /tmp/ca/servers/web_cert.pem

simple-ca cert revoke /tmp/ca/servers/alice_cert.pem
simple-ca crl create

simple-ca ca show
simple-ca cert show /tmp/ca/servers/web_cert.pem
simple-ca cert list --revoked
simple-ca cert list --ca-dir /tmp/ca
```
