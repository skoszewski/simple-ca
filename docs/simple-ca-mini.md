# Simple CA Mini

`simple-ca-mini.py` is a lightweight re-implementation of the Simple CA command line tool, a
single Python 3 script using the standard library alone. It creates root and issuing CAs, issues
certificates, writes PKCS#12 bundles and serves the CA certificates and the CA bundle over HTTP.

The script controls the `openssl` command, which does every key generation, signature,
fingerprint and PKCS#12 operation; Simple CA Mini is for systems with OpenSSL installed.

## Requirements

- Python 3.9 or later;
- `openssl` on the `PATH`, OpenSSL 3 or later.

The script is installed by copying it, for example as `/usr/local/bin/simple-ca-mini`.

## Directory layout

```text
CA_DIR/
  simple-ca.json           settings (optional)
  ca_cert.pem              root CA certificate
  ca_key.pem               root CA private key
  ca_bundle.pem            root and all issuing CA certificates concatenated
  {name}_cert.pem          certificate issued by the root CA
  {name}_key.pem           key of a certificate issued by the root CA
  {name}.pfx               PKCS#12 bundle (cert pfx)
  {issuing-ca}/
    ca_cert.pem            issuing CA certificate
    ca_key.pem             issuing CA private key
    {name}_cert.pem        certificate issued by the issuing CA
    {name}_key.pem         key of a certificate issued by the issuing CA
```

The layout and the file names are those of `simple-ca`. `{name}` is the CN of a server or none
certificate up to its first dot, the CN of a user certificate, or the part of the emailAddress
before the `@` when there is no CN. Each run of characters other than letters, digits, hyphens and
underscores becomes one `_`, without a leading or trailing `_`: `web.example.com` is written as
`web_cert.pem`, `Alice Example` as `Alice_Example_cert.pem` and `a.example@example.org` as
`a_example_cert.pem`. The keys are RSA 4096, unencrypted PKCS#8 PEM files readable by their owner
alone.

## Commands

```sh
simple-ca-mini.py ca create   [--ca-dir DIR] [--days N] [--ca-url URL]
                              [--issuing-ca NAME] CA_NAME
simple-ca-mini.py cert create [--ca-dir DIR] [--cert-dir DIR] [--days N]
                              [--type server|user|none] CN|EMAIL [EMAIL|CN] [SAN ...]
simple-ca-mini.py cert pfx    [--ca-dir DIR] [--password PASS] CERT_PATH
simple-ca-mini.py serve       [--ca-dir DIR] [--address ADDRESS] [--port PORT]
simple-ca-mini.py --version
```

The commands are in the groups of `simple-ca`, `ca` and `cert`, and `serve` stands alone.
`simple-ca-mini.py -h` lists the groups, `simple-ca-mini.py GROUP -h` the commands of a group,
and `simple-ca-mini.py GROUP COMMAND -h` the options of a command.

The CA directory is `--ca-dir`, else `SIMPLE_CA_DIR`, else the working directory. A CA whose
certificate is self-signed is a root CA; any other is an issuing CA, and its root CA is in the
directory above it.

### ca create

Without `--issuing-ca`, creates the root CA in the CA directory, with a path length of 1. With
`--issuing-ca NAME`, creates an issuing CA in `CA_DIR/NAME/`, signed by the root CA in the CA
directory, with a path length of 0; `NAME` is a **kebab-case** name, such as `lab-servers`. Both
have the key usages keyCertSign and cRLSign. A CA that exists is left as it is, and
`ca_bundle.pem` is written again with the root CA and every issuing CA. `--days` defaults to
`days.ca` of `simple-ca.json`, else 3650.

`--ca-url URL` is stored in `simple-ca.json` and embeds an AIA (Authority
Information Access) extension in the issuing CAs and certificates issued from then on:
`URL/ca_cert.crt` for those signed by the root CA, `URL/NAME/ca_cert.crt` for those signed by the
issuing CA `NAME`. These are the URLs of [serve](#serve).

### cert create

The type sets the key usages and extended key usages of the certificate:

| `--type` | Key usage | Extended key usage |
|---|---|---|
| `server` (default) | digitalSignature, keyEncipherment | serverAuth, clientAuth |
| `user` | digitalSignature, contentCommitment | clientAuth, emailProtection, codeSigning |
| `none` | | |

`--type server` and `--type none` take a CN and SANs:

```sh
simple-ca-mini.py cert create [--type none] CN [SAN ...]
```

- `CN` is a hostname or an FQDN, and is also the first DNS name SAN.
- A `SAN` is a hostname, an FQDN, an IPv4 or IPv6 address, or a numeric OID.

`--type user` creates a certificate for a person:

```sh
simple-ca-mini.py cert create --type user CN|EMAIL [EMAIL|CN] [SAN ...]
```

- The first argument is the CN or the emailAddress of the subject; an argument with an `@` and a
  dot after it is an email address, anything else a CN.
- The second argument, when given, is the other of the two.
- The emailAddress is also the first email address SAN.
- A `SAN` is an email address or a numeric OID.

A numeric OID, such as `1.3.6.1.4.1.99999.1`, is a registeredID SAN; an IPv4 address, such as
`1.2.3.4`, is an IP address SAN of a server or none certificate.

The certificate is signed by the CA in the CA directory and written to that directory, or to
`--cert-dir`. A certificate that exists is left as it is. `--days` defaults to `days.cert` of
`simple-ca.json`, else 365.

```sh
simple-ca-mini.py cert create web.example.com web 192.0.2.1 2001:db8::1 1.3.6.1.4.1.99999.1
simple-ca-mini.py cert create --type user alice@example.com "Alice Example" a.example@example.org
```

### cert pfx

Creates `{name}.pfx` next to `CERT_PATH` from the certificate, its key and the chain of the CA in
the CA directory, which signed it: the root CA, and the issuing CA when the CA directory holds
one. The password defaults to `changeit` and reaches `openssl` through its environment. The
bundle is encrypted with AES-256-CBC and PBKDF2, with a SHA-256 MAC.

### serve

Serves the certificates of the root CA of the CA directory, and of all its issuing CAs, over
HTTP, until it is stopped with Ctrl-C. `--address` is the address of the interface it listens on,
`127.0.0.1` by default and `0.0.0.0` for all interfaces (`::` also works), and `--port` the TCP
port, 8080 by default.

| URL | File | Content type |
|---|---|---|
| `/` | an index page of the CAs, with links to their files | `text/html` |
| `/ca_cert.crt` | `ca_cert.pem` of the root CA, as DER | `application/pkix-cert` |
| `/ca_cert.pem` | `ca_cert.pem` of the root CA | `application/x-pem-file` |
| `/ca_bundle.pem` | `ca_bundle.pem` | `application/x-pem-file` |
| `/NAME/ca_cert.crt` | `ca_cert.pem` of the issuing CA `NAME`, as DER | `application/pkix-cert` |
| `/NAME/ca_cert.pem` | `ca_cert.pem` of the issuing CA `NAME` | `application/x-pem-file` |

The index page lists the root CA and its issuing CAs, each with its subject, issuer, validity
period, days left and SHA-256 fingerprint. The files are read on each request; any other path is
`404 Not Found`. Each request is logged to the standard error.

```sh
simple-ca-mini.py ca create --ca-dir /tmp/ca --ca-url http://pki.example.com:8080 "My Root CA"
simple-ca-mini.py serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8080
```

## simple-ca.json

The settings in the root CA directory, shared with `simple-ca`. Simple CA Mini reads:

- `ca_publish_base_url` - base URL for the AIA extension, written by `ca create --ca-url`;
- `days` - defaults for `--days`: `ca` and `cert`.

```json
{
  "ca_publish_base_url": "http://pki.example.com",
  "days": {
    "ca": 3650,
    "cert": 90
  }
}
```

## Example

```sh
mkdir -p /tmp/ca
simple-ca-mini.py ca create --ca-dir /tmp/ca "My Root CA"
simple-ca-mini.py ca create --ca-dir /tmp/ca --issuing-ca servers "My Servers CA"

export SIMPLE_CA_DIR=/tmp/ca/servers

simple-ca-mini.py cert create web.example.com web.example.com 192.168.1.1
simple-ca-mini.py cert pfx --password s3cr3t /tmp/ca/servers/web_cert.pem

openssl verify -CAfile /tmp/ca/ca_bundle.pem /tmp/ca/servers/web_cert.pem
```

## systemd

`systemd/simple-ca-mini.service` runs `serve` for a CA in `/etc/simple-ca`, on all interfaces,
port 8080, with the script installed as `/usr/local/bin/simple-ca-mini` and run as the user
`simple-ca`. The service reads the CA directory and sees the rest of the file system read-only.

```sh
sudo install -m 755 simple-ca-mini.py /usr/local/bin/simple-ca-mini
sudo useradd --system --home-dir /etc/simple-ca --no-create-home \
  --shell /usr/sbin/nologin simple-ca
sudo install -d -o simple-ca -g simple-ca -m 750 /etc/simple-ca
sudo -u simple-ca simple-ca-mini ca create --ca-dir /etc/simple-ca \
  --ca-url http://ca.example.com:8080 "My Root CA"
sudo -u simple-ca simple-ca-mini ca create --ca-dir /etc/simple-ca \
  --issuing-ca servers "My Servers CA"
sudo cp systemd/simple-ca-mini.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now simple-ca-mini.service
```

Other settings, such as the port, are changed with `systemctl edit simple-ca-mini.service`.
