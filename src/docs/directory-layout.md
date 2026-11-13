---
title: Directory layout
---

```text
CA_DIR/
  simple-ca.json           settings (optional)
  theme.json               colours of the pages of the root CA (optional)
  oidc-users.json          token profiles of the OIDC sign-in and their rules (optional)
  audit.log                audit log of the root CA and its issuing CAs (audit.file)
  ca_cert.pem              root CA certificate
  ca_key.pem               root CA private key
  ca_bundle.pem            root and all issuing CA certificates concatenated
  index.txt                certificates issued by the root CA
  index.txt.attr           attributes of index.txt
  crlnumber                next CRL number of the root CA
  crl.pem                  root CA CRL (ca create, crl create)
  openssl.cnf              configuration of openssl ca (ca create --write-conf)
  acme.json                ACME accounts and orders of the root CA (serve)
  tokens-db.json           tokens of the root CA (token create)
  tokens-db.json.lock      lock of tokens-db.json while it is changed
  {name}_cert.pem          certificate issued by the root CA
  {name}_key.pem           key of a certificate issued by the root CA
  {name}.pfx               PKCS#12 bundle (cert pfx)
  {issuing-ca}/
    theme.json             colours of the pages of the issuing CA (optional)
    ca_cert.pem            issuing CA certificate
    ca_key.pem             issuing CA private key
    index.txt              certificates issued by the issuing CA
    index.txt.attr         attributes of index.txt
    crlnumber              next CRL number of the issuing CA
    crl.pem                issuing CA CRL (ca create, crl create)
    openssl.cnf            configuration of openssl ca (ca create --write-conf)
    acme.json              ACME accounts and orders of the issuing CA (serve)
    tokens-db.json         tokens of the issuing CA (token create)
    tokens-db.json.lock    lock of tokens-db.json while it is changed
    {name}_cert.pem        certificate issued by the issuing CA
    {name}_key.pem         key of a certificate issued by the issuing CA
    {name}.pfx             PKCS#12 bundle (cert pfx)
```

`{name}` follows the name rules of the certificate type: with the server rules, of the types
`server` and `none` and of a type of `simple-ca.json` without other rules, it is the CN up to its
first dot; with the user rules, it is the CN, or the part of the emailAddress before the `@` when
there is no CN. Each run of characters other than letters, digits, hyphens and underscores
becomes one `_`, without a leading or trailing `_`: `web.example.com` is written as
`web_cert.pem`, `Alice Example` as `Alice_Example_cert.pem` and `a.example@example.org` as
`a_example_cert.pem`.

`cert sign` names the certificate after the request file, as described under
[cert sign](usage.md#cert-sign), and the [signing API](signing-api.md) after the `name` of the
request, cleaned the same way. The signing form names it by the rules of its type after the CN of
the request, without a leading `*.`, else its first DNS name, and its emailAddress or first email
address; a request that gives no name is named after the serial. The [ACME](acme.md) server names
it after the first name of the order, by the server rules.

The signing API, the signing form and the ACME server store the certificate as `{name}_cert.pem`
too, without a key, which stays with the client, so the
[certificate page](usage.md#certificate-page) can show it. For them and for `cert sign`, the
newest certificate of a name replaces the file of the one before it, which `index.txt` still
lists, and the name `ca`, whose file is the CA certificate, is refused.

The keys, `ca_key.pem` and `{name}_key.pem`, are PKCS#8 PEM files with the private mode of
[File modes and a shared CA](usage.md#file-modes-and-a-shared-ca), by default 0600, encrypted with
the passphrase of the private keys when it is set, as described under
[Encrypted private keys](usage.md#encrypted-private-keys).

Use `ca_bundle.pem` with `openssl verify -CAfile CA_DIR/ca_bundle.pem`; this works the same on
Linux, macOS and Windows without hash symlinks.

## Certificate database

Every CA directory holds the database of `openssl ca`, so the directory can also be used with
`openssl ca` and `openssl ocsp -index`:

- `index.txt` - one line per certificate the CA issued, the issuing CAs included in that of the
  root CA, with six tab-separated fields: status (`V` valid, `R` revoked, `E` expired, which
  simple-ca reads but does not write), expiry, revocation, serial in hex, file name (`unknown`) and
  subject. The revocation is the date, followed by `,` and the reason when one is recorded. The
  dates are UTCTime, `YYMMDDHHMMSSZ`; an expiry from 2050 on is GeneralizedTime,
  `YYYYMMDDHHMMSSZ`. While simple-ca changes it, `index.txt.lock` holds the PID of the process
  that does, as `tokens-db.json.lock` does for the tokens; a lock left by a process that is gone
  is removed by hand.
- `index.txt.attr` - `unique_subject = no`, so a subject can be issued again.
- `crlnumber` - the number of the next CRL, in hex.

```text
V	271030213502Z		57926D0E17563988B2B8B0CCD8301FD9C2895CF8	unknown	/CN=web.example.com
R	271030213502Z	261030213502Z	1A4793AE63C220A5B05D59EBCB19B0B0C2AA8E65	unknown	/CN=alice.example.com
```

`ca create --write-conf` writes a configuration of `openssl ca` for the CA directory, `openssl.cnf`.
