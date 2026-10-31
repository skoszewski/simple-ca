# ACME

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
extended key usages, AIA and CRL Distribution Point URLs are those of `cert create`. It is recorded
in `index.txt` like any other. The chain returned holds the certificate and, from an issuing CA,
the issuing CA certificate. A certificate is revoked by the account it was issued to, or with its
key, for a reason from 0 to 5, as for `cert revoke`; `crl create` writes the CRL listing it.

The accounts, the orders and the authorizations of a CA are kept in `acme.json` of its directory,
so `serve` needs to write to the CA directories and read the CA keys. An order and its
authorizations expire 7 days after they are made. Nonces are kept in memory; after a restart, a
client retries a request with a new nonce.

The ACME clients require HTTPS, so `serve` is run with a certificate of the CA, which the clients
must trust. With [lego](https://go-acme.github.io/lego/), `LEGO_CA_CERTIFICATES` names the root CA
certificate:

```sh
simple-ca cert create --ca-dir /tmp/ca --cert-dir /tmp pki.example.com
simple-ca serve --ca-dir /tmp/ca --address 0.0.0.0 --port 8443 \
  --tls-cert /tmp/pki_cert.pem --tls-key /tmp/pki_key.pem
LEGO_CA_CERTIFICATES=/tmp/ca/ca_cert.pem lego run --accept-tos --email admin@example.com \
  --server https://pki.example.com:8443/servers/acme/directory --domains web.example.com --http
```
