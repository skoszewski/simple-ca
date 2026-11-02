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

## Getting a certificate with lego

The ACME clients require HTTPS, so `serve` is run with a certificate the clients trust: one of a
CA they trust already, or one of its own CA, whose root CA certificate the clients are given.
These steps give `web.example.com` a certificate of the issuing CA `servers` with
[lego](https://go-acme.github.io/lego/) 5, which `serve` on `pki.example.com` issues.

1. On `pki.example.com`, create the CAs and let the ACME server issue certificates for
   `example.com` and the names below it, with `acme.domains` in `simple-ca.json`:

   ```sh
   mkdir -p /etc/simple-ca
   simple-ca ca create --ca-dir /etc/simple-ca "Example Root CA"
   simple-ca ca create --ca-dir /etc/simple-ca --issuing-ca servers "Example Servers CA"
   cat > /etc/simple-ca/simple-ca.json <<'EOF'
   {
     "acme": {"domains": ["example.com"]}
   }
   EOF
   ```

2. Run `serve` over HTTPS, with `--tls-cert`, the certificate of `pki.example.com` followed by
   the CA certificates of its chain, and `--tls-key`, its key. It is either a certificate the
   host has, from a CA the clients trust, or one of its own CA, which these commands make:

   ```sh
   simple-ca cert create --ca-dir /etc/simple-ca --cert-dir /etc/simple-ca pki.example.com
   simple-ca serve --ca-dir /etc/simple-ca --address 0.0.0.0 --port 8443 \
     --tls-cert /etc/simple-ca/pki_cert.pem --tls-key /etc/simple-ca/pki_key.pem
   ```

3. With a certificate of its own CA, lego must trust the root CA: on `web.example.com`, copy the
   root CA certificate, `/etc/simple-ca/ca_cert.pem`, of `pki.example.com`, or download
   `https://pki.example.com:8443/ca_cert.pem` and compare its fingerprint with the one
   `simple-ca ca show` prints, and name it in `LEGO_CA_CERTIFICATES`. With a certificate of a CA
   lego trusts already, this step is left out.

   ```sh
   export LEGO_CA_CERTIFICATES=/etc/ssl/simple-ca-root.pem
   ```

4. Get the certificate. With `--http`, lego answers the `http-01` challenge on port 80 of
   `web.example.com`, which `serve` must reach, and so runs as root, or with `--http.address`
   on another port that port 80 is forwarded to:

   ```sh
   lego run --accept-tos --email admin@example.com \
     --server https://pki.example.com:8443/servers/acme/directory \
     --domains web.example.com --domains www.example.com --http
   ```

   lego writes the certificate, with the issuing CA certificate after it, to
   `.lego/certificates/web.example.com.crt`, its key to `web.example.com.key` and the issuing CA
   certificate to `web.example.com.issuer.crt`; `--path` names another directory than `.lego`.
   The certificate is also listed by `simple-ca cert list --ca-dir /etc/simple-ca/servers`.

5. For a wildcard name, `*.example.com`, use the `dns-01` challenge: `--dns` names lego's
   provider of the DNS zone, `lego dnshelp` lists them, and the TXT record must reach the
   resolver of `pki.example.com`:

   ```sh
   lego run --accept-tos --email admin@example.com \
     --server https://pki.example.com:8443/servers/acme/directory \
     --domains '*.example.com' --dns cloudflare
   ```

`lego run` with the same options renews the certificate once a third of its validity is left, and
with `--renew-force` at once. `lego certificates revoke` revokes it, with a reason from 0 to 5,
and `simple-ca crl create` publishes the revocation:

```sh
lego certificates revoke --email admin@example.com \
  --server https://pki.example.com:8443/servers/acme/directory --cert.name web.example.com --reason 4
simple-ca crl create --ca-dir /etc/simple-ca/servers
```

## Renewing with systemd

`examples/simple-ca-lego.sh` runs the `lego run` of step 4 with the settings of the environment,
and `systemd/simple-ca-lego.service` and `systemd/simple-ca-lego.timer` run it daily on
`web.example.com`, so the certificate is renewed when it is due; lego leaves it as it is until
then. The service runs as root, to answer the `http-01` challenge on port 80 and to run the
deploy hook, and reads its settings from `/etc/simple-ca-lego.env`:

```sh
LEGO_SERVER=https://pki.example.com:8443/servers/acme/directory
LEGO_EMAIL=admin@example.com
LEGO_DOMAINS=web.example.com,www.example.com
LEGO_CA_CERTIFICATES=/etc/ssl/simple-ca-root.pem
LEGO_DEPLOY_HOOK="systemctl reload nginx"
```

- `LEGO_SERVER`, `LEGO_EMAIL` and `LEGO_DOMAINS` are required: the ACME directory of the CA, the
  contact of the account and the names of the certificate, comma-separated.
- `LEGO_CA_CERTIFICATES` is the root CA certificate the certificate of `serve` chains to, when
  it is a certificate of its own CA, as in step 3; it is left out for a certificate of a CA lego
  trusts already.
- `LEGO_PATH` is the directory of the account and the certificates, `/var/lib/lego` by default:
  the certificate is `/var/lib/lego/certificates/web.example.com.crt` and its key
  `web.example.com.key`, which the server is configured to read.
- `LEGO_HTTP_ADDRESS` is the address the `http-01` challenge is answered on, `:80` by default;
  `LEGO_DNS` names the provider of the `dns-01` challenge instead, with the variables of the
  provider that `lego dnshelp` lists.
- `LEGO_DEPLOY_HOOK` runs once a certificate is obtained or renewed, to make its server use it.

```sh
sudo install -m 755 examples/simple-ca-lego.sh /usr/local/bin/simple-ca-lego
sudo install -m 600 simple-ca-lego.env /etc/simple-ca-lego.env
sudo cp systemd/simple-ca-lego.service systemd/simple-ca-lego.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start simple-ca-lego.service
sudo systemctl enable --now simple-ca-lego.timer
```

The first start of the service gets the certificate; `journalctl -u simple-ca-lego.service` shows
what lego did.
