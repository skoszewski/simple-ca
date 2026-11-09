---
title: systemd
---

`systemd/` holds units for a CA in `/etc/simple-ca` and the executable in
`/usr/local/bin/simple-ca`, both run as the user `simple-ca`:

- `simple-ca.service` runs `serve --webui` on all interfaces, port 8080, with write access to
  `/etc/simple-ca` for [ACME](acme.md), the [signing API](signing-api.md), the
  [pages](#token-certificate-and-audit-pages) and `audit.log`, and with access to the Unix socket
  of the journal; `SIMPLE_CA_TLS_CERT` and `SIMPLE_CA_TLS_KEY`, set with
  `systemctl edit simple-ca.service`, serve it over HTTPS;
- `simple-ca-crl.service` runs `crl create --all`, for the root CA in `/etc/simple-ca` and its
  issuing CAs;
- `simple-ca-crl.timer` starts `simple-ca-crl.service` daily, and on boot when a run was missed.

`systemd/simple-ca-mini.service` runs the `serve` command of [Simple CA Mini](simple-ca-mini.md)
instead; its installation is in [simple-ca-mini.md](simple-ca-mini.md#systemd).

`systemd/simple-ca-lego.service` and `systemd/simple-ca-lego.timer` are for a client of the ACME
server instead: they get and renew the certificate of its host daily with lego and
`examples/simple-ca-lego.sh`; their installation is in [ACME](acme.md#renewing-with-systemd).

```sh
sudo install -m 755 simple-ca /usr/local/bin/simple-ca
sudo useradd --system --home-dir /etc/simple-ca --no-create-home \
  --shell /usr/sbin/nologin simple-ca
sudo install -d -o simple-ca -g simple-ca -m 750 /etc/simple-ca
sudo -u simple-ca simple-ca ca create --ca-dir /etc/simple-ca \
  --ca-url http://ca.example.com:8080 "My Root CA"
sudo -u simple-ca simple-ca ca create --ca-dir /etc/simple-ca --issuing-ca servers "My Servers CA"
sudo cp systemd/simple-ca.service systemd/simple-ca-crl.service systemd/simple-ca-crl.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now simple-ca.service simple-ca-crl.timer
```

The CRL is renewed daily, well within `days.crl`, 30 days by default. Other settings, such as
the port, are changed with `systemctl edit simple-ca.service`.

## Encrypted keys

With [encrypted private keys](usage.md#encrypted-private-keys), both services need the
passphrase, since neither has a terminal to ask at. `key encrypt` asks for it on the terminal,
and a file readable by root alone keeps it for the services:

```sh
sudo -u simple-ca simple-ca key encrypt --ca-dir /etc/simple-ca --all
sudo install -m 600 /dev/null /etc/simple-ca-key-password
sudoedit /etc/simple-ca-key-password
```

A credential passes the file to each service, in a drop-in of each, made with
`sudo systemctl edit simple-ca.service` and `sudo systemctl edit simple-ca-crl.service`:

```ini
[Service]
LoadCredential=key-password:/etc/simple-ca-key-password
Environment=SIMPLE_CA_KEY_PASSWORD_FILE=%d/key-password
```

## Log and audit records

`serve` sends every record of its [log](serve.md), its start, pages, warnings, errors, requests
and [audit records](audit.md), to the systemd journal by its native protocol, besides writing
the audit records to `audit.log`. Each key is a journal field named `SIMPLE_CA_` and the key in
upper case, with `PRIORITY` `err`, `warning` or `info` and `SYSLOG_IDENTIFIER=simple-ca`, as
described under [the journal and containers](audit.md#the-journal-and-containers):

```sh
journalctl -u simple-ca SIMPLE_CA_EVENT=cert.issue
```

## Token, certificate and audit pages

`simple-ca.service` runs `serve` with `--webui`, so the
[token page](signing-api.md#token-page), the [certificate page](usage.md#certificate-page) and
the [audit page](audit.md#the-audit-page) are at `http://pki.example.com:8080/tokens/`,
`http://pki.example.com:8080/certificates/` and `http://pki.example.com:8080/audit/`. They ask
for a token; this command makes the first one, with the scopes of the three pages:

```sh
sudo -u simple-ca simple-ca token create --ca-dir /etc/simple-ca --valid 720h \
  --scope tokens --scope certs --scope audit admin
```

Over plain HTTP the tokens cross the network in clear. To serve the pages over HTTPS, make a
certificate of the host and name it and its key in a drop-in, made with
`sudo systemctl edit simple-ca.service`, then restart the service; the browsers that open the
pages then trust the root CA certificate, `/etc/simple-ca/ca_cert.pem`, for example with
[simple-ca-trust](trust.md):

```sh
sudo -u simple-ca simple-ca cert create --ca-dir /etc/simple-ca --cert-dir /etc/simple-ca \
  pki.example.com
```

```ini
[Service]
Environment=SIMPLE_CA_TLS_CERT=/etc/simple-ca/pki_cert.pem
Environment=SIMPLE_CA_TLS_KEY=/etc/simple-ca/pki_key.pem
```
