# systemd

`systemd/` holds units for a CA in `/etc/simple-ca` and the executable in
`/usr/local/bin/simple-ca`, both run as the user `simple-ca`:

- `simple-ca.service` runs `serve` on all interfaces, port 8080, with write access to
  `/etc/simple-ca` for [ACME](acme.md) and the [signing API](signing-api.md); `--tls-cert` and
  `--tls-key` are added to its command with `systemctl edit simple-ca.service`;
- `simple-ca-crl.service` runs `crl create --all`, for the root CA in `/etc/simple-ca` and its
  issuing CAs;
- `simple-ca-crl.timer` starts `simple-ca-crl.service` daily, and on boot when a run was missed.

`systemd/simple-ca-mini.service` runs the `serve` command of [Simple CA Mini](simple-ca-mini.md)
instead; its installation is in [simple-ca-mini.md](simple-ca-mini.md#systemd).

```sh
sudo install -m 755 simple-ca /usr/local/bin/simple-ca
sudo useradd --system --home-dir /etc/simple-ca --no-create-home \
  --shell /usr/sbin/nologin simple-ca
sudo install -d -o simple-ca -g simple-ca -m 750 /etc/simple-ca
sudo -u simple-ca simple-ca ca create --ca-dir /etc/simple-ca \
  --ca-publish-base-url http://ca.example.com:8080 "My Root CA"
sudo -u simple-ca simple-ca ca create --ca-dir /etc/simple-ca --issuing-ca servers "My Servers CA"
sudo cp systemd/simple-ca.service systemd/simple-ca-crl.service systemd/simple-ca-crl.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now simple-ca.service simple-ca-crl.timer
```

The CRL is renewed daily, well within `days.crl`, 30 days by default. Other settings, such as
the port, are changed with `systemctl edit simple-ca.service`.
