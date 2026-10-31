# Docker

The `Dockerfile` builds an image of `simple-ca` alone: the static executable on
`gcr.io/distroless/static-debian13:nonroot`, run as the user `nonroot` (uid 65532). The CA
directory is `/data`, a volume, and `SIMPLE_CA_DIR` points at it, so every command works with the
CA there. Without arguments the container runs `serve` on all interfaces, port 8080; with
arguments it runs them as a command. `VERSION` sets the version `--version` prints.

```sh
docker build --build-arg VERSION=v1.3.0 -t simple-ca .
docker volume create simple-ca
docker run --rm -v simple-ca:/data simple-ca ca create \
  --ca-publish-base-url http://pki.example.com:8080 "My Root CA"
docker run --rm -v simple-ca:/data simple-ca ca create --issuing-ca servers "My Servers CA"
docker run -d --name simple-ca -p 8080:8080 -v simple-ca:/data simple-ca
docker exec simple-ca simple-ca cert list --ca-dir /data/servers
```

A new named volume is writable by `nonroot`. A host directory mounted at `/data` must be writable
by uid 65532, or the container is run with `--user` of the owner of the directory. `serve` writes
`acme.json` and `tokens-db.json` to the CA directories, so `/data` is mounted read-write. With
`--tls-cert` and `--tls-key`, the certificate and the key are files of the volume or of another
mount:

```sh
docker run -d -p 8443:8443 -v simple-ca:/data simple-ca serve --address 0.0.0.0 --port 8443 \
  --tls-cert /data/servers/pki_cert.pem --tls-key /data/servers/pki_key.pem
```
