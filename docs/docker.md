# Docker

The `Dockerfile` builds an image of `simple-ca`: the static executable on
`gcr.io/distroless/static-debian13`, run as the user and group 1000, the first user of Ubuntu, with
`request-cert`, the Go [client of the signing API](examples.md), beside it. The CA
directory is `/data`, a volume, and `SIMPLE_CA_DIR` points at it, so every command works with the
CA there. Without arguments the container runs `serve` on all interfaces, port 8080; with
arguments it runs them as a command. `VERSION` sets the version `--version` prints. The build
downloads the browser files of the `/help/` and `/docs/` pages from the serve-markdown release
`go.mod` names (see [Development](development.md)).

`./build.mjs docker` builds it with `docker buildx build`, as `simple-ca:X.Y.Z`, the version of
the newest `CHANGELOG.md` entry, and `simple-ca:latest`, with `VERSION` set to `vX.Y.Z`;
`--registry REGISTRY` puts both below the registry, as `REGISTRY/simple-ca:X.Y.Z`, and a platform
such as `linux/arm64` builds for it. `--push` pushes the image too.

```sh
./build.mjs docker
docker volume create simple-ca
docker run --rm -v simple-ca:/data simple-ca ca create \
  --ca-url http://pki.example.com:8080 "My Root CA"
docker run --rm -v simple-ca:/data simple-ca ca create --issuing-ca servers "My Servers CA"
docker run -d --name simple-ca -p 8080:8080 -v simple-ca:/data simple-ca
docker exec simple-ca simple-ca cert list --ca-dir /data/servers
```

A new named volume is writable by the user 1000. A host directory mounted at `/data` must be
writable by uid 1000, as a directory of the first user of an Ubuntu host is, or the container is
run with `--user` of the owner of the directory. `serve` writes
`acme.json` and `tokens-db.json` to the CA directories, so `/data` is mounted read-write. With
`--tls-cert` and `--tls-key`, the certificate and the key are files of the volume or of another
mount:

```sh
docker run -d -p 8443:8443 -v simple-ca:/data simple-ca serve --address 0.0.0.0 --port 8443 \
  --tls-cert /data/servers/pki_cert.pem --tls-key /data/servers/pki_key.pem
```

`SIMPLE_CA_TLS_CERT` and `SIMPLE_CA_TLS_KEY` name them in the environment instead:

```sh
docker run -d -p 8443:8443 -v simple-ca:/data -e SIMPLE_CA_TLS_CERT=/data/servers/pki_cert.pem \
  -e SIMPLE_CA_TLS_KEY=/data/servers/pki_key.pem simple-ca serve --address 0.0.0.0 --port 8443
```

`request-cert` runs with `--entrypoint`. It writes the key, the certificate and the chain to its
working directory, so a host directory is mounted there, with `--user` of its owner:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work -e SIMPLE_CA_TOKEN \
  --entrypoint request-cert simple-ca https://pki.example.com:8080/servers/api/sign web.example.com
```
