---
title: Docker
---

The `Dockerfile` builds an image of `simple-ca`: the static executable on
`gcr.io/distroless/static-debian13`, run as the user and group 1000, the first user of Ubuntu, with
`request-cert`, the Go [client of the signing API](examples.md), `token-setup`, which exchanges
a setup code for its token, and `request-jwt`, which gets the JWTs of workload identity
federation, beside it. The CA
directory is `/data`, a volume, and `SIMPLE_CA_DIR` points at it, so every command works with the
CA there. Without arguments the container runs `serve` on all interfaces, port 8080; with
arguments it runs them as a command. `VERSION` sets the version `--version` prints. The build
downloads the browser files of the `/help/` and `/docs/` pages from the serve-markdown release
`go.mod` names (see [Development](development.md)).

`./build.mjs docker` builds it with `docker buildx build`, as `simple-ca:X.Y.Z`, the version of
the newest `CHANGELOG.md` entry, and `simple-ca:latest`, with `VERSION` set to `vX.Y.Z`;
`--registry REGISTRY`, or else `SIMPLE_CA_REGISTRY` when it is set, puts both below the registry,
as `REGISTRY/simple-ca:X.Y.Z`, and a platform such as `linux/arm64` builds for it. `--push` pushes
the image too.

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
run with `--user` of the owner of the directory. `serve` writes `acme.json`, `tokens-db.json`,
`audit.log` and the files of the certificates it issues, such as `index.txt`, to the CA
directories, so `/data` is mounted read-write. With
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
CA_URL=https://pki.example.com:8443/servers
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work -e SIMPLE_CA_TOKEN \
  --entrypoint request-cert simple-ca "$CA_URL" web.example.com
```

With [encrypted private keys](usage.md#encrypted-private-keys), a container without a terminal
gets the passphrase from a file, mounted read-only and readable by the user of the container, and
named by `SIMPLE_CA_KEY_PASSWORD_FILE`:

```sh
KEY_PASSWORD_FILE=$HOME/.config/simple-ca/key-password
docker run -d -p 8080:8080 -v simple-ca:/data -v "$KEY_PASSWORD_FILE:/run/secrets/key-password:ro" \
  -e SIMPLE_CA_KEY_PASSWORD_FILE=/run/secrets/key-password simple-ca serve --address 0.0.0.0
```

## Docker Compose

`examples/compose.yaml` runs the image of `./build.mjs docker` as the service `simple-ca`, with
`serve --webui` on port 8080 and the CA directory in the named volume `simple-ca`. The other
commands run in the same volume with `docker compose run`, whose arguments replace the command of
the service:

```sh
./build.mjs docker
docker compose -f examples/compose.yaml run --rm simple-ca ca create \
  --ca-url http://pki.example.com:8080 "My Root CA"
docker compose -f examples/compose.yaml run --rm simple-ca ca create \
  --issuing-ca servers "My Servers CA"
docker compose -f examples/compose.yaml run --rm simple-ca token create \
  --scope tokens --scope certs --scope audit admin
docker compose -f examples/compose.yaml up -d
```

The index page is at `http://pki.example.com:8080/`, and the token, certificate and audit pages
ask for the token `admin`. For an image of a registry, `image` names it, such as
`registry.example.com/simple-ca:latest` for `./build.mjs docker --registry registry.example.com
--push`.

`serve` writes every record of its [log](serve.md), its start, pages, warnings, errors, requests
and [audit records](audit.md), to the standard error, so
`docker compose -f examples/compose.yaml logs simple-ca` shows them; the audit records also go
to `audit.log`, in the volume unless `audit.file` of `simple-ca.json` names another path. The
records of the commands of `docker compose run` are in `audit.log` alone.

## Kubernetes

`kubernetes/kubernetes.yaml` runs the same image in Kubernetes: the claim `simple-ca` holds the CA
directory, and the Deployment `simple-ca` runs `serve --webui` on it, behind the Service
`simple-ca` on port 8080. Before `serve` starts, its init container creates what the CA
directory lacks, so it does nothing on later starts:

- the root CA `SIMPLE_CA_ROOT_NAME`;
- the issuing CA `SIMPLE_CA_ISSUING_CA`, named `SIMPLE_CA_ISSUING_NAME`, when it is set.

The init container runs the image `simple-ca-init`: `kubernetes/simple-ca-init.sh` with busybox and
the `simple-ca` executable of the image `simple-ca`, which `IMAGE` names, `simple-ca:latest` by
default:

```sh
./build.mjs docker
docker buildx build -t simple-ca-init:latest kubernetes
kubectl apply -f kubernetes/kubernetes.yaml
kubectl port-forward service/simple-ca 8080:8080
```

With the port forwarded, the index page is at `http://127.0.0.1:8080/`. A token of the token,
certificate and audit pages is made when one is needed, in the running container:

```sh
kubectl exec deployment/simple-ca -- \
  simple-ca token create --valid 8h --scope tokens --scope certs --scope audit alice
```

The nodes of the cluster must have both images; for images
of a registry, `image` names them, and `--build-arg IMAGE=registry.example.com/simple-ca:latest`
builds the init image on the image of the registry.
