---
title: Docker
---

The `Dockerfile` builds an image of `simple-ca`: the static executable on
`gcr.io/distroless/static-debian13`, run as the user and group 1000, the first user of Ubuntu, with
`request-cert`, the Go [client of the signing API](examples.md), `token-setup`, which exchanges
a setup code for its token, `request-token`, which gets the JWTs of workload identity
federation and the access tokens of the clouds, and `simple-ca-wif`, which sets up Google
workload identity federation, beside it. The CA
directory is `/data`, a volume, and `SIMPLE_CA_DIR` points at it, so every command works with the
CA there. Without arguments the container runs `serve` on all interfaces, port 8080; with
arguments it runs them as a command. `VERSION` sets the version `--version` prints. The build
downloads the browser files of the `/help/` and `/docs/` pages from the serve-markdown release
`go.mod` names (see [Development](development.md)).

`./build.mjs docker` builds it with `docker buildx build`, as `simple-ca:X.Y.Z`, the version of
the newest `CHANGELOG.md` entry, and `simple-ca:latest`, with `VERSION` set to `vX.Y.Z`;
`--registry REGISTRY`, or else `SIMPLE_CA_REGISTRY` when it is set, puts both below the registry,
as `REGISTRY/simple-ca:X.Y.Z`. The image is for the platform of the Docker engine, which may be
a remote host of the docker context, and a platform such as `linux/arm64` builds for it instead.
The build stage runs on the platform of the engine and cross-compiles the programs, so a platform
of another architecture needs no emulation on the engine. `--push` pushes the image too.

`./build.mjs container` builds the same image on the local Mac with Apple's `container` CLI, for
the platform of its Linux VM unless a platform is named, and takes the same options; `--push`
pushes both tags with `container image push`. The image is then run with `container run`.

Both take a comma-separated list of platforms for a multi-platform image, one image index with
an image of each platform:

```sh
PLATFORMS=linux/amd64,linux/arm64

./build.mjs container --push "$PLATFORMS"
```

The build stage of each platform runs on the platform of the builder and cross-compiles. A
multi-platform image of `docker` needs a buildx builder that supports multi-platform builds.

```sh
IMAGE=${SIMPLE_CA_REGISTRY:+$SIMPLE_CA_REGISTRY/}simple-ca

./build.mjs docker
docker volume create simple-ca
docker run --rm -v simple-ca:/data "$IMAGE" ca create \
  --ca-url http://pki.example.com:8080 "My Root CA"
docker run --rm -v simple-ca:/data "$IMAGE" ca create --issuing-ca servers "My Servers CA"
docker run -d --name simple-ca -p 8080:8080 -v simple-ca:/data "$IMAGE"
docker exec simple-ca simple-ca cert list --ca-dir /data/servers
```

`IMAGE` is the name of the image `./build.mjs docker` builds, below `SIMPLE_CA_REGISTRY` when it
is set; the later examples call it `simple-ca`.

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

## simple-ca-full

`--full` adds a second image to `./build.mjs docker` and `./build.mjs container`:
`simple-ca-full:X.Y.Z` and `simple-ca-full:latest`, built by `Dockerfile.full` from
`simple-ca:X.Y.Z` of the same build, below the same registry, and pushed with it by `--push`. It
adds one layer:

- the release archives of `X.Y.Z`, `simple-ca-X.Y.Z-*.tar.gz` and `simple-ca-lite-X.Y.Z-*.tar.gz`
  and their `.zip` files, with a `.sha256` file written for each, in `/srv/simple-ca/downloads`;
  archives of other versions in the directory are left out;
- the apt repository of `./build.mjs apt` in `/srv/simple-ca/apt`.

Its command replaces the one of `simple-ca`: without arguments, the container runs `serve` on
port 8080 with `--downloads /srv/simple-ca/downloads` and `--packages /srv/simple-ca/apt`, so it
offers the archives at `/downloads/` and the repository, with its setup page, at `/apt/` (see
[serve](serve.md#downloads)). `--full` takes the directory of the archives, `dist/` by default,
and that of the repository, `apt/` by default, and refuses to build when the first holds no
archive of `X.Y.Z` or the second has no `Release`, `InRelease` or `key.asc`. The repository is
copied as it is, so it is built for the same version first with `./build.mjs apt`.

The archives of every platform and the Debian packages come first, see
[Development](development.md#building): built on macOS before the version is tagged, and
downloaded from its GitHub release after it:

```sh
./build.mjs dist --all --dpkg
```

The repository is signed with the gpg key of [Development](development.md#building). A key
without a passphrase:

```sh
SIMPLE_CA_GPG_KEY_FILE=$HOME/.config/simple-ca/apt-signing-key.asc

./build.mjs apt --key "$SIMPLE_CA_GPG_KEY_FILE"
```

A key with a passphrase, held in a file of its own:

```sh
SIMPLE_CA_GPG_KEY_FILE=$HOME/.config/simple-ca/apt-signing-key.asc
SIMPLE_CA_GPG_PASSPHRASE_FILE=$HOME/.config/simple-ca/apt-signing-key.pass

./build.mjs apt --key "$SIMPLE_CA_GPG_KEY_FILE" --passphrase-file "$SIMPLE_CA_GPG_PASSPHRASE_FILE"
```

Then both images are built, and `simple-ca-full` is run. As with `simple-ca`, `serve` needs a CA
in `/data`, so the CA is created first:

```sh
IMAGE=${SIMPLE_CA_REGISTRY:+$SIMPLE_CA_REGISTRY/}simple-ca-full

./build.mjs docker --full
docker volume create simple-ca
docker run --rm -v simple-ca:/data "$IMAGE" ca create \
  --ca-url http://pki.example.com:8080 "My Root CA"
docker run -d --name simple-ca -p 8080:8080 -v simple-ca:/data "$IMAGE"
```

`IMAGE` is the name `build.mjs` gives the image, below `SIMPLE_CA_REGISTRY` when it is set; with
`--registry REGISTRY`, it is `REGISTRY/simple-ca-full`.

Built on another host before the tag, the `darwin` archives lack `simple-ca-trust`, and the
packages are those of the architecture of the Docker engine; without `--all`, `./build.mjs dist`
writes the archives of the host only. The image offers what `dist/` holds.

The `FROM` of `Dockerfile.full` reads `simple-ca:X.Y.Z` where the builder reads images: the local images for the `docker`
driver of buildx and for the `container` CLI, and the registry for a `docker-container` builder,
so that a multi-platform build of `docker` needs `--push`, which pushes `simple-ca` before
`simple-ca-full` is built.

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
