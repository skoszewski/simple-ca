# The builder of the signed flat apt repository of ./build.mjs apt, from the .deb files in debs/
# of its context; the out stage holds the repository. The key and its passphrase are the build
# secrets gpg_key and gpg_passphrase, and the temporary files are in a tmpfs on /tmp.

FROM debian:trixie AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        apt-utils \
        gnupg \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
COPY debs/ ./
COPY apt-repo/build-repo.sh /usr/local/bin/
RUN --mount=type=secret,id=gpg_key,required=true --mount=type=secret,id=gpg_passphrase \
    --mount=type=tmpfs,target=/tmp sh /usr/local/bin/build-repo.sh

FROM scratch AS out
COPY --from=build /repo /
