# The image simple-ca-builder of ./build.mjs setup; ./build.mjs apt runs
# /usr/local/bin/build-repo.sh in it, which builds the signed flat apt repository.

FROM ubuntu:26.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        apt-utils \
        gnupg \
 && rm -rf /var/lib/apt/lists/*
COPY build-repo.sh /usr/local/bin/
