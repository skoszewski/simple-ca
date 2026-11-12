# The image simple-ca-builder of ./build.mjs build-helpers, the Linux toolset of build.mjs; its
# tools are in /usr/local/bin: build-repo.sh, the signed flat apt repository of ./build.mjs apt.

FROM ubuntu:26.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        apt-utils \
        gnupg \
 && rm -rf /var/lib/apt/lists/*
COPY build-repo.sh /usr/local/bin/
