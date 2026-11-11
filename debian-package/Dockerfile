# The builder of the Debian package of simple-ca, for the platform the image is built for. The
# programs are compiled in the image; ./build.mjs deb writes debian/changelog and the browser
# files of assets/markdown first, and buildx writes the .deb of the out stage to dist/. The
# temporary files of the build are in a tmpfs on /tmp.

FROM golang:1.27 AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        dpkg-dev \
        debhelper \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build/src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN mv debian-package/debian debian
ARG VERSION=""
RUN --mount=type=tmpfs,target=/tmp SIMPLE_CA_VERSION="$VERSION" dpkg-buildpackage -us -uc -b

FROM scratch AS out
COPY --from=build /build/*.deb /
