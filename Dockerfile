# simple-ca in a container: the static executable on distroless, run as the user nonroot (uid
# 65532), with the CA directory /data on a volume. Without arguments it runs serve on port 8080;
# with arguments it runs them as a command, such as "ca create NAME". The Go client of the signing
# API, request-cert, is installed beside it.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd/request-cert ./cmd/request-cert
COPY assets ./assets
COPY templates ./templates
COPY help ./help
COPY docs/*.md ./docs/
# The browser files of serve-markdown's page for /help/ and /docs/, from the release go.mod names.
RUN tag="$(go list -m -f '{{.Version}}' github.com/skoszewski/serve-markdown/v3)" \
    && find assets/markdown -mindepth 1 ! -name .gitkeep -delete \
    && curl -fsSL "https://github.com/skoszewski/serve-markdown/releases/download/$tag/serve-markdown-assets-${tag#v}.tar.gz" \
    | tar -xz -C assets/markdown
ARG VERSION=""
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.buildVersion=${VERSION}" -o /out/simple-ca . \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.buildVersion=${VERSION}" -o /out/request-cert ./cmd/request-cert \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/simple-ca /usr/local/bin/simple-ca
COPY --from=build /out/request-cert /usr/local/bin/request-cert
# A new named volume takes the owner of /data, so nonroot can write the CA to it.
COPY --from=build --chown=65532:65532 /out/data /data
ENV SIMPLE_CA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/simple-ca"]
CMD ["serve", "--address", "0.0.0.0", "--port", "8080"]
