# simple-ca in a container: the static executable on distroless, run as the user and group 1000,
# the first user of Ubuntu, with the CA directory /data on a volume. Without arguments it runs
# serve on port 8080;
# with arguments it runs them as a command, such as "ca create NAME". The Go client of the signing
# API, request-cert, and token-setup, which exchanges a setup code, are installed beside it.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd/request-cert ./cmd/request-cert
COPY cmd/token-setup ./cmd/token-setup
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
    && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.buildVersion=${VERSION}" -o /out/token-setup ./cmd/token-setup \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian13
COPY --from=build /out/simple-ca /usr/local/bin/simple-ca
COPY --from=build /out/request-cert /usr/local/bin/request-cert
COPY --from=build /out/token-setup /usr/local/bin/token-setup
# A new named volume takes the owner of /data, so the user 1000 can write the CA to it.
COPY --from=build --chown=1000:1000 /out/data /data
USER 1000:1000
ENV SIMPLE_CA_DIR=/data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/simple-ca"]
CMD ["serve", "--address", "0.0.0.0", "--port", "8080"]
