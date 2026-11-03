ARG IMAGE=simple-ca:latest
FROM ${IMAGE} AS simple-ca

FROM busybox:stable-musl
COPY --from=simple-ca /usr/local/bin/simple-ca /usr/local/bin/simple-ca
COPY simple-ca-init.sh /usr/local/bin/simple-ca-init
USER 1000:1000
ENV SIMPLE_CA_DIR=/data
ENTRYPOINT ["/bin/sh", "/usr/local/bin/simple-ca-init"]
