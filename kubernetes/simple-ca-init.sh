#!/bin/sh
# Creates the CAs of the environment that $SIMPLE_CA_DIR lacks.
set -eu

dir="${SIMPLE_CA_DIR:?SIMPLE_CA_DIR is required}"

if [ ! -f "$dir/ca_cert.pem" ]; then
  simple-ca ca create "${SIMPLE_CA_ROOT_NAME:?SIMPLE_CA_ROOT_NAME is required}"
fi

if [ -n "${SIMPLE_CA_ISSUING_CA:-}" ] && [ ! -f "$dir/$SIMPLE_CA_ISSUING_CA/ca_cert.pem" ]; then
  simple-ca ca create --issuing-ca "$SIMPLE_CA_ISSUING_CA" \
    "${SIMPLE_CA_ISSUING_NAME:?SIMPLE_CA_ISSUING_NAME is required}"
fi
