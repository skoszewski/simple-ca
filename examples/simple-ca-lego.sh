#!/bin/bash
# Get or renew the certificate of this host from the ACME server of simple-ca serve with lego,
# with the settings of the environment; docs/acme.md describes them.
set -eu

for name in LEGO_SERVER LEGO_EMAIL LEGO_DOMAINS; do
  if [ -z "${!name:-}" ]; then
    echo "$name is not set; see docs/acme.md" >&2
    exit 1
  fi
done
export LEGO_PATH=${LEGO_PATH:-/var/lib/lego}

if [ -n "${LEGO_DNS:-}" ]; then
  exec lego run --accept-tos
fi
exec lego run --accept-tos --http
