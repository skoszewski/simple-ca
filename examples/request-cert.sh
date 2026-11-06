#!/bin/bash
# Request a server certificate from the signing API of simple-ca serve.
#
# Usage: SIMPLE_CA_TOKEN=TOKEN request-cert.sh CA_URL CN [DNS_NAME ...]
#        SIMPLE_CA_TOKEN_FILE=FILE request-cert.sh CA_URL CN [DNS_NAME ...]
#        [SIMPLE_CA_TOKEN_FILE=NEW_FILE] request-cert.sh --setup-code CODE CA_URL CN [DNS_NAME ...]
#
# A setup code is exchanged for the token at /api/token-setup of the server of CA_URL first; the
# token is written to SIMPLE_CA_TOKEN_FILE, a file that does not exist yet, when it is set.
#
# openssl makes an EC P-256 key and a certificate signing request for the CN, with the CN and the
# DNS names as its DNS names; curl sends it to the signing API of the CA at CA_URL, such as
# https://pki.example.com/servers, with a token made by simple-ca token create, in
# SIMPLE_CA_TOKEN or in the file SIMPLE_CA_TOKEN_FILE names, the certificate type in
# SIMPLE_CA_TYPE, server when it is unset, the validity in days in SIMPLE_CA_DAYS, 365 when it is
# unset, and the name of the certificate file of the CA directory, the prefix of the files written
# here; jq builds the request and reads the response. curl reads the
# token from a file in a private temporary directory, so it does not show in the process list.
# The key, the certificate and the chain are written to CN_key.pem, CN_cert.pem and CN_chain.pem,
# a wildcard CN *.NAME as wildcard.NAME; the key only once the certificate is signed.
set -eu

token=${SIMPLE_CA_TOKEN:-}
token_file=${SIMPLE_CA_TOKEN_FILE:-}
code=
if [ "${1:-}" = --setup-code ] && [ "$#" -ge 2 ]; then
  code=$2
  shift 2
fi
if [ "$#" -lt 2 ] || [ -z "$token$token_file$code" ]; then
  echo "Usage: SIMPLE_CA_TOKEN=TOKEN $0 CA_URL CN [DNS_NAME ...]" >&2
  echo "       SIMPLE_CA_TOKEN_FILE=FILE $0 CA_URL CN [DNS_NAME ...]" >&2
  echo "       [SIMPLE_CA_TOKEN_FILE=NEW_FILE] $0 --setup-code CODE CA_URL CN [DNS_NAME ...]" >&2
  exit 1
fi
if [ -n "$token" ] && [ -n "$token_file$code" ]; then
  echo "set SIMPLE_CA_TOKEN or SIMPLE_CA_TOKEN_FILE, or give --setup-code, not two of them" >&2
  exit 1
fi
if [ -n "$code" ] && [ -n "$token_file" ] && [ -e "$token_file" ]; then
  echo "SIMPLE_CA_TOKEN_FILE: $token_file exists; the token of --setup-code is written to a new file" >&2
  exit 1
fi
if [ -n "$token_file" ] && [ -z "$code" ]; then
  if [ ! -r "$token_file" ]; then
    echo "SIMPLE_CA_TOKEN_FILE: $token_file cannot be read" >&2
    exit 1
  fi
  token=$(tr -d "[:space:]" < "$token_file")
  if [ -z "$token" ]; then
    echo "SIMPLE_CA_TOKEN_FILE: $token_file is empty" >&2
    exit 1
  fi
fi
url=${1%/}
url=${url%/api/sign}/api/sign
cn=$2
shift 2

prefix=$cn
if [ "${cn#\*.}" != "$cn" ]; then
  prefix="wildcard.${cn#\*.}"
fi
key_path="${prefix}_key.pem"
cert_path="${prefix}_cert.pem"
chain_path="${prefix}_chain.pem"
if [ -e "$key_path" ]; then
  echo "$key_path exists" >&2
  exit 1
fi

tmp=$(mktemp -d ./.request-cert-XXXXXX)
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

if [ -n "$code" ]; then
  if [[ ! $url =~ ^(https?://[^/]+) ]]; then
    echo "$url is not a URL such as https://pki.example.com/servers" >&2
    exit 1
  fi
  setup_url="${BASH_REMATCH[1]}/api/token-setup"
  jq -n --arg code "$code" '{code: $code}' > "$tmp/setup.json"
  status=$(curl -sS -o "$tmp/setup" -w "%{http_code}" -X POST -H "Content-Type: application/json" \
    --data-binary "@$tmp/setup.json" "$setup_url")
  if [ "$status" != 200 ] || ! token=$(jq -er .token "$tmp/setup" 2>/dev/null); then
    if jq -e .error "$tmp/setup" >/dev/null 2>&1; then
      message=$(jq -r .error "$tmp/setup")
    else
      message=$(cat "$tmp/setup")
    fi
    echo "$setup_url: $status $message" >&2
    exit 1
  fi
  if [ -n "$token_file" ]; then
    (umask 077; printf "%s\n" "$token" > "$token_file")
    echo "Token written to $token_file"
  fi
fi

sans="DNS:$cn"
for name in "$@"; do
  if [ "$name" != "$cn" ]; then
    sans="$sans,DNS:$name"
  fi
done
if ! openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$tmp/key.pem" \
  -subj "/CN=$cn" -addext "subjectAltName=$sans" -out "$tmp/request.csr" 2>"$tmp/openssl.err"; then
  echo "openssl req failed:" >&2
  cat "$tmp/openssl.err" >&2
  exit 1
fi

days=${SIMPLE_CA_DAYS:-365}
case $days in
  '' | *[!0-9]*)
    echo "SIMPLE_CA_DAYS: '$days' is not a number of days" >&2
    exit 1
    ;;
esac
jq -n --rawfile csr "$tmp/request.csr" --arg type "${SIMPLE_CA_TYPE:-server}" --argjson days "$days" \
  --arg name "$prefix" '{csr: $csr, type: $type, days: $days, name: $name}' > "$tmp/request.json"
printf "Authorization: Bearer %s\n" "$token" > "$tmp/headers"
status=$(curl -sS -o "$tmp/response" -w "%{http_code}" -X POST \
  -H "@$tmp/headers" -H "Content-Type: application/json" \
  --data-binary "@$tmp/request.json" "$url")
if [ "$status" != 200 ]; then
  # The API answers with {"error": ...}; a URL that is not the API answers with text.
  if jq -e .error "$tmp/response" >/dev/null 2>&1; then
    message=$(jq -r .error "$tmp/response")
  else
    message=$(cat "$tmp/response")
  fi
  echo "$url: $status $message" >&2
  exit 1
fi

jq -r .certificate "$tmp/response" > "$cert_path"
jq -r .chain "$tmp/response" > "$chain_path"
mv "$tmp/key.pem" "$key_path"
echo "Certificate $(jq -r .serial "$tmp/response") written to $cert_path, its chain to $chain_path and its key to $key_path"
