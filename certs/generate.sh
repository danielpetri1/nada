#!/usr/bin/env bash
set -euo pipefail

authority=${1:-${RELAY_AUTHORITY:-localhost}}
if (( $# > 1 )) || [[ ! "$authority" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
    printf 'Usage: bash certs/generate.sh [DNS_NAME]\n' >&2
    exit 1
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -e relay-cert.pem || -L relay-cert.pem || -e relay-key.pem || -L relay-key.pem ]]; then
    printf 'relay-cert.pem or relay-key.pem already exists\n' >&2
    exit 1
fi

umask 077
cert_tmp_dir=$(mktemp -d .self-signed.XXXXXX)
trap 'rm -rf -- "$cert_tmp_dir"' EXIT

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -sha256 -nodes -days 365 \
    -subj "/CN=$authority" \
    -addext "subjectAltName=DNS:$authority" \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,digitalSignature,keyCertSign' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$cert_tmp_dir/relay-key.pem" \
    -out "$cert_tmp_dir/relay-cert.pem"

mv -- "$cert_tmp_dir/relay-key.pem" relay-key.pem
mv -- "$cert_tmp_dir/relay-cert.pem" relay-cert.pem
printf 'Created certs/relay-cert.pem and certs/relay-key.pem for %s.\n' "$authority"
