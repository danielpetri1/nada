#!/usr/bin/env bash
set -euo pipefail

authority=${1:-${PROXY_AUTHORITY:-localhost}}
if (( $# > 1 )) || [[ ! "$authority" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
    printf 'Usage: bash certs/generate.sh [DNS_NAME]\n' >&2
    exit 1
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ -e proxy-cert.pem || -L proxy-cert.pem || -e proxy-key.pem || -L proxy-key.pem ]]; then
    printf 'proxy-cert.pem or proxy-key.pem already exists\n' >&2
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
    -keyout "$cert_tmp_dir/proxy-key.pem" \
    -out "$cert_tmp_dir/proxy-cert.pem"

mv -- "$cert_tmp_dir/proxy-key.pem" proxy-key.pem
mv -- "$cert_tmp_dir/proxy-cert.pem" proxy-cert.pem
printf 'Created certs/proxy-cert.pem and certs/proxy-key.pem for %s.\n' "$authority"
