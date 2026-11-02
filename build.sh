#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [[ -f ./env.sh ]]; then
    source ./env.sh
else
    source ./env-examples.sh
fi

cargo install --path . --bin nada --force
