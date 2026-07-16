#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/debug/supercore}"
CONFIG="${ROOT}/Supercore/supercore.example.yaml"

if [[ ! -x "${CORE}" ]]; then
  cargo build --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi

"${CORE}" check -c "${CONFIG}"
"${CORE}" probe -c "${CONFIG}" --timeout-ms 500
