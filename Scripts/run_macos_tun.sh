#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:-${ROOT}/Supercore/supercore.example.yaml}"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/release/supercore}"

if [[ ! -x "${CORE}" ]]; then
  cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi

"${CORE}" check -c "${CONFIG}"
echo "Starting Supercore TUN with administrator privileges. Press Ctrl-C to stop."
exec sudo -E env RUST_LOG="${RUST_LOG:-supercore=info,info}" \
  "${CORE}" run -c "${CONFIG}"
