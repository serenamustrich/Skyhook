#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_SUPPORT="${HOME}/Library/Application Support/YueqiuElevator"
CORE_DIR="${APP_SUPPORT}/cores"
SOURCE="${ROOT}/Supercore"

mkdir -p "${CORE_DIR}"

cd "${SOURCE}"
cargo build --release
cp "${SOURCE}/target/release/supercore" "${CORE_DIR}/supercore"
chmod +x "${CORE_DIR}/supercore"
"${CORE_DIR}/supercore" --version
echo "Installed: ${CORE_DIR}/supercore"
