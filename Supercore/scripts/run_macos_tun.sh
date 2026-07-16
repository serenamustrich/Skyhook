#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:-${SUPERCORE_CONFIG:-supercore.example.yaml}}"
LOG_LEVEL="${SUPERCORE_LOG_LEVEL:-supercore=info,info}"

if [[ -n "${SUPERCORE_BINARY:-}" ]]; then
  BIN="$SUPERCORE_BINARY"
else
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
  BIN="$ROOT/target/release/supercore"
fi

"$BIN" check -c "$CONFIG"

echo "Starting Supercore with sudo for TUN/device/route permissions."
echo "Config: $CONFIG"
sudo -E env RUST_LOG="$LOG_LEVEL" "$BIN" run -c "$CONFIG"
