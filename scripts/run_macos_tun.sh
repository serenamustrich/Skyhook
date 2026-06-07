#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${1:-${SKYHOOK_CONFIG:-skyhook.example.yaml}}"
LOG_LEVEL="${SKYHOOK_LOG_LEVEL:-skyhook=info,info}"

if [[ -n "${SKYHOOK_BINARY:-}" ]]; then
  BIN="$SKYHOOK_BINARY"
else
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
  BIN="$ROOT/target/release/skyhook"
fi

"$BIN" check -c "$CONFIG"

echo "Starting Skyhook with sudo for TUN/device/route permissions."
echo "Config: $CONFIG"
sudo -E env RUST_LOG="$LOG_LEVEL" "$BIN" run -c "$CONFIG"
