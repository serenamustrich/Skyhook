#!/bin/bash
# Skyhook Native TUN Real Verification Script
# Runs privileged TUN tests. Requires sudo.
# Exit on any failure (set -euo pipefail).
set -euo pipefail

echo "=== Skyhook Native TUN Real Verification ==="
echo ""

if [ "$(uname)" != "Darwin" ]; then
    echo "Warning: This script is designed for macOS."
    echo "Native TUN tests may not work on other platforms."
    echo ""
fi

echo "Running Native TUN privileged tests..."
echo "Note: This requires sudo privileges."
echo ""

sudo -E cargo test --test native_tun_privileged -- --ignored --nocapture

echo ""
echo "=== Native TUN verification complete ==="
