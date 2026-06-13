#!/bin/bash
# Skyhook Real Protocol Verification Script
# Runs env-gated real protocol tests.
# Tests that require external servers are skipped with SKIP, not PASS.
# Exit on any failure (set -euo pipefail).
set -euo pipefail

echo "=== Skyhook Real Protocol Verification ==="
echo ""

SKIP_COUNT=0
RUN_COUNT=0
FAIL_COUNT=0

run_or_skip() {
    local name="$1"
    shift
    if [ -z "${!name:-}" ]; then
        echo "SKIP: $name not set"
        SKIP_COUNT=$((SKIP_COUNT + 1))
    else
        echo "RUN: $name is set, running test..."
        if "$@"; then
            RUN_COUNT=$((RUN_COUNT + 1))
        else
            echo "FAIL: $name test failed"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
}

# Hysteria v1
run_or_skip "SKYHOOK_HYSTERIA_V1_SERVER" \
    cargo test --test hysteria_v1_real -- --ignored --nocapture

# Snell
run_or_skip "SKYHOOK_SNELL_SERVER" \
    cargo test --test snell_real_integration -- --ignored --nocapture

# SSR
run_or_skip "SKYHOOK_SSR_SERVER" \
    cargo test --test ssr_real_integration -- --ignored --nocapture

# OpenVPN
echo "SKIP: OpenVPN real dialing is explicitly excluded by docs/OPENVPN_NOT_INCLUDED_IN_FINAL.md"
SKIP_COUNT=$((SKIP_COUNT + 1))

echo ""
echo "=== Real protocol verification complete ==="
echo "Run: $RUN_COUNT, Skip: $SKIP_COUNT, Fail: $FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
