#!/bin/bash
# Skyhook Verify All Required Script
# Runs all required verification checks for final acceptance.
# Exit on any failure (set -euo pipefail).
set -euo pipefail

echo "=== Skyhook Verify All Required ==="
echo ""

echo "1. Running final verification..."
bash scripts/verify_final.sh
echo ""

echo "2. Compiling benchmarks..."
bash scripts/bench_final.sh --no-run
echo ""

echo "3. Checking verification scripts for hidden failures..."
if grep -nE '\|\| true|set \+e|SKIP: .*bench not found' \
    scripts/verify_final.sh \
    scripts/verify_real_protocols.sh \
    scripts/verify_native_tun_real.sh \
    scripts/bench_final.sh; then
    echo "   FAIL: verification scripts contain hidden-failure patterns"
    exit 1
fi
echo "   ✓ Verification scripts are strict"
echo ""

echo "4. Checking required benchmark targets..."
for bench in routing_decision tcp_forwarder udp_relay dns subscription_parse probe_outbounds; do
    if [ ! -f "benches/${bench}.rs" ]; then
        echo "   FAIL: missing benches/${bench}.rs"
        exit 1
    fi
done
echo "   ✓ Required benchmark targets exist"
echo ""

echo "5. Checking required env-gated test targets..."
for test_file in hysteria_v1_real snell_real_integration ssr_real_integration; do
    if [ ! -f "tests/${test_file}.rs" ]; then
        echo "   FAIL: missing tests/${test_file}.rs"
        exit 1
    fi
done
echo "   ✓ Required env-gated test targets exist"
echo ""

echo "6. Checking documentation consistency..."
echo "   Checking README.md..."
if grep -q "TODO\|placeholder\|not implemented" README.md; then
    echo "   FAIL: README.md contains TODO/placeholder/not implemented"
    exit 1
fi
echo "   ✓ README.md clean"

echo "   Checking README.zh-CN.md..."
if grep -q "TODO\|placeholder\|not implemented" README.zh-CN.md; then
    echo "   FAIL: README.zh-CN.md contains TODO/placeholder/not implemented"
    exit 1
fi
echo "   ✓ README.zh-CN.md clean"

echo "   Checking PROTOCOL_SUPPORT_MATRIX.md..."
if grep -q "TODO\|placeholder" docs/PROTOCOL_SUPPORT_MATRIX.md; then
    echo "   FAIL: PROTOCOL_SUPPORT_MATRIX.md contains TODO/placeholder"
    exit 1
fi
echo "   ✓ PROTOCOL_SUPPORT_MATRIX.md clean"

echo ""
echo "=== All required verification passed ==="
