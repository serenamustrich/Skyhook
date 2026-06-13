#!/bin/bash
# Skyhook Benchmark Script
# Runs all benchmark targets.
# Use --no-run to compile-only mode.
# Exit on any failure (set -euo pipefail).
set -euo pipefail

echo "=== Skyhook Final Benchmark ==="
echo ""

if [ "${1:-}" = "--no-run" ]; then
    echo "Compiling benchmarks (no-run mode)..."
    cargo bench --no-run
    echo "✓ All benchmarks compiled"
    exit 0
fi

echo "Running routing_decision benchmark..."
cargo bench --bench routing_decision -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "Running tcp_forwarder benchmark..."
cargo bench --bench tcp_forwarder -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "Running udp_relay benchmark..."
cargo bench --bench udp_relay -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "Running dns benchmark..."
cargo bench --bench dns -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "Running subscription_parse benchmark..."
cargo bench --bench subscription_parse -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "Running probe_outbounds benchmark..."
cargo bench --bench probe_outbounds -- --warm-up-time 1 --measurement-time 3 --sample-size 20
echo ""

echo "=== Benchmark complete ==="
