#!/bin/bash
# Skyhook Final Verification Script
# Runs all non-privileged verification checks.
# Exit on any failure (set -euo pipefail).
set -euo pipefail

echo "=== Skyhook Final Verification ==="
echo ""

echo "1. Checking formatting..."
cargo fmt --all -- --check
echo "   ✓ Formatting OK"

echo "2. Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings
echo "   ✓ Clippy OK"

echo "3. Checking compilation..."
cargo check --tests
echo "   ✓ Compilation OK"

echo "4. Running all tests..."
cargo test --all-targets
echo "   ✓ All tests pass"

echo "5. Running config check..."
cargo run -- check -c skyhook.example.yaml
echo "   ✓ Config check OK"

echo ""
echo "=== All verification passed ==="
