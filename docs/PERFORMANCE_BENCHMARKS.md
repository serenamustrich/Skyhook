# Skyhook Performance Benchmarks

Last updated: 2026-06-13

## Overview

This document reports the performance benchmarks for Skyhook's core components.
Run `scripts/bench_final.sh` to reproduce the benchmark targets that exist today.

## How to Run

```bash
# Full benchmark suite
scripts/bench_final.sh

# Individual benchmarks
cargo bench --bench routing_decision
cargo bench --bench tcp_forwarder
```

## Test Environment

- OS: macOS (Apple Silicon)
- Rust: 1.96.0
- Build: release profile with LTO

## Benchmark Results

### Routing Decision

| Metric | p50 | p95 | p99 |
|--------|-----|-----|-----|
| routing_decision_direct | ~370ns | ~422ns | ~425ns |
| routing_decision_ip | ~348ns | ~405ns | ~410ns |

These results show sub-microsecond routing decisions, well under the 50μs target.

### TCP Forwarder

| Metric | p50 | p95 | p99 |
|--------|-----|-----|-----|
| tcp_forwarder_syn_ack | ~7.2µs | ~8.2µs | ~8.5µs |

These results show sub-10µs TCP SYN-ACK generation, well under the 100µs target.

### Verified Test Results

From `cargo test --all-targets`:

| Test Suite | Tests | Time |
|------------|-------|------|
| tcp_forwarder_e2e | 11 | ~0.04s |
| native_l3_udp_tests | 4 | ~0.03s |
| native_l4_dispatcher_tests | 5 | ~0.13s |
| background_tasks_tests | 7 | ~0.00s |
| traffic_store_tests | 5 | ~0.00s |
| subscription_store | 8 | ~0.02s |
| subscription_tests | 4 | ~0.00s |
| smart_rules_tests | 5 | ~0.00s |
| protocol_mock_tests | 7 | ~0.00s |
| protocol_echo_tests | 3 | ~0.00s |

### 30-Minute Soak Test

- Status: Not verified in this repository snapshot
- Iterations: -
- Failures: -
- Panics: -

## Optimization Notes

1. **Routing Decision**: HashMap-based O(1) lookup
2. **TCP Forwarder**: Minimal allocation, direct forwarding
3. **UDP Relay**: Session-based socket reuse
4. **Traffic Store**: Atomic write with temp file rename

## Known Performance Characteristics

- Native TUN throughput depends on OS implementation
- QUIC-based protocols have higher handshake overhead
- TLS adds ~100ms latency per new connection
- Memory usage scales linearly with active sessions

## Comparison Targets

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Routing p95 | <50μs | ~422ns | ✅ Met |
| TCP SYN-ACK | <100μs | ~7.2μs | ✅ Met |
| Memory/10k conn | <100MB | - | Pending |
| Startup time | <200ms | - | Pending |
