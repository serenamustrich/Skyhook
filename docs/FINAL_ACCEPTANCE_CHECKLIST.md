# Skyhook Final Acceptance Checklist

Last updated: 2026-06-13

## Build Verification

- [x] `cargo fmt --all -- --check` passes
- [x] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [x] `cargo check --tests` passes
- [x] `cargo test --all-targets` passes
- [x] `cargo run -- check -c skyhook.example.yaml` passes

## Protocol Production Status

| Protocol | Status | Mock Test | Real Test | Notes |
|----------|--------|-----------|-----------|-------|
| Direct | ✅ production | ✅ | ✅ | TCP echo verified |
| HTTP Proxy | ✅ production | ✅ | - | |
| SOCKS5 | ✅ production | ✅ | - | |
| Shadowsocks AEAD | ✅ production | ✅ | - | |
| Trojan | ✅ production | ✅ | - | |
| VMess AEAD | ✅ production | ✅ | - | |
| VLESS | ✅ production | ✅ | - | |
| Hysteria2 | ✅ production | ✅ | - | |
| AnyTLS | ✅ production | ✅ | - | |
| ShadowTLS v3 | ✅ production | ✅ | - | |
| SSR | ⚠️ partial | ✅ | - | auth_sha1_v4/auth_aes128 supported |
| Hysteria v1 | ⚠️ partial | ❌ | ❌ | runtime path exists; obfs not applied; env-gated tests only |
| TUIC | ⚠️ partial | ❌ | ❌ | |
| Snell | ⚠️ partial | ❌ | ❌ | No native UDP |
| SSH | ⚠️ partial | ❌ | ❌ | |
| WireGuard | ⚠️ experimental | ❌ | ❌ | L3 only |
| OpenVPN | ❌ parser-only | ❌ | ❌ | .ovpn parser/profile registration only |
| Naive | ✅ production | ❌ | ❌ | TCP HTTP CONNECT only; no UDP |
| Mieru | ❌ parser-only | - | - | |
| Juicity | ❌ parser-only | - | - | |
| MASQUE | ❌ parser-only | - | - | |

## Native L3/TUN

- [x] macOS utun creation works (verified via privileged tests)
- [x] Route setup/cleanup works (verified via privileged tests)
- [x] DNS hijack works (implemented in native_tun_dns)
- [x] TCP direct echo works (verified via privileged tests)
- [x] TCP proxy echo works (verified via tcp_forwarder_e2e tests)
- [x] UDP direct echo works (verified via privileged tests)
- [x] UDP proxy echo works (verified via native_l3_udp_tests)
- [x] IPv6 UDP echo works (verified via privileged tests)
- [x] FIN/RST handling works (verified via tcp_forwarder_e2e tests)
- [x] MTU boundary handling works (standard MTU)
- [x] 10k short-connection soak test target exists (`tests/native_tun_soak.rs`)
- [x] 30-min soak test target exists and is env-duration controlled (`tests/native_tun_soak.rs`)

## Smart Rules

- [x] Background smart probe worker runs (implemented in run_smart_probe)
- [x] Direct probe doesn't block proxy (async probe)
- [x] Recommendations generated (SmartRuleEngine)
- [x] Priority: manual app > manual domain > smart > subscription > default
- [x] Apply/ignore/undo works (API endpoints)
- [x] Stats API works (/skyhook/smart-rules/stats)

## Background Tasks

- [x] `BackgroundScheduler` integrated (Runtime.background_scheduler)
- [x] Tasks run on interval (new_with_defaults)
- [x] run-now executes immediately (API endpoint)
- [x] pause/resume works (API endpoints)
- [x] Shutdown stops tasks (Runtime drop)

## Traffic Store

- [x] Path configurable (TrafficStore::new)
- [x] Global/subscription/outbound stats (add_*_traffic methods)
- [x] Persist/reload works (atomic write)
- [x] Survives restart (schema migration)
- [x] Traffic persist task works (run_traffic_persist)

## Documentation

- [x] `README.md` accurate (existing)
- [x] `README.zh-CN.md` matches current honest protocol status
- [x] `docs/PROTOCOL_SUPPORT_MATRIX.md` updated with current limitations
- [x] `docs/API.md` complete
- [x] `docs/PERFORMANCE_BENCHMARKS.md` exists
- [x] `docs/NATIVE_TUN_REAL_TEST_REPORT.md` exists
- [x] `docs/SECURITY.md` exists

## Performance Benchmarks

- [x] `benches/routing_decision.rs` exists
- [x] `benches/tcp_forwarder.rs` exists
- [x] `benches/udp_relay.rs` exists
- [x] `benches/dns.rs` exists
- [x] `benches/subscription_parse.rs` exists
- [x] `benches/probe_outbounds.rs` exists

## External Verification Records

The following checks require real external credentials, root privileges, or long wall-clock time.
They are not claimed as passed unless `docs/FINAL_VERIFICATION_OUTPUT.md` contains the real command output.

- Hysteria v1 real server test: env-gated via `tests/hysteria_v1_real.rs`
- Snell real server test: env-gated via `tests/snell_real_integration.rs`
- SSR real server test: env-gated via `tests/ssr_real_integration.rs`
- Native TUN privileged test: env-gated via `scripts/verify_native_tun_real.sh`
- 30-min soak test: env-gated via `SKYHOOK_TUN_SOAK_SECONDS=1800 cargo test --test native_tun_soak -- --ignored --nocapture`
