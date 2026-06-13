# MiMo Executable Final Acceptance Plan for Skyhook

Last updated: 2026-06-13

This document is the locked execution plan for MiMo. It is intentionally concrete.
When MiMo says the work is finished, Codex will judge completion only against the
acceptance rules in this document plus the commands listed here. No extra hidden
requirements should be added after the fact.

## 0. Completion Contract

Skyhook is considered final for this round only when all of the following are true:

1. Every task marked **Required** in this plan is implemented.
2. Every required test file listed in this plan exists and contains meaningful assertions.
3. The final command suite in section 10 passes.
4. `docs/FINAL_ACCEPTANCE_CHECKLIST.md` has no unchecked required item.
5. `docs/PROTOCOL_SUPPORT_MATRIX.md`, `README.md`, and `README.zh-CN.md` match the actual code and test results.
6. No script may hide failures with `|| true`, `set +e`, unconditional `exit 0`, or "warning only" behavior for required verification.
7. No protocol may be marked `production` unless it has a real dialing path and at least one meaningful runtime test.

If MiMo completes every Required item exactly as written, Codex should accept the work as done for this plan.

## 1. Current Baseline

The current repository already has:

1. Passing regular verification through `scripts/verify_final.sh`.
2. Native L3 TCP/UDP dispatcher tests.
3. Subscription store tests for multi-subscription, active switching, rules, groups, and traffic carry-over.
4. Smart rule tests for direct recommendation, override priority, apply-all behavior.
5. Traffic store tests for global/subscription/outbound accumulation and persistence.
6. Benchmark targets only for `routing_decision` and `tcp_forwarder`.
7. Real protocol script that is strict for configured env vars.

The current known gaps are:

1. Hysteria v1 is partial, not production.
2. Snell is partial, lacks native UDP and real integration tests.
3. OpenVPN is parser/profile registration only, not real dialing.
4. Native TUN privileged real tests exist but are not fully expanded or documented with real local outputs.
5. UDP/DNS/subscription/node-probe benchmark targets are missing.
6. Some protocol "mock" tests only parse config or check no-panic behavior; they need real wire assertions.

## 2. Non-Negotiable Engineering Rules

MiMo must follow these rules:

1. Do not replace real implementation with placeholder structs or TODO comments.
2. Do not mark parser-only code as real dialing.
3. Do not mark ignored/env-gated tests as passed unless they were actually run and output is saved.
4. Do not weaken existing tests.
5. Do not delete honest limitations from docs until code and tests prove the limitation is gone.
6. Do not change existing public API names unless the docs and tests are updated in the same commit/work batch.
7. Keep unsupported protocols explicit with actionable errors.
8. Keep `cargo clippy --all-targets --all-features -- -D warnings` clean.

## 3. Required Task A: Verification Infrastructure Must Be Trustworthy

### A1. Final verification script

Files:

- `scripts/verify_final.sh`
- `scripts/verify_real_protocols.sh`
- `scripts/verify_native_tun_real.sh`
- `scripts/bench_final.sh`

Required work:

1. Ensure every script starts with `set -euo pipefail`.
2. Ensure required verification failures cause non-zero exit.
3. Ensure skipped env-gated tests print `SKIP`, not `PASS`.
4. Ensure every called test target or bench target exists.
5. Add a `scripts/verify_all_required.sh` wrapper that runs:
   - `scripts/verify_final.sh`
   - `scripts/bench_final.sh --no-run` or equivalent compile-only mode if full bench is too slow
   - strict documentation consistency checks
6. Add script-level comments explaining which tests require root or external servers.

Acceptance:

```bash
bash scripts/verify_final.sh
bash scripts/verify_real_protocols.sh
bash -c 'set +e; SKYHOOK_SNELL_SERVER=127.0.0.1 bash scripts/verify_real_protocols.sh; test $? -ne 0'
bash scripts/bench_final.sh --no-run
bash scripts/verify_all_required.sh
```

`verify_all_required.sh` must fail if any required non-privileged test fails.

### A2. Test quality cleanup

Files:

- `tests/subscription_tests.rs`
- `tests/protocol_mock_tests.rs`
- `tests/protocol_echo_tests.rs`
- any new protocol test files

Required work:

1. Replace no-op tests with assertions that verify real behavior.
2. Remove tautological assertions such as `x || !x`.
3. For config parse tests, assert at least:
   - outbound kind,
   - capability flags,
   - relevant fields are preserved,
   - unsupported limitations are reported correctly.
4. For protocol echo tests, assert bytes on the wire where possible.

Acceptance:

```bash
cargo test --test subscription_tests -- --nocapture
cargo test --test protocol_mock_tests -- --nocapture
cargo test --test protocol_echo_tests -- --nocapture
```

## 4. Required Task B: Protocol Production Closure

This section is Required. A protocol may remain partial only if this plan explicitly says partial is acceptable. For this final plan, Hysteria v1, Snell, SSR, TUIC, SSH, AnyTLS, ShadowTLS, and Naive must have honest runtime tests. OpenVPN has a special acceptance path in section 5.

### B1. Hysteria v1 real dialing

Files:

- `src/outbound/mod.rs`
- `src/subscription/mod.rs`
- `tests/hysteria_v1_real.rs`
- `tests/protocol_integration.rs`
- `docs/PROTOCOL_SUPPORT_MATRIX.md`

Required work:

1. Confirm Hysteria v1 wire protocol separately from Hysteria2.
2. Implement TCP stream dialing that works against a real Hysteria v1 server.
3. Implement UDP exchange that works against a real Hysteria v1 server.
4. Implement configured obfs correctly. Current placeholder XOR/random-key behavior is not acceptable unless it matches the real protocol.
5. Add env-gated real tests:
   - `SKYHOOK_HYSTERIA_V1_SERVER`
   - `SKYHOOK_HYSTERIA_V1_PORT`
   - `SKYHOOK_HYSTERIA_V1_AUTH`
   - optional `SKYHOOK_HYSTERIA_V1_OBFS`
6. Add a local/mock wire test that verifies request framing, auth bytes, and obfs behavior deterministically.
7. Make `probe_outbounds` work for Hysteria v1 without hanging beyond the configured timeout.

Acceptance:

```bash
cargo test hysteria_v1 -- --nocapture
SKYHOOK_HYSTERIA_V1_SERVER=... \
SKYHOOK_HYSTERIA_V1_PORT=... \
SKYHOOK_HYSTERIA_V1_AUTH=... \
cargo test --test hysteria_v1_real -- --ignored --nocapture
```

Completion status after acceptance:

- If both TCP and UDP real tests pass: mark `production`.
- If only TCP passes: mark `partial` and explicitly state UDP missing.
- If only parser/unit tests pass: not complete for this plan.

### B2. Snell TCP, UDP, and obfs

Files:

- `src/outbound/mod.rs`
- `src/subscription/mod.rs`
- `tests/snell_real_integration.rs`
- `tests/snell_wire_tests.rs`
- `docs/PROTOCOL_SUPPORT_MATRIX.md`

Required work:

1. Verify Snell v1/v2/v3 TCP handshake bytes.
2. Implement TLS obfs if advertised in docs.
3. Implement native UDP if claiming UDP support.
4. If Snell UDP cannot be implemented in this round, keep Snell `partial`, but then this plan is not fully complete. Do not claim final.
5. Add env-gated real tests:
   - `SKYHOOK_SNELL_SERVER`
   - `SKYHOOK_SNELL_PORT`
   - `SKYHOOK_SNELL_PSK`
   - optional `SKYHOOK_SNELL_OBFS`
6. Add mock/wire tests for handshake and obfs.

Acceptance:

```bash
cargo test snell -- --nocapture
SKYHOOK_SNELL_SERVER=... \
SKYHOOK_SNELL_PORT=... \
SKYHOOK_SNELL_PSK=... \
cargo test --test snell_real_integration -- --ignored --nocapture
```

Completion status after acceptance:

- TCP + UDP + advertised obfs pass: mark `production`.
- TCP only: mark `partial`, and this final plan remains incomplete.

### B3. SSR variant coverage

Files:

- `src/outbound/mod.rs`
- `src/subscription/mod.rs`
- `tests/ssr_wire_tests.rs`
- `tests/ssr_real_integration.rs`

Required work:

1. Support the commonly used SSR protocols:
   - `origin`
   - `auth_sha1_v4`
   - `auth_aes128_md5`
   - `auth_aes128_sha1`
2. Support the commonly used obfs modes:
   - `plain`
   - `http_simple`
   - `http_post`
   - `tls1.2_ticket_auth`
3. Add explicit errors for unsupported combinations.
4. Add deterministic wire tests for each supported protocol/obfs combination.
5. Add env-gated real SSR test if a server is available.

Acceptance:

```bash
cargo test ssr -- --nocapture
SKYHOOK_SSR_SERVER=... \
SKYHOOK_SSR_PORT=... \
SKYHOOK_SSR_PASSWORD=... \
cargo test --test ssr_real_integration -- --ignored --nocapture
```

If no real SSR server is available, keep real test ignored but do not mark SSR `production`; mark `partial`.

### B4. TUIC, SSH, AnyTLS, ShadowTLS, Naive runtime assertions

Files:

- `src/outbound/mod.rs`
- `tests/tuic_wire_tests.rs`
- `tests/ssh_integration.rs`
- `tests/anytls_wire_tests.rs`
- `tests/shadowtls_wire_tests.rs`
- `tests/naive_integration.rs`

Required work:

1. TUIC:
   - test TCP connect request encoding,
   - test UDP packet exchange path,
   - test timeout behavior.
2. SSH:
   - launch local test SSH server or use a deterministic mock,
   - verify direct-tcpip data roundtrip,
   - verify password auth and private-key auth if both are advertised.
3. AnyTLS:
   - verify auth/settings/stream-open framing,
   - verify timeout and server rejection behavior.
4. ShadowTLS:
   - verify v3 ClientHello HMAC,
   - verify application-data framing,
   - verify rejection on wrong password.
5. Naive:
   - launch local TLS CONNECT server in test,
   - verify CONNECT request,
   - verify data roundtrip after 200 response,
   - verify non-200 rejects.

Acceptance:

```bash
cargo test tuic -- --nocapture
cargo test ssh -- --nocapture
cargo test anytls -- --nocapture
cargo test shadowtls -- --nocapture
cargo test naive -- --nocapture
```

Completion status:

- Protocols with meaningful runtime tests may be marked `production` or `partial` according to capability.
- Protocols with only parse tests must not be marked `production`.

## 5. Required Task C: OpenVPN Final Decision

OpenVPN is the largest risk. This plan allows exactly two acceptable outcomes. MiMo must pick one and complete it.

### C1. Option 1: Full native OpenVPN production support

Files:

- `src/l3/openvpn/*`
- `src/l3/mod.rs`
- `src/inbound/native_tun.rs`
- `tests/openvpn_packet_tests.rs`
- `tests/openvpn_control_tests.rs`
- `tests/openvpn_real_integration.rs`

Required work:

1. Parse and serialize OpenVPN opcodes.
2. Implement TLS over OpenVPN control packets.
3. Implement server option negotiation enough for common profile use.
4. Implement auth-user-pass if supported in config.
5. Implement data channel key derivation.
6. Implement encrypt/decrypt for negotiated data ciphers.
7. Bridge TUN packet to OpenVPN data packet.
8. Bridge OpenVPN data packet back to TUN packet.
9. Expose connected/connecting/error status accurately.
10. Add env-gated real test:
    - `SKYHOOK_OPENVPN_PROFILE`, or
    - `SKYHOOK_OPENVPN_SERVER`, `SKYHOOK_OPENVPN_PORT`, cert/key env vars.

Acceptance:

```bash
cargo test openvpn -- --nocapture
SKYHOOK_OPENVPN_PROFILE=... \
cargo test --test openvpn_real_integration -- --ignored --nocapture
```

If this option is completed, update docs to mark OpenVPN `experimental` or `production` based on test depth.

### C2. Option 2: Explicitly scoped out of final production

This option is acceptable only if the final release explicitly says OpenVPN is not part of this final completion.

Required work:

1. Keep OpenVPN `parser-only` everywhere.
2. Keep `start_l3(openvpn)` returning a clear unsupported status.
3. Add tests that prove parser/profile registration works and start returns honest unsupported status.
4. Remove OpenVPN from "Mihomo parity complete" claims.
5. Add `docs/OPENVPN_NOT_INCLUDED_IN_FINAL.md` explaining why OpenVPN is deferred.

Acceptance:

```bash
cargo test openvpn -- --nocapture
rg -n "OpenVPN.*production|OpenVPN.*real dialing|OpenVPN.*complete" README.md README.zh-CN.md docs && exit 1 || true
```

If option C2 is chosen and all other sections pass, Codex will not call the plan incomplete because of OpenVPN. But docs must explicitly say OpenVPN is out of final production scope.

## 6. Required Task D: Native TUN Real-World Acceptance

Files:

- `src/inbound/native_tun.rs`
- `src/inbound/native_tun_session.rs`
- `src/inbound/native_tun_dispatcher.rs`
- `src/inbound/native_tun_tcp_forward.rs`
- `src/inbound/native_tun_dns.rs`
- `tests/native_tun_privileged.rs`
- `tests/native_tun_soak.rs`
- `scripts/verify_native_tun_real.sh`
- `docs/NATIVE_TUN_REAL_TEST_REPORT.md`

Required work:

1. Expand privileged TUN tests to cover:
   - utun creation,
   - route setup,
   - route cleanup,
   - TCP direct echo,
   - TCP proxy echo,
   - UDP direct echo,
   - UDP proxy echo,
   - IPv6 UDP echo,
   - DNS hijack,
   - FIN/RST cleanup,
   - MTU boundary packet.
2. Add `tests/native_tun_soak.rs` ignored test:
   - 10k short TCP connections,
   - 10k short UDP exchanges,
   - 30-minute soak mode controlled by env var.
3. Add metrics assertions:
   - packets in/out,
   - bytes in/out,
   - errors,
   - active sessions return to zero after cleanup.
4. Update `scripts/verify_native_tun_real.sh` to run all privileged TUN tests strictly.
5. Save a real local run summary into `docs/NATIVE_TUN_REAL_TEST_REPORT.md`.

Acceptance:

```bash
sudo -E bash scripts/verify_native_tun_real.sh
sudo -E SKYHOOK_TUN_SOAK_SECONDS=1800 cargo test --test native_tun_soak -- --ignored --nocapture
```

For normal non-root CI, tests may remain ignored. But final local acceptance requires the sudo commands above.

## 7. Required Task E: Benchmarks and Performance Targets

Files:

- `benches/routing_decision.rs`
- `benches/tcp_forwarder.rs`
- `benches/udp_relay.rs`
- `benches/dns.rs`
- `benches/subscription_parse.rs`
- `benches/probe_outbounds.rs`
- `scripts/bench_final.sh`
- `docs/PERFORMANCE_BENCHMARKS.md`

Required work:

1. Add missing benchmark targets:
   - UDP relay,
   - DNS resolution/cache/fake-IP,
   - subscription parsing for realistic Clash YAML and URI list,
   - node probing with 100/500/1000 outbounds.
2. `scripts/bench_final.sh --no-run` must compile every bench target.
3. `scripts/bench_final.sh` must run every bench target.
4. Update `docs/PERFORMANCE_BENCHMARKS.md` with actual output values from the current machine.
5. Add a stable "performance target" table:
   - routing decision p95,
   - TCP SYN-ACK p95,
   - UDP exchange p95,
   - DNS cache hit p95,
   - subscription parse throughput,
   - probe 100 nodes total time,
   - memory after 10k sessions.

Acceptance:

```bash
bash scripts/bench_final.sh --no-run
bash scripts/bench_final.sh
```

The plan is complete if benchmarks exist, compile, run, and docs show actual values. It is acceptable if a metric is slower than desired, but it must be documented honestly.

## 8. Required Task F: Smart Rules, Subscriptions, Traffic, and API Hardening

Files:

- `src/smart/mod.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `src/subscription_store.rs`
- `src/traffic_store.rs`
- `tests/smart_rules_tests.rs`
- `tests/subscription_store.rs`
- `tests/traffic_store_tests.rs`
- `docs/API.md`

Required work:

1. Smart rules:
   - verify manual app rule outranks manual domain,
   - verify manual domain outranks smart,
   - verify smart outranks subscription,
   - verify subscription outranks default,
   - verify apply-one, apply-all, ignore, undo.
2. Direct probe:
   - timeout is configurable,
   - concurrency is bounded,
   - failures do not block proxy traffic,
   - background probe does not spawn unbounded tasks.
3. Subscription:
   - first import auto-switches,
   - later import does not auto-switch if active exists,
   - update-all updates every saved subscription,
   - active runtime config preserves selected subscription groups/rules,
   - subscription traffic survives replace/update.
4. Traffic:
   - global traffic persists,
   - subscription traffic persists,
   - outbound traffic persists,
   - real-time rate is non-zero during test traffic and returns to zero after idle.
5. API:
   - every documented endpoint has a test or smoke test,
   - error responses are JSON and include `ok: false`.

Acceptance:

```bash
cargo test --test smart_rules_tests -- --nocapture
cargo test --test subscription_store -- --nocapture
cargo test --test subscription_tests -- --nocapture
cargo test --test traffic_store_tests -- --nocapture
cargo test api -- --nocapture
```

If no API test file exists, add `tests/api_tests.rs`.

## 9. Required Task G: Documentation Must Match Reality

Files:

- `README.md`
- `README.zh-CN.md`
- `docs/API.md`
- `docs/PROTOCOL_SUPPORT_MATRIX.md`
- `docs/FINAL_ACCEPTANCE_CHECKLIST.md`
- `docs/NATIVE_TUN_REAL_TEST_REPORT.md`
- `docs/PERFORMANCE_BENCHMARKS.md`
- `docs/REAL_WORLD_TEST_ENV.md`
- `docs/SECURITY.md`

Required work:

1. Update English and Chinese README with the same capability matrix.
2. Remove stale links to nonexistent scripts or tests.
3. For every protocol, docs must state:
   - config parse,
   - subscription parse,
   - TCP runtime,
   - UDP runtime,
   - limitations,
   - test file proving it.
4. `docs/FINAL_ACCEPTANCE_CHECKLIST.md` must be the final truth table.
5. Every checked item in the checklist must have a command or test evidence.
6. Add `docs/FINAL_VERIFICATION_OUTPUT.md` containing copied summary output from:
   - `scripts/verify_final.sh`,
   - `scripts/bench_final.sh --no-run`,
   - real protocol env-gated tests that were actually run,
   - privileged TUN tests if run.

Acceptance:

```bash
rg -n "planned|TODO|placeholder|not implemented|parser-only|partial|not verified|SKIP" README.md README.zh-CN.md docs
```

Any remaining hit must be intentionally present and must correspond to an explicitly deferred item. If the final claim is "all complete", the only allowed remaining hits are historical plan docs, not active README/checklist/matrix docs.

## 10. Final Command Suite

MiMo must run these commands and paste the outputs into `docs/FINAL_VERIFICATION_OUTPUT.md`.

Non-privileged required commands:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
bash scripts/verify_final.sh
bash scripts/verify_real_protocols.sh
bash scripts/bench_final.sh --no-run
git diff --check
```

Benchmark command:

```bash
bash scripts/bench_final.sh
```

Env-gated protocol commands, run when the matching server env is available:

```bash
SKYHOOK_HYSTERIA_V1_SERVER=... \
SKYHOOK_HYSTERIA_V1_PORT=... \
SKYHOOK_HYSTERIA_V1_AUTH=... \
cargo test --test hysteria_v1_real -- --ignored --nocapture

SKYHOOK_SNELL_SERVER=... \
SKYHOOK_SNELL_PORT=... \
SKYHOOK_SNELL_PSK=... \
cargo test --test snell_real_integration -- --ignored --nocapture

SKYHOOK_SSR_SERVER=... \
SKYHOOK_SSR_PORT=... \
SKYHOOK_SSR_PASSWORD=... \
cargo test --test ssr_real_integration -- --ignored --nocapture
```

OpenVPN command depends on section 5 choice:

```bash
SKYHOOK_OPENVPN_PROFILE=... \
cargo test --test openvpn_real_integration -- --ignored --nocapture
```

Privileged Native TUN commands:

```bash
sudo -E bash scripts/verify_native_tun_real.sh
sudo -E SKYHOOK_TUN_SOAK_SECONDS=1800 cargo test --test native_tun_soak -- --ignored --nocapture
```

## 11. Final Review Rules for Codex

When MiMo reports completion, Codex will review as follows:

1. Run section 10 non-privileged commands.
2. If MiMo provides env-gated outputs in `docs/FINAL_VERIFICATION_OUTPUT.md`, verify the referenced test files exist and match the outputs.
3. If MiMo does not have external protocol servers, Codex will not require those env-gated commands unless the protocol is marked `production`.
4. If OpenVPN section C2 is chosen and documented, Codex will not reject the plan because OpenVPN remains parser-only.
5. Codex will reject only if:
   - a required command fails,
   - a script hides failure,
   - docs claim capability that tests do not prove,
   - a Required task is missing,
   - `FINAL_ACCEPTANCE_CHECKLIST.md` still has unchecked required items.

This section is the anti-moving-goalpost contract.

## 12. Recommended Execution Order

MiMo should execute in this order:

1. A1 verification scripts.
2. A2 no-op test cleanup.
3. E benchmark targets, because this is easy and reduces false final claims.
4. F smart/subscription/traffic/API hardening.
5. D Native TUN privileged expansion.
6. B4 TUIC/SSH/AnyTLS/ShadowTLS/Naive tests.
7. B3 SSR variants.
8. B2 Snell UDP/obfs and real test.
9. B1 Hysteria v1 real dialing and obfs.
10. C OpenVPN decision: either full support or explicit final defer.
11. G docs and final verification output.
12. Run section 10 command suite.

## 13. Final Deliverables

MiMo must deliver:

1. Code changes for all Required sections.
2. Test files listed in each section.
3. Updated scripts.
4. Updated docs.
5. `docs/FINAL_VERIFICATION_OUTPUT.md`.
6. Updated `docs/FINAL_ACCEPTANCE_CHECKLIST.md` with only completed required items checked.

Do not submit "done" until all six deliverables are present.

