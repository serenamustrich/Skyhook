# Skyhook / Yueqiu Core Development Guide for MiMo

This document is the implementation guide for the next Skyhook development pass.
It is written for MiMo to execute directly in:

```text
/Users/chency/Downloads/clash/Skyhook
```

## 0. Non-Negotiable Rules

1. Do not modify the old Yueqiu Elevator app.
2. Do not create a dual-core design.
3. Do not build a Mihomo compatibility wrapper.
4. Skyhook is an independent Rust core. It may learn from previous features, but it must not pretend to be Mihomo.
5. Do not delete or revert existing dirty worktree changes.
6. Do not delete `src/l3/`, `src/inbound/native_tun.rs`, `docs/`, or existing tests.
7. Do not call parser/profile/placeholder code "real dialing".
8. Do not mark a feature complete unless traffic can actually flow through the runtime path.
9. Prefer durable runtime state and explicit APIs over hidden globals.
10. During development, do focused compile checks only when needed. Run the full validation suite at the end of major phases.

## 1. Current Baseline to Read First

Before editing, read these files in this order:

```text
src/config/mod.rs
src/inbound/native_tun.rs
src/inbound/tun.rs
src/inbound/dns.rs
src/core/mod.rs
src/routing/mod.rs
src/smart/mod.rs
src/api/mod.rs
src/l3/mod.rs
src/l3/openvpn/parser.rs
src/outbound/mod.rs
src/subscription/mod.rs
skyhook.example.yaml
README.md
tests/config_and_runtime.rs
tests/real_subscription_compat.rs
tests/subscription_store.rs
```

Current important facts:

1. `TunConfig` already has many fields for TUN route/DNS/session behavior:
   `auto_route`, `dns_hijack`, `inet4_address`, `inet4_route_address`,
   `bypass`, `route_exclude_address`, `mtu`, `dns_strategy`, and process/app
   include/exclude fields.
2. `src/inbound/native_tun.rs` already creates macOS utun and Linux TUN, reads
   packets, strips/adds macOS utun headers, sends IP packets to L3, and writes
   inbound L3 packets back to TUN.
3. `native_tun::profile()` still warns that route setup, auto_route, bypass
   routes, and non-direct DNS strategy are unsupported.
4. `src/main.rs` already starts the configured `tun.l3_profile` before spawning
   `native_tun::serve()` when `tun.backend = native-l3`.
5. `src/l3/mod.rs` has real WireGuard L3 manager support and packet channels.
6. OpenVPN is still parser/profile/status only. `start_l3(openvpn)` returns
   `Unsupported`.
7. `OutboundConfig::Hysteria` is still mapped to `UnsupportedProtocolOutbound`.
8. `Mieru`, `Juicity`, and `MASQUE` are unsupported.
9. `src/smart/mod.rs` already has smart observations, recommendations,
   persistence, direct probe, and smart rule APIs, but it is mostly connected to
   stream-level connect paths. It is not yet a complete NativeL3 packet-to-flow
   decision engine.
10. `src/api/mod.rs` has smart-rule and L3 endpoints, but not complete NativeL3
    status/metrics/reload APIs.

## 2. Target Architecture

Skyhook should become an independent smart network core with these layers:

```text
OS TUN device
  -> NativeL3 packet ingress
  -> packet parser / flow classifier
  -> smart decision engine
  -> route decision
  -> direct / stream outbound / group / country group / L3 tunnel
  -> packet or stream egress
  -> metrics + learning feedback
```

For the near-term implementation, do not try to solve every hard problem in one
giant patch. Build the feature in this order:

```text
P0 NativeL3 interface route/address lifecycle
P1 NativeL3 metrics and status API
P2 NativeL3 DNS hijack
P3 NativeL3 packet-to-flow classifier foundation
P4 Smart decision engine completion
P5 User rules for app/domain/ip -> specified node/group/country/direct/reject
P6 OpenVPN real L3 dialing
P7 Hysteria v1 real dialing
P8 Other unsupported protocols and parity cleanup
P9 Final validation and honest README update
```

If time is limited, finish P0-P5 first. They are more important to Skyhook's
identity than chasing every protocol immediately.

## 3. P0: NativeL3 Interface Route/Address Lifecycle

### Goal

`tun.backend = native-l3` must create a usable OS TUN interface and configure
address, MTU, and routes. It must also clean up routes on shutdown.

### Files to Modify

Primary:

```text
src/inbound/native_tun.rs
src/config/mod.rs
src/main.rs
skyhook.example.yaml
README.md
```

Recommended new helper files:

```text
src/inbound/native_tun_system.rs
src/inbound/native_tun_metrics.rs
```

Do not convert `src/inbound/native_tun.rs` into a directory unless you update
module paths carefully. The simplest low-risk path is adding sibling modules and
importing them from `src/inbound/mod.rs`.

### Required Config Behavior

Use existing `TunConfig` fields first. Add new fields only if the existing fields
cannot express the behavior.

Existing fields to honor:

```text
tun.name
tun.mtu
tun.setup
tun.auto_route
tun.auto_detect_interface
tun.strict_route
tun.inet4_address
tun.inet6_address
tun.inet4_route_address
tun.inet6_route_address
tun.bypass
tun.auto_bypass_private
tun.auto_bypass_proxy_servers
tun.route_exclude_address
tun.dns_hijack
tun.dns_strategy
```

Expected example:

```yaml
tun:
  enabled: true
  backend: native-l3
  l3_profile: wg-main
  name: utun
  setup: true
  auto_route: true
  auto_detect_interface: true
  strict_route: false
  mtu: 1420
  inet4_address:
    - 198.18.0.1/30
  inet4_route_address:
    - 0.0.0.0/1
    - 128.0.0.0/1
  bypass:
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
```

### Implementation Tasks

1. Change `create_tun_interface()` so it returns both the file and interface
   metadata:

```rust
pub struct NativeTunDevice {
    pub file: tokio::fs::File,
    pub interface_name: String,
    pub mtu: u16,
}
```

2. Add a route/address manager:

```rust
pub struct NativeTunSetupPlan {
    pub interface_name: String,
    pub mtu: u16,
    pub inet4_address: Vec<String>,
    pub inet6_address: Vec<String>,
    pub route_add: Vec<String>,
    pub route_exclude: Vec<String>,
    pub bypass: Vec<String>,
}

pub struct NativeTunSetupGuard {
    // stores enough info to restore routes
}
```

3. On macOS, implement setup using system commands first. This is acceptable for
   the current pass and safer than writing fragile raw routing socket code:

```text
ifconfig <ifname> inet <address> <peer> mtu <mtu> up
route -n add -net <cidr> -interface <ifname>
route -n delete -net <cidr> -interface <ifname>
```

4. Parse CIDRs with `ipnet` instead of string slicing.
5. When `tun.setup = false`, create the device but do not change address/routes.
6. When `tun.auto_route = false`, configure address/MTU only.
7. When `tun.auto_bypass_private = true`, automatically add private ranges to
   bypass/exclude lists.
8. When `tun.auto_bypass_proxy_servers = true`, extract proxy server IPs from
   configured outbounds and bypass them so Skyhook does not route its own proxy
   transport into the TUN.
9. Store all route changes in `NativeTunSetupGuard`.
10. On normal shutdown, call cleanup.
11. On read/write task failure, also call cleanup before returning.
12. Log clear structured messages:

```text
native_tun: created interface=<ifname>
native_tun: configured address=<...> mtu=<...>
native_tun: added route=<...>
native_tun: added bypass=<...>
native_tun: cleanup route=<...>
```

### macOS Requirements

Minimum macOS support:

1. utun creation through `PF_SYSTEM` / `SYSPROTO_CONTROL`.
2. interface name discovery through `UTUN_OPT_IFNAME`.
3. address + MTU setup through `ifconfig`.
4. split default route through `0.0.0.0/1` and `128.0.0.0/1`.
5. route cleanup on shutdown.

Do not claim full NetworkExtension-grade integration yet.

### Linux Requirements

Linux can remain behind macOS, but must be honest:

1. Continue `/dev/net/tun` + `IFF_TUN | IFF_NO_PI`.
2. If route/address setup is not implemented on Linux yet, return a clear
   warning in `native_tun::profile()` and README.

### Tests

Add focused tests without requiring root:

```text
native_tun setup plan builds full-route macOS commands
native_tun setup plan honors auto_route=false
native_tun setup plan adds private bypass ranges
native_tun setup plan adds proxy-server bypass ranges
native_tun setup guard stores cleanup actions in reverse order
native_tun profile no longer warns about auto_route when setup support exists
```

Use dry-run command builders, not real `ifconfig`, in unit tests.

### Acceptance

P0 is done only when:

1. `native-l3` can report the created interface name.
2. setup plan can configure address and routes on macOS.
3. cleanup plan can restore routes.
4. missing permission produces a clear error.
5. README no longer says NativeL3 route setup is unsupported if implemented.

## 4. P1: NativeL3 Metrics and Status API

### Goal

The UI must be able to show whether NativeL3 is running, which interface it uses,
how much traffic passed, whether packets were dropped, and why.

### Files to Modify

```text
src/inbound/native_tun.rs
src/inbound/native_tun_metrics.rs
src/core/mod.rs
src/api/mod.rs
src/telemetry/mod.rs
README.md
tests/config_and_runtime.rs
```

### Data to Track

Add metrics similar to:

```rust
pub struct NativeTunMetrics {
    pub enabled: bool,
    pub running: bool,
    pub backend: String,
    pub interface_name: Option<String>,
    pub l3_profile: Option<String>,
    pub mtu: u16,
    pub setup_enabled: bool,
    pub auto_route: bool,
    pub routes_installed: Vec<String>,
    pub bypass_routes_installed: Vec<String>,
    pub read_packets: u64,
    pub read_bytes: u64,
    pub write_packets: u64,
    pub write_bytes: u64,
    pub decode_errors: u64,
    pub encode_errors: u64,
    pub rejected_packets: u64,
    pub dropped_packets: u64,
    pub lagged_events: u64,
    pub last_error: Option<String>,
    pub last_drop_reason: Option<String>,
}
```

### API Endpoints

Add these endpoints:

```text
GET /skyhook/tun/status
GET /skyhook/tun/metrics
POST /skyhook/tun/reload
```

Expected response shape:

```json
{
  "ok": true,
  "status": {
    "backend": "native-l3",
    "running": true,
    "interface_name": "utun7",
    "l3_profile": "wg-main",
    "mtu": 1420,
    "setup": {
      "enabled": true,
      "auto_route": true,
      "routes": ["0.0.0.0/1", "128.0.0.0/1"]
    },
    "metrics": {
      "read_packets": 100,
      "write_packets": 90,
      "dropped_packets": 0
    }
  }
}
```

### Implementation Notes

1. Metrics must use atomics or a lock with tiny critical sections.
2. Do not record packet payloads.
3. Do not make API calls block on TUN read/write loops.
4. `reload` can be conservative: return "not implemented" if hot reload is not
   safe yet, but the endpoint must not crash.

### Tests

Add tests for JSON shape and metric increments where possible. If runtime-level
tests are hard, unit test the metrics struct.

## 5. P2: NativeL3 DNS Hijack

### Goal

NativeL3 must handle DNS traffic. DNS must not be a feature only of the
`tun2-proxy` backend.

### Files to Modify

```text
src/inbound/native_tun.rs
src/inbound/native_tun_packet.rs
src/inbound/dns.rs
src/core/mod.rs
src/config/mod.rs
src/api/mod.rs
README.md
tests/config_and_runtime.rs
```

### Required Behavior

1. Detect IPv4 UDP packets where destination or source port is 53.
2. Decode IP header, UDP header, and DNS payload.
3. When `dns.hijack_udp_53 = true` or `tun.dns_hijack` matches, route the DNS
   payload into the existing DNS resolver path.
4. Build a valid UDP response packet and write it back to TUN.
5. Support checksum recalculation for IPv4.
6. If IPv6 support is not implemented in this pass, explicitly return a metric
   and warning instead of silently dropping.
7. Count:

```text
dns_hijack_queries
dns_hijack_successes
dns_hijack_failures
dns_hijack_unsupported_ipv6
```

### Packet Parser Tasks

Create a minimal parser with no ad hoc slicing in business logic:

```rust
pub enum TunIpPacket {
    Ipv4(Ipv4Packet),
    Ipv6(Ipv6Packet),
}

pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}
```

Parser must validate:

1. IP version.
2. IPv4 header length.
3. total length.
4. protocol = UDP.
5. UDP length.

### Tests

Add unit tests for:

```text
parse IPv4 UDP DNS query
reject truncated IPv4 header
reject invalid UDP length
build IPv4 UDP DNS response
checksum changes after response build
dns hijack disabled lets packet continue to L3
dns hijack enabled consumes DNS packet and writes response
```

## 6. P3: NativeL3 Packet-to-Flow Classifier Foundation

### Goal

Skyhook needs a foundation for app/domain/ip smart routing at packet level.
Do not try to build a full TCP stack in this phase. Build classification,
flow tracking, and decision hooks first.

### Files to Modify

```text
src/inbound/native_tun.rs
src/inbound/native_tun_packet.rs
src/core/mod.rs
src/routing/mod.rs
src/smart/mod.rs
src/api/mod.rs
```

### Required Types

Add types similar to:

```rust
pub struct FlowKey {
    pub protocol: FlowProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub enum FlowProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

pub struct FlowMetadata {
    pub key: FlowKey,
    pub host: Option<String>,
    pub app: Option<AppIdentity>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub decision: Option<RouteDecision>,
}
```

### Domain Discovery

Domain may come from:

1. DNS hijack mapping.
2. TLS SNI from ClientHello.
3. HTTP Host header.
4. Existing fake-ip mapping if available.

Implement in this order:

```text
DNS mapping first
TLS SNI second
HTTP Host third
fake-ip mapping later if not already available
```

### App Identity

macOS app/process identity can be incomplete in this phase.

Acceptable first pass:

1. Build the `AppIdentity` data model.
2. For packet flows, leave app identity as `None` unless a reliable lookup is
   implemented.
3. Do not fake app identity.
4. If implementing macOS lookup, isolate it behind:

```rust
pub trait AppIdentityResolver {
    fn resolve(&self, flow: &FlowKey) -> Option<AppIdentity>;
}
```

### Decision Hook

For each new flow, build a `Destination`:

```text
host = domain if known, otherwise destination IP
port = destination port
app = app identity if known
```

Then call:

```rust
runtime.decide(&destination)
```

Store the result in the flow table.

### Tests

Add tests:

```text
tcp syn creates flow
udp packet creates flow
dns-mapped ip produces domain destination
tls sni produces domain destination
flow reuses first decision
expired flow is removed
```

## 7. P4: Smart Decision Engine Completion

### Goal

Smart rules should become a core feature, not a UI-only recommendation list.
Skyhook should learn whether targets can direct-connect and apply decisions
without blocking current traffic.

### Files to Modify

```text
src/smart/mod.rs
src/core/mod.rs
src/routing/mod.rs
src/api/mod.rs
tests/config_and_runtime.rs
```

### Required Priority Order

Implement and document this exact priority:

```text
1. User explicit app/domain/ip outbound rule
2. Enabled smart recommendation rule
3. User custom direct/proxy rule
4. Auto-applied smart learning result
5. Subscription rule
6. Default outbound
```

### Required Behavior

1. Every new domain/IP observation is recorded.
2. If traffic went proxy and direct probe later succeeds, recommend direct.
3. If traffic went direct and connection fails, recommend proxy.
4. Direct probe runs in the background and never blocks active traffic.
5. Probe concurrency and timeout are controlled by config.
6. Probe cooldown prevents repeat testing the same target too often.
7. Recommendations can be enabled individually or in bulk.
8. Enabled recommendations become rules above subscription rules.

### API Additions

Existing smart APIs can remain, but add better comparison endpoints:

```text
GET /skyhook/smart-rules/stats
GET /skyhook/smart-rules/recommendations
POST /skyhook/smart-rules/recommendations/apply-all
POST /skyhook/smart-rules/recommendations/apply-one
POST /skyhook/smart-rules/recommendations/ignore
```

### Stats Required

Return:

```text
observed_targets
proxy_routed_targets
proxy_routed_but_direct_available_targets
proxy_routed_but_direct_available_ratio
recommended_direct_targets
recommended_proxy_targets
enabled_direct_rules
enabled_proxy_rules
direct_probe_attempts
direct_probe_successes
direct_probe_failures
```

### Tests

Add tests:

```text
smart explicit rule beats subscription rule
enabled recommendation beats subscription rule
auto recommendation does not apply under confidence threshold
direct probe success recommends direct for proxy-routed target
direct probe failure recommends proxy
cooldown prevents repeated probes
bulk apply direct recommendations creates enabled rules
single apply recommendation creates enabled rule
```

## 8. P5: App/Domain/IP to Specified Node, Group, Country, Direct, Reject

### Goal

Users must be able to specify:

```text
this app -> this node
this domain -> this group
this IP/CIDR -> this country group
this domain -> DIRECT
this app -> REJECT
```

### Files to Modify

```text
src/config/mod.rs
src/routing/mod.rs
src/smart/mod.rs
src/core/mod.rs
src/api/mod.rs
skyhook.example.yaml
README.md
tests/config_and_runtime.rs
```

### Rule Model

Current `RouteRule` and `SmartRouteRule` point to outbound names. Keep that
model, but make target validation smarter:

Outbound reference may be:

```text
leaf outbound name
group outbound name
country group outbound name
direct
reject
```

Do not add a separate "node vs group" field unless necessary. A named outbound
already represents node/group/country group in the runtime.

### YAML Examples

Add examples:

```yaml
rules:
  - target: domain-suffix
    value: openai.com
    outbound: US-Auto
  - target: ip-cidr
    value: 8.8.8.8/32
    outbound: direct
  - target: app-bundle
    value: com.tencent.xinWeChat
    outbound: HK-01

smart_rules:
  rules:
    - target: domain
      value: api.example.com
      outbound: JP-Auto
      enabled: true
      note: user override
```

### API Requirements

Expose a route-rule CRUD API separate from smart recommendations:

```text
GET /skyhook/rules
POST /skyhook/rules
POST /skyhook/rules/enabled
POST /skyhook/rules/delete
POST /skyhook/rules/reorder
```

If persistent config editing is too risky, store user rules in a durable state
file and merge them before subscription rules.

### Tests

Add tests:

```text
domain rule selects specific leaf node
domain rule selects group
domain rule selects country group
ip cidr selects direct
app bundle selects specified node when app metadata exists
rule validation rejects missing outbound
rule order is preserved
user rule beats subscription rule
```

## 9. P6: OpenVPN Real L3 Dialing

### Goal

OpenVPN must move from parser/profile/status to real native L3 dialing.

### Files to Modify

```text
src/l3/mod.rs
src/l3/openvpn/mod.rs
src/l3/openvpn/parser.rs
src/l3/openvpn/config.rs
src/config/mod.rs
README.md
tests/config_and_runtime.rs
```

Recommended new files:

```text
src/l3/openvpn/packet.rs
src/l3/openvpn/control.rs
src/l3/openvpn/crypto.rs
src/l3/openvpn/data.rs
src/l3/openvpn/transport.rs
```

### Required Work

Phase 1: packet/control foundation

1. Parse and serialize OpenVPN packet opcodes.
2. Generate local session id.
3. Implement hard reset client packet.
4. Implement ACK/control packet structures.
5. Implement UDP transport first.
6. TCP transport second.

Phase 2: TLS/control channel

1. Establish TLS over OpenVPN control channel.
2. Support inline CA.
3. Support cert/key if parser already captures them.
4. Support username/password auth if profile has `auth-user-pass`.
5. Implement ping/keepalive timers.

Phase 3: data channel

1. Implement key derivation for supported ciphers.
2. Implement data packet encrypt/decrypt.
3. Wire TUN packet -> OpenVPN data packet -> network.
4. Wire network data packet -> decrypt -> L3 inbound packet broadcast.
5. Update `L3TunnelStatus` packet and byte counters.

### Explicit Non-Goals for First OpenVPN Pass

Do not silently support compression:

```text
comp-lzo
compress
```

Reject compression with a clear unsupported error.

### Acceptance

OpenVPN is not complete until:

1. `start_l3(openvpn)` no longer returns `Unsupported`.
2. It attempts a real network connection.
3. Handshake state appears in `/skyhook/l3`.
4. Data channel can carry IP packets or clearly reports why it cannot.
5. README no longer says OpenVPN is only parser/profile.

If no real OpenVPN server is available, add ignored integration tests that can
be enabled with env vars.

## 10. P7: Hysteria v1 Real Dialing

### Goal

`OutboundConfig::Hysteria` must stop using `UnsupportedProtocolOutbound`.

### Files to Modify

```text
src/outbound/mod.rs
src/config/mod.rs
src/subscription/mod.rs
src/core/mod.rs
README.md
tests/config_and_runtime.rs
tests/real_subscription_compat.rs
```

### Required Work

1. Confirm Hysteria v1 wire protocol details before coding. Do not copy
   Hysteria2 blindly.
2. Implement QUIC transport.
3. Implement auth.
4. Implement TCP relay.
5. Implement UDP relay if protocol supports it in current config.
6. Support URI conversion and Clash YAML conversion.
7. Update capability reporting from unsupported to actual TCP/UDP support.
8. Make `probe_outbounds` work for Hysteria v1.

### Tests

Add tests:

```text
hysteria v1 uri parses to OutboundConfig::Hysteria
hysteria v1 clash yaml parses to OutboundConfig::Hysteria
hysteria v1 capability is not unsupported
hysteria v1 outbound attempts real QUIC connection
```

Use ignored integration tests if a real server is needed.

## 11. P8: Remaining Unsupported Protocols and Partial Parity

### Goal

Reduce protocol gaps honestly.

### Priority

```text
1. SSR missing variants
2. Snell UDP and TLS obfs
3. Mieru
4. Juicity
5. MASQUE
```

### Files to Modify

```text
src/outbound/mod.rs
src/subscription/mod.rs
src/core/mod.rs
README.md
tests/real_subscription_compat.rs
```

### Rules

1. Every protocol must have accurate capability reporting.
2. Unknown or partial protocols must remain clearly limited.
3. Do not remove unsupported tracking.
4. Do not claim Mihomo-level parity unless tests and real dialing support it.

### Acceptance

For each protocol:

```text
subscription parse works
config parse works
capability is accurate
probe behavior is accurate
real dialing works or explicit Unsupported remains
```

## 12. P9: Documentation and Example Config Updates

### Files to Modify

```text
README.md
skyhook.example.yaml
docs/MIMOCODE_CONTINUATION_PLAN.md
docs/SKYHOOK_FOLLOWUP_IMPLEMENTATION_PLAN.md
```

### Required Documentation

Update docs to show:

1. NativeL3 setup example.
2. NativeL3 known limitations.
3. Smart rules and recommendation workflow.
4. Route-rule priority.
5. Protocol support matrix.
6. Exact difference between:

```text
parser support
profile discovery
capability reporting
real dialing
full data plane
```

### Do Not

1. Do not leave docs claiming route setup is unsupported if P0 implements it.
2. Do not say OpenVPN is real if only parser/control shell exists.
3. Do not say Hysteria v1 is supported if it still maps to
   `UnsupportedProtocolOutbound`.

## 13. Development Sequence

Follow this exact order:

```text
Step 1: P0 NativeL3 route/address lifecycle
Step 2: P1 NativeL3 metrics/status API
Step 3: P2 NativeL3 DNS hijack
Step 4: P3 packet-to-flow classifier
Step 5: P4 smart decision completion
Step 6: P5 user app/domain/ip specified routing
Step 7: P9 docs/example updates for P0-P5
Step 8: focused validation for P0-P5
Step 9: P6 OpenVPN real dialing
Step 10: P7 Hysteria v1 real dialing
Step 11: P8 remaining protocol cleanup
Step 12: final full validation and honest gap report
```

Reason:

1. NativeL3 route/address makes TUN actually usable.
2. Metrics make failures visible.
3. DNS is required before domain-smart routing works well.
4. Packet-to-flow is the bridge from L3 packets to smart routing.
5. Smart decision rules are Skyhook's unique direction.
6. Protocol completion comes after the core routing model is solid.

## 14. Validation Plan

Do not run full tests after every tiny edit. Use this validation cadence.

After P0:

```bash
cargo check --tests
cargo test native_tun
cargo run -- check -c skyhook.example.yaml
```

After P1-P2:

```bash
cargo check --tests
cargo test native_tun
cargo test dns
cargo run -- check -c skyhook.example.yaml
```

After P3-P5:

```bash
cargo check --tests
cargo test smart
cargo test config_and_runtime
cargo run -- check -c skyhook.example.yaml
```

After P6-P8:

```bash
cargo check --tests
cargo test l3
cargo test real_subscription_compat
cargo run -- check -c skyhook.example.yaml
```

Final validation:

```bash
cargo fmt --all
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

Manual macOS validation if root permission is available:

```bash
cargo build
sudo target/debug/skyhook run -c skyhook.example.yaml
```

Manual checks:

```text
utun interface created
address assigned
mtu assigned
routes installed
DNS resolves in NativeL3
WireGuard L3 starts
browser traffic flows
/skyhook/tun/status reports interface and routes
/skyhook/tun/metrics reports non-zero packets/bytes
stop restores routes
```

## 15. Final Output Required from MiMo

When finished, output exactly this shape:

```text
## Completed

1. ...
2. ...

## Files Changed

- path: summary

## Validation

- cargo fmt --all: pass/fail
- cargo check --tests: pass/fail
- cargo test --all-targets: pass/fail
- cargo run -- check -c skyhook.example.yaml: pass/fail
- manual NativeL3 macOS run: pass/fail/not run, reason

## Still Not Complete

1. ...
2. ...

## Risks

1. ...
2. ...
```

## 16. Completion Definition

Do not call Skyhook "complete" until all of these are true:

1. NativeL3 can configure routes and DNS on macOS.
2. NativeL3 can expose real traffic metrics.
3. WireGuard NativeL3 can carry real system traffic end to end.
4. Smart rules can learn, recommend, enable, and override subscription rules.
5. app/domain/ip specified routing works where metadata is available.
6. OpenVPN either truly dials or remains honestly marked incomplete.
7. Hysteria v1 either truly dials or remains honestly marked incomplete.
8. Unsupported protocols are still visible and not hidden.
9. README and example config match reality.

