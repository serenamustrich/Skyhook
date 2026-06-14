# Skyhook

[![CI](https://github.com/serenamustrich/Skyhook/actions/workflows/ci.yml/badge.svg)](https://github.com/serenamustrich/Skyhook/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)

[中文说明](README.zh-CN.md)

**Skyhook** is a Rust-native intelligent proxy core.  
Chinese name: **玥球核心**.

Skyhook combines proxy protocol dialing, TUN traffic capture, subscription
management, traffic telemetry, node probing, country-aware routing, and smart
rules in one independent Rust core.

The core is built for desktop proxy clients, menu bar apps, automation tools,
and local network-control surfaces that need a fast, observable, and programmable
proxy engine.

## Downloads

- macOS app DMG: [玥球电梯.dmg](https://github.com/serenamustrich/Skyhook/releases/download/v0.1.1/default.dmg)
- Core binaries are published from GitHub Releases.

## Core Capabilities

### Inbound And TUN

- Mixed inbound proxy server.
- SOCKS5 TCP proxying.
- SOCKS5 UDP ASSOCIATE.
- HTTP CONNECT proxying.
- Plain HTTP absolute-form proxying.
- TUN mode.
- DNS hijack.
- Virtual DNS.
- Native TUN metrics.
- macOS utun support.
- Linux `/dev/net/tun` support.
- Route and address setup planning.
- Automatic private-network bypass rules.
- IP-literal endpoint bypass rules.
- Session limits and idle cleanup.
- SNI sniffing.
- HTTP Host sniffing.
- Process metadata lookup on macOS and Linux.

### NativeL3

- Raw IP packet ingestion from TUN.
- WireGuard L3 packet bridge.
- L3 profile discovery from config outbounds.
- L3 profile start and stop API.
- WireGuard Noise handshake engine.
- WireGuard keepalive and timer handling.
- WireGuard packet encapsulation and decapsulation.
- L3 packet subscription channel.
- TCP forwarding for direct and routed paths.
- UDP relay for direct and routed paths.
- Response packet injection back into the TUN stack.
- DNS cache for IP-to-domain reverse lookup.
- Native metrics for packets, bytes, errors, and active targets.

### DNS

- UDP DNS listener.
- TCP DNS listener.
- DoH upstream support.
- DoT upstream support.
- Default nameservers.
- Fallback nameservers.
- Direct/proxy-server nameserver separation.
- Fake-IP allocation.
- Fake-IP reverse lookup.
- Fake-IP filter support.
- DNS timeout controls.
- TUN virtual-DNS integration.

### Subscriptions

- Clash-style YAML subscription parsing.
- URI-list subscription parsing.
- Multi-subscription storage.
- Subscription import.
- Active subscription switching.
- Update-all subscription refresh.
- Startup subscription refresh.
- Background subscription refresh.
- Active subscription config export.
- Node metadata preservation.
- Proxy group preservation.
- Proxy-provider resolution.
- Provider-only subscription support.
- Subscription rule preservation.
- Rule provider preservation.
- Direct no-proxy subscription refresh.
- Direct no-proxy provider refresh.
- Country metadata extraction.
- Per-subscription lifetime traffic totals.

### Proxy Groups

- `select` groups.
- `url-test` groups.
- `fallback` groups.
- `auto` groups.
- Latency-oriented groups.
- Load-balance style groups.
- Group snapshots through the control API.
- Best-latency reporting.
- Explicit group selection.
- Country group selection.

### Rules

- Domain rules.
- Domain suffix rules.
- Domain keyword rules.
- IP rules.
- CIDR rules.
- App bundle rules.
- Process rules.
- Rule-set rules.
- Geosite rules.
- GeoIP rules.
- Match/final rules.
- Subscription rule conversion.
- Inline config rules.
- High-priority smart-rule overrides.

### Smart Routing

- Domain observation.
- IP observation.
- App/process observation.
- Direct reachability probing.
- Proxy recommendation list.
- Direct recommendation list.
- One-click recommendation apply.
- Apply-all recommendations.
- Persistent smart-rule state.
- Configurable direct-probe timeout.
- Configurable probe concurrency.
- Configurable confidence thresholds.
- Smart rules evaluated above subscription rules.

### Traffic And Telemetry

- Runtime connection table.
- Per-outbound traffic counters.
- Live rate snapshots.
- Lifetime traffic counters.
- Per-subscription traffic counters.
- TUN packet counters.
- TUN byte counters.
- TUN error counters.
- Event logs.
- Runtime health snapshots.
- Outbound capability reporting.

### Control API

Skyhook exposes local HTTP APIs for runtime control and monitoring.

| API | Function |
| --- | --- |
| `GET /health` | Health check. |
| `GET /skyhook/version` | Version information. |
| `GET /skyhook/status` | Runtime status. |
| `GET /skyhook/connections` | Connection and traffic table. |
| `GET /skyhook/outbounds` | Outbound list, health, and capabilities. |
| `POST /skyhook/outbounds/use` | Switch default outbound. |
| `POST /skyhook/probe/outbounds` | Probe outbounds. |
| `GET /skyhook/groups` | Proxy group snapshots. |
| `GET /skyhook/countries` | Country group snapshots. |
| `POST /skyhook/countries/use` | Select a country group. |
| `GET /skyhook/tun/profile` | TUN startup profile. |
| `GET /skyhook/tun/status` | TUN running state. |
| `GET /skyhook/tun/metrics` | Native TUN metrics. |
| `GET /skyhook/l3` | L3 profile status. |
| `POST /skyhook/l3/start` | Start L3 profiles. |
| `POST /skyhook/l3/stop` | Stop L3 profiles. |
| `GET /skyhook/subscriptions` | Saved subscriptions. |
| `POST /skyhook/subscriptions/import` | Import a subscription. |
| `POST /skyhook/subscriptions/use` | Switch active subscription. |
| `POST /skyhook/subscriptions/update-all` | Refresh all subscriptions. |
| `GET /skyhook/traffic/subscriptions` | Lifetime traffic by subscription. |
| `GET /skyhook/smart-rules` | Smart-rule snapshot. |
| `GET /skyhook/smart-rules/stats` | Smart-rule statistics. |
| `GET /skyhook/smart-rules/recommendations` | Smart recommendations. |
| `POST /skyhook/route/decision` | Inspect a route decision. |
| `GET /skyhook/config` | Current runtime config. |
| `POST /skyhook/config/reload` | Reload config. |

## Protocol Capabilities

| Protocol | TCP | UDP | Status | Functionality |
| --- | --- | --- | --- | --- |
| Direct | yes | yes | production | Native direct egress. |
| HTTP proxy | yes | no | production | HTTP CONNECT and absolute-form proxying. |
| SOCKS5 | yes | yes | production | TCP connect and UDP ASSOCIATE. |
| Shadowsocks AEAD | yes | yes | production | AES-GCM and ChaCha20-Poly1305. |
| Shadowsocks simple-obfs | yes | partial | production | HTTP/TLS obfs for TCP. |
| SSR | partial | no | partial | Origin AES-CFB TCP and first-packet obfs paths. |
| Trojan | yes | yes | production | TLS TCP and UDP relay. |
| VMess AEAD | yes | yes | production | TCP, WebSocket, gRPC, HTTP/2, command UDP. |
| VLESS | yes | yes | production | TCP, TLS, Reality, WebSocket, gRPC, HTTP/2, command UDP. |
| Hysteria2 | yes | yes | production | QUIC TCP streams and datagram UDP. |
| Hysteria v1 | partial | partial | partial | QUIC runtime path with env-gated real-server coverage. |
| TUIC | yes | yes | partial | QUIC TCP, datagram UDP, and stream UDP modes. |
| Naive | yes | no | production | TLS HTTP CONNECT. |
| SSH | yes | no | partial | direct-tcpip with password and private-key auth. |
| Snell | yes | no | partial | AEAD TCP and HTTP obfs first packet. |
| AnyTLS | yes | no | production | TLS auth, settings, stream open, SOCKS address handoff. |
| ShadowTLS v3 | yes | no | production | v3 ClientHello HMAC and application-data framing. |
| WireGuard | L3 | L3 | experimental | Native L3 manager and WireGuard Noise packet engine. |
| OpenVPN | parser only | no | parser-only | `.ovpn` parser and profile registration. |
| Mieru | parser only | no | parser-only | Config parse surface. |
| Juicity | parser only | no | parser-only | Config parse surface. |
| MASQUE | parser only | no | parser-only | Config parse surface. |

Status labels:

- **production**: supported runtime capability with local automated coverage.
- **partial**: supported runtime surface with limited variant coverage.
- **experimental**: available runtime surface for advanced use.
- **parser-only**: config or subscription parsing capability.

## Configuration Functions

Skyhook configuration covers:

- Core listen addresses.
- Mixed inbound settings.
- TUN settings.
- DNS settings.
- Outbound definitions.
- Proxy group definitions.
- Rule definitions.
- Rule provider definitions.
- Subscription store settings.
- Smart-rule settings.
- Traffic store paths.
- Probe timeout and concurrency.
- NativeL3 profile settings.
- L3 tunnel settings.

Example config files:

- [minimal-direct.yaml](examples/minimal-direct.yaml)
- [proxy-groups.yaml](examples/proxy-groups.yaml)
- [smart-rules.yaml](examples/smart-rules.yaml)
- [native-tun.yaml](examples/native-tun.yaml)
- [skyhook.example.yaml](skyhook.example.yaml)

## Documentation

- [API reference](docs/API.md)
- [Protocol support matrix](docs/PROTOCOL_SUPPORT_MATRIX.md)
- [Security notes](docs/SECURITY.md)
- [macOS system integration](docs/macos-system-integration.md)
- [Native TUN real-test notes](docs/NATIVE_TUN_REAL_TEST_REPORT.md)
- [Performance benchmarks](docs/PERFORMANCE_BENCHMARKS.md)

## Clean-Room Note

Skyhook is an independent Rust implementation. It contains Skyhook source code,
tests, examples, scripts, and build dependencies. It does not include private
subscriptions, user configs, or source code from other proxy cores.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
