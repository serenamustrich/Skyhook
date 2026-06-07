# Skyhook

**Skyhook** is a Rust-native intelligent proxy core.  
Chinese name: **玥球核心**.

It is built around one idea: the proxy core should understand the network it is
running in. Instead of asking users to maintain fragile rule lists forever,
Skyhook combines protocol dialing, TUN capture, live telemetry, adaptive probing,
subscription management, and smart routing into one native engine.

Skyhook is an independent implementation. It does not ship source code from
other proxy cores. Protocol compatibility is implemented for interoperability.

## Why Skyhook

Most proxy cores are excellent packet movers. Skyhook wants to become a network
decision engine.

- It can import real-world subscriptions and preserve proxy groups, rules, rule
  providers, country buckets, and node metadata.
- It can run mixed inbound proxying and TUN mode, then expose runtime state
  through a local control API.
- It can learn from traffic, recommend direct/proxy decisions, and promote
  user-approved recommendations above subscription rules.
- It can test nodes in the background, record latency, and select better paths
  without freezing active traffic.
- It is written in Rust, with async I/O, explicit capability reporting, bounded
  concurrency, and a design that favors predictable failure over magic.

Skyhook is not trying to be a clone. It is a new core with a more autonomous
routing model.

## Current Status

Skyhook is under active development. The architecture, config model, API, and
many dialing paths are already in place. Some protocols are production-shaped;
others are still being expanded. Treat the project as an ambitious early core,
not a quiet finished binary.

The current focus areas are:

- real protocol dialing coverage,
- stronger TUN behavior,
- smart routing and learning,
- background subscription refresh,
- traffic accounting,
- clean APIs for desktop clients.

## Highlights

- **Rust-native core** using Tokio, rustls, Quinn, HTTP/2, HTTP/3, and async
  streams.
- **Mixed inbound** with SOCKS5, SOCKS5 UDP ASSOCIATE, HTTP CONNECT, and plain
  HTTP absolute-form proxying.
- **TUN mode** for device-level capture with DNS hijack, virtual DNS support,
  route setup options, session bounds, and macOS integration scripts.
- **Native DNS service** with UDP/TCP DNS handling, DoH/DoT upstream support,
  timeout control, fake-IP support, and TUN virtual-DNS integration.
- **Subscription engine** for Clash-style YAML and URI-list feeds.
- **Multi-subscription store** with import, list, switch, update-all, active
  config export, startup refresh, and background refresh.
- **Proxy groups** for select, url-test, fallback, auto, latency, and
  load-balance style behavior.
- **Rule conversion** for domain, IP, CIDR, app, process, rule-set, geosite,
  geoip, match, and final rules.
- **Rule providers** with download, cache, compile, and native RULE-SET matching.
- **Country intelligence** with country recognition, country grouping, and
  country-based low-latency selection.
- **Smart rules** that record observations, recommend route changes, and allow
  one-click promotion into high-priority overrides.
- **Traffic telemetry** with connection table, per-outbound stats, live rates,
  event logs, health, and per-subscription lifetime totals.
- **Background probing** with bounded concurrency, short timeout defaults, and
  non-blocking update loops.
- **Control API** for desktop clients and automation.

## Protocol Dialing

Skyhook has native outbound implementations for:

| Protocol | TCP | UDP | Notes |
| --- | --- | --- | --- |
| Direct | yes | yes | Native direct egress. |
| HTTP proxy | yes | no | HTTP CONNECT and absolute-form proxying. |
| SOCKS5 | yes | yes | TCP connect and pooled UDP ASSOCIATE. |
| Shadowsocks AEAD | yes | yes | AES-GCM and ChaCha20-Poly1305, pooled UDP. |
| Shadowsocks simple-obfs | yes | partial | HTTP/TLS obfs for TCP; UDP with plugin is disabled. |
| Trojan | yes | yes | TLS TCP and pooled UDP relay. |
| VMess AEAD | yes | yes | TCP, WebSocket, gRPC, HTTP/2, command UDP. |
| VLESS | yes | yes | TCP, TLS, Reality, WebSocket, gRPC, HTTP/2, command UDP. |
| Hysteria2 | yes | yes | QUIC TCP streams, datagram UDP, Salamander/Gecko paths. |
| TUIC | yes | yes | QUIC TCP, native datagram UDP, stream UDP modes. |
| Naive | yes | no | TLS HTTP CONNECT. |
| SSH | yes | no | Real direct-tcpip dialing, password/private-key auth. |
| SSR | partial | no | Real origin/plain AES-CFB TCP path. |
| Snell | yes | no | Real AEAD TCP path with Argon2id session keys. |
| AnyTLS | yes | no | TLS auth, settings, stream open, SOCKS address handoff. |
| ShadowTLS v3 | yes | no | v3 ClientHello HMAC and application-data framing. |
| WireGuard | planned | planned | Requires L3 tunnel manager, not a TCP stream adapter. |
| OpenVPN | planned | planned | Requires L3 process/tunnel integration. |
| Hysteria v1 | planned | planned | Separate QUIC v1 protocol implementation. |

Capability reporting is first-class. Each outbound reports whether TCP/UDP is
supported, how UDP is implemented, and which limitations are known.

## Smart Routing

Skyhook's routing direction is intentionally different from static-rule cores.
The long-term model is:

1. Observe each new domain, IP, process, and app bundle.
2. Probe whether the destination is directly reachable.
3. Recommend direct when direct is healthy.
4. Recommend proxy when direct fails or performs poorly.
5. Let users promote recommendations into durable smart rules.
6. Keep smart rules above subscription rules.

The current smart-rule engine supports:

- direct-reachability observations,
- recommendation lists,
- proxy/direct recommendation buckets,
- one-click apply-all,
- one-click single recommendation enable,
- high-priority smart overrides,
- persistent state with throttled writes,
- route decisions with optional app identity.

## TUN And DNS

Skyhook includes a TUN integration layer designed for desktop clients and
privileged helpers.

Supported configuration areas include:

- TUN enable/setup flags,
- MTU,
- stack selection,
- auto-route controls,
- strict route,
- IPv4/IPv6 route lists,
- DNS hijack,
- virtual DNS address,
- TCP/UDP session timeouts,
- session limits,
- UID/process/package include and exclude lists,
- app-controlled setup mode,
- macOS LaunchAgent and LaunchDaemon scripts.

DNS support includes:

- UDP DNS listener,
- TCP DNS listener,
- regular nameservers,
- default nameservers,
- fallback nameservers,
- DoH/DoT upstreams,
- fake-IP range,
- fake-IP TTL,
- fake-IP filter options,
- direct/proxy-server nameserver separation,
- timeout and blocking controls.

## Control API

Skyhook exposes a local HTTP API under `/skyhook/*`.

Important endpoints:

- `GET /health`
- `GET /skyhook/version`
- `GET /skyhook/status`
- `GET /skyhook/connections`
- `GET /skyhook/outbounds`
- `POST /skyhook/outbounds/use`
- `GET /skyhook/groups`
- `GET /skyhook/countries`
- `POST /skyhook/countries/use`
- `POST /skyhook/probe/outbounds`
- `POST /skyhook/route/decision`
- `GET /skyhook/subscriptions`
- `POST /skyhook/subscriptions/import`
- `POST /skyhook/subscriptions/use`
- `POST /skyhook/subscriptions/reload-active`
- `POST /skyhook/subscriptions/update-all`
- `POST /skyhook/subscriptions/active-config`
- `GET /skyhook/traffic/subscriptions`
- `GET /skyhook/smart-rules`
- `POST /skyhook/smart-rules`
- `POST /skyhook/smart-rules/enabled`
- `POST /skyhook/smart-rules/delete`
- `POST /skyhook/smart-rules/apply-recommendations`
- `POST /skyhook/smart-rules/apply-recommendation`
- `GET /skyhook/logs`
- `GET /skyhook/config`
- `POST /skyhook/config/reload`

Example probe request:

```json
{ "timeout_ms": 500, "url": "http://cp.cloudflare.com/generate_204" }
```

Example route decision:

```json
{
  "host": "example.com",
  "port": 443,
  "network": "tcp",
  "app_bundle": "com.apple.Safari"
}
```

Example smart rule:

```json
{
  "target": "domain-suffix",
  "value": "example.com",
  "outbound": "direct",
  "enabled": true
}
```

## Quick Start

Generate a config:

```bash
cargo run -- example-config > skyhook.yaml
```

Check a config:

```bash
cargo run -- check -c skyhook.example.yaml
```

Run the core:

```bash
cargo run -- run -c skyhook.example.yaml
```

Probe configured outbounds:

```bash
cargo run -- probe -c skyhook.example.yaml --timeout-ms 500
```

Import a subscription:

```bash
cargo run -- subscriptions import --url https://example.com/sub --id profile-id --name MySub
```

Update all saved subscriptions:

```bash
cargo run -- subscriptions update-all --timeout-secs 10 --retries 1 --concurrency 4
```

Export active subscription into a runnable config:

```bash
cargo run -- subscriptions export-active-config \
  --base skyhook.example.yaml \
  --output active.yaml \
  --use-first-node
```

## Example Config

See [skyhook.example.yaml](skyhook.example.yaml).

Defaults are intentionally local:

- mixed proxy: `127.0.0.1:7897`
- control API: `127.0.0.1:9197`
- probe timeout: `500ms`
- probe concurrency: `256`
- subscription update timeout: `10s`

## macOS

See [docs/macos-system-integration.md](docs/macos-system-integration.md).

For manual TUN diagnosis:

```bash
./scripts/run_macos_tun.sh skyhook.example.yaml
```

For login-time non-root runs:

```bash
./scripts/install_macos_launch_agent.sh
```

For root-owned TUN setup:

```bash
./scripts/install_macos_launch_daemon.sh
```

## Design Principles

- **Native over wrapper.** Implement the core behavior directly in Rust.
- **Measure before switching.** Routing decisions should be backed by health,
  latency, traffic, and reachability signals.
- **Bound everything.** Probes, refreshes, sessions, DNS, and UDP relay paths
  should have explicit limits.
- **Expose the truth.** A desktop client should know why an outbound is healthy,
  slow, unsupported, or failing.
- **Prefer durable state.** Subscriptions, traffic totals, smart rules, and
  observations survive restarts.
- **Make advanced routing humane.** Users should not have to hand-write complex
  rule trees to get sane behavior.

## Roadmap

- Complete Hysteria v1 dialing.
- Add WireGuard/OpenVPN L3 tunnel manager.
- Expand SSR obfs/protocol variants.
- Add Snell UDP and obfs support.
- Add chain outbounds and nested transport composition.
- Add richer DNS rule awareness.
- Harden TUN route setup across macOS/Linux.
- Add benchmark suite for dialing latency, DNS latency, and TUN throughput.
- Add fuzz targets for subscription parsing and rule conversion.
- Publish stable schema docs for config and API.

## Clean-Room Note

Skyhook is an independent Rust implementation. The repository is intended to
contain Skyhook source code, examples, tests, scripts, and vendored dependencies
needed by the build. It does not include private subscriptions, user configs, or
source code from other proxy cores.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
