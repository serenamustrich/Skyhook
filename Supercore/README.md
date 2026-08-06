# Supercore

Supercore is a Rust-native proxy core for 玥球电梯.

This is not a Mihomo compatibility wrapper. It has its own config model, routing model, telemetry, and control API.

## Features

Protocol capability is described by `docs/protocol-matrix.md` (full/partial/parse-only/unsupported).
Items in this section are capabilities that exist in the current product; protocol-level completeness is
governed by the matrix and may be partial for specific transports, codecs, or fields.

- Mixed inbound listener with SOCKS5 and HTTP CONNECT.
- SOCKS5 UDP ASSOCIATE with bounded concurrent routed UDP exchange.
- HTTP absolute-form proxy requests for plain HTTP.
- Direct, HTTP/HTTPS CONNECT, SOCKS5, and SSH outbounds, with Direct UDP and pooled SOCKS5 UDP ASSOCIATE.
- HTTP and HTTPS proxy outbounds with Basic authentication, SNI and certificate policy, IPv4/IPv6
  CONNECT authorities, non-2xx errors, and preservation of tunnel bytes prefetched with the response.
- SOCKS5 outbounds with no-auth or username/password authentication, domain/IPv4/IPv6 TCP CONNECT,
  UDP ASSOCIATE relay validation, bounded payloads, and reusable UDP session pools.
- SSH outbounds with pinned OpenSSH host keys or SHA-256 fingerprints, host-key algorithm policy,
  password or inline/file private-key authentication, keepalive, concurrent direct-tcpip channels on
  a shared session, and automatic stale-session reconnection. Standard SSH has no UDP relay.
- Proxy group outbounds for subscription `select`, `url-test`, `fallback`, and similar groups.
- Shadowsocks legacy stream, stream, AEAD, and extended AEAD TCP with pooled UDP, including AES,
  ChaCha20/ChaCha8, XChaCha, LEA, AEGIS, AEZ, Deoxys-II, Ascon, and Rabbit128 method families.
- Shadowsocks 2022 TCP and UDP for the BLAKE3 AES-128, AES-256, ChaCha20, and ChaCha8 methods,
  including SIP022 request and response headers, SIP023 extensible identity headers, UDP sessions,
  and replay windows.
- Shadowsocks `simple-obfs` HTTP/TLS modes for subscriptions that use `obfs=http` or `obfs=tls`.
  Simple-obfs UDP is still restricted by matrix limitations (see `docs/protocol-matrix.md` `Shadowsocks` row).
- Shadowsocks `v2ray-plugin` WebSocket transport with optional TLS, real WebSocket framing, and
  independent response salts.
- Shadowsocks UDP-over-TCP v1/v2 for native and plugin transports, with bounded reusable sessions.
- ShadowTLS v3 with authenticated TLS 1.3 ClientHello session IDs, verified and restored backend
  handshake records, HelloRetryRequest handling, active-probe camouflage, and strict certificate
  boundaries. Standalone SOCKS5 data backends, dialer-proxy composition, and the Shadowsocks
  `shadow-tls` SIP003 plugin have independent real-dial coverage; native ShadowTLS is TCP-only.
- NaiveProxy HTTP/2 CONNECT, explicitly selected HTTP/3 CONNECT, and HTTP/1.1 compatibility with
  Basic authentication, official non-index header padding, bidirectional padding for the first
  eight payload frames, multiplexed sessions, and IPv6 targets. NaiveProxy transports TCP streams;
  CONNECT-UDP is an explicit not-applicable boundary.
- ShadowsocksR TCP/UDP for none/dummy, AES-CTR/CFB, RC4-MD5, ChaCha20, ChaCha20-IETF, and
  XChaCha20; authenticated
  `verify_simple`, `auth_simple`, `auth_sha1`, `auth_sha1_v2`, `auth_sha1_v4`,
  `auth_aes128_md5`/`auth_aes128_sha1`, and `auth_chain_a` through `auth_chain_f`.
  Supported combinations include TCP/UDP, multi-user `uid:key` parameters, random-head, HTTP
  simple/post, and TLS ticket auth/fastauth obfuscation; protocol-specific UDP boundaries remain
  explicit in the matrix.
- Snell v1-v5 TCP with independent response salts, HTTP/TLS obfuscation, and v3-v5
  UDP-over-TCP. v5 follows the public v4-compatible wire format. v4/v5 support opt-in
  `reuse: true` with a bounded 10-connection pool, 15-second idle eviction, protocol zero-frame
  half-close, and stale pooled-connection retry. v1/v2 UDP remains an explicit protocol boundary.
- Trojan TCP and pooled UDP outbound over TLS, WebSocket, gRPC, HTTP/2, and HTTPUpgrade, with SNI
  and optional certificate verification bypass. Custom transport headers, explicit ALPN, gRPC
  trailer errors, UDP over WebSocket/gRPC, half-close, bounded UDP payloads, session reuse, and
  timeout eviction are covered by real-dial tests.
- VLESS TCP and command-UDP outbound with TLS or plaintext, WebSocket, gRPC, HTTP/2,
  HTTP/1.1 camouflage, and HTTPUpgrade transports. Custom transport headers, ALPN,
  multi-destination UDP associations, half-close, bounded payloads, and stale-session recovery
  have independent real-dial coverage.
- VLESS Reality performs X25519/HKDF/AES-GCM ClientHello authentication with short IDs and time
  metadata, verifies authenticated temporary certificates, and applies named fingerprint profiles.
  XTLS Vision implements bidirectional padding, TLS-record tracking, TLS 1.3 ServerHello validation,
  and direction-independent direct-copy switching.
- VMess AEAD and legacy alterId TCP plus command-UDP over TCP, WebSocket, gRPC, HTTP/2,
  HTTP/1.1 camouflage, and HTTPUpgrade. The AES-128-GCM, ChaCha20-Poly1305, and none body modes,
  standard `vmess://` JSON, custom transport headers, ALPN, multi-destination UDP associations,
  authenticated EOF, and stale-session eviction have independent real-dial coverage. XHTTP is an
  explicit pre-dial unsupported boundary rather than a false timeout.
- Hysteria v1 native QUIC TCP and UDP with v3 wire authentication, upload/download negotiation,
  rate-aware congestion control, connection/session reuse, fragmentation, fast-open, xplus, and
  wechat-video packet transport. TCP and UDP interoperate with the official `hy1` server.
- Mieru v3 over native TCP or reliable UDP underlays with username/password authentication,
  XChaCha20-Poly1305 encryption, multiplexing, random padding, MTU fragmentation, congestion and
  retransmission control, SOCKS5 TCP/UDP relay, fixed ports and `port-range`. Both official simple
  and protobuf share formats are supported, with TCP/UDP interoperability against `mita`.
- Juicity v0 over native QUIC with UUID/password TLS-exporter authentication, multiplexed TCP,
  reliable UDP-over-stream sessions, BBR/Cubic/NewReno, keepalive, TLS session caching, stale-session
  recovery, and official certificate-chain SHA-256 pinning. TCP/UDP and rejected authentication
  interoperate with the official v0.5.0 server.
- Hysteria2 and TUIC native QUIC TCP outbounds with strict authentication and complete local QUIC
  server end-to-end coverage.
- OpenVPN native TLS control/data channels with TCP, UDP, pushed routes/DNS, reconnect handling and
  userspace Layer-3 relay. The OpenVPN profile never starts an external OpenVPN process.
- Sudoku native KIP handshake, AEAD records, pure Sudoku and 6-bit packed downlink, UoT UDP,
  ASCII/entropy/custom tables, table rotation, and legacy/stream/poll/auto/WebSocket HTTP masking.
- TrustTunnel native HTTP/2 and HTTP/3 CONNECT with Basic authentication, TCP relay and `_udp2`
  framed UDP exchange.
- Tailscale native userspace TCP/UDP with persistent Skyhook-owned identity/control state, optional
  auth key, hostname and tags. It does not invoke the installed Tailscale process or alter host routes.
- DNS outbound for raw UDP, TCP, DNS-over-TLS and DNS-over-HTTPS queries, plus Rematch rule-control
  outbounds with named re-entry, cycle detection and bounded depth.
- Hysteria2 HTTP/3 auth, TCP, QUIC datagram UDP, session reuse, fragmentation, bandwidth-aware
  congestion control, and Salamander/Gecko packet obfuscation.
- TUIC UDP exchange for `native` QUIC datagram mode and `quic` unidirectional-stream mode, with a
  session pool, UDP fragmentation, heartbeat, dissociation, persistent TLS resumption, and a safe
  replay policy that withholds authentication and user traffic until a resumed handshake is
  accepted.
- Structured YAML config.
- Native versioned control API under `/v1/*`.
- Control-plane modules isolate authentication, structured errors, schemas, SSE events, route
  registration, and probe handlers instead of concentrating those responsibilities in one file.
- Runtime modules isolate lifecycle, atomic reload, subscription merge, selection/capabilities,
  probing, connection relay, and DNS exchange; `core/mod.rs` is only the public composition entry.
- A runtime cancellation tree drives graceful control API shutdown, mixed/DNS listener shutdown,
  TUN cancellation, background probe/update cancellation, and active dial contexts.
- Outbound contracts and construction live in dedicated `traits.rs` and `factory.rs` modules.
  Every outbound implementation reports its own TCP/UDP capability and limitations; Runtime no
  longer infers capability from a protocol-name switch.
- Dial errors carry operation, protocol, node, destination, trace ID, retryability, and source
  context. SSH and WireGuard implementations are isolated protocol modules.
- Shared transport modules for TCP, TLS, HTTP CONNECT, WebSocket, HTTP/2, gRPC, HTTPUpgrade, and
  QUIC client configuration.
- Shared UDP runtime with bounded associations, endpoint-dependent and endpoint-independent NAT
  keying, queue backpressure, idle eviction, replay/reassembly guards, and per-outbound statistics.
- Traceable, cancellable dial contexts propagated through concrete outbounds and proxy groups.
- Outbound capability reporting for TCP/UDP support, UDP mode, and known protocol limitations.
- Connection table, traffic totals, event logs, and outbound health.
- Fast active outbound probes with a 500ms default timeout.
- Bounded probe concurrency with a 50 default to avoid resource spikes on large subscriptions.
- Background probe loop that waits the configured interval before its first run and does not block
  proxy traffic.
- Subscription import parser for Clash YAML and URI-list feeds.
- Native multi-subscription store with import, list, switch, update-all, and active config export.
- Per-subscription lifetime upload/download totals.
- Proxy startup always uses the saved local subscription cache and never downloads subscriptions.
- Optional background subscription refresh starts only after its configured interval.
- Bounded subscription refresh with timeout, retry, and concurrency limits.
- Subscription `rule-providers` import, download, cache, and native `RULE-SET` matching.
- Clash rule conversion for `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`,
  `IP-CIDR6`, `PROCESS-NAME`, `PROCESS-PATH`, `RULE-SET`, `GEOSITE`, `GEOIP`, `MATCH`, and
  `FINAL`.
- Local GEOIP matching through configured CIDR ranges, optional MaxMind `.mmdb` databases, and
  startup geo asset cache updates.
- Native smart rules with direct-reachability learning and recommendations.
- Smart rules and learning observations persist to disk with throttled writes.
- Smart-rule APIs support upsert, single-rule enable/disable, delete, and recommendation apply.
- Route rules can send domains, IPs, CIDRs, apps, or app bundles to a named outbound.
- Country recognition, country grouping, and country-based low-latency selection.
- macOS LaunchAgent, LaunchDaemon, and manual TUN startup scripts.

## Protocol capability status

Supercore no longer treats protocol support as a single boolean.

- **full**: parsing and every protocol-applicable TCP/UDP dialing path are complete for common usage
- **partial**: parsed and runnable, but with known feature gaps (for example: UDP mode, Reality options, or limited codec/protocol variants)
- **parse-only**: config is recognized but native dialing is not implemented yet
- **unsupported**: not currently implemented or intentionally blocked

Current matrix details are in `docs/protocol-matrix.md`:

- **full**: `MASQUE` and `OpenVPN` both have native outbound implementations. OpenVPN's
  `faketcp`/packet-backend path remains an explicit platform boundary; MASQUE's H2/H3
  CONNECT-IP and CONNECT-UDP paths are implemented in the native runtime.
- **unsupported**: parse failures and unknown configs with explicit parse errors
- **full**: Shadowsocks, ShadowsocksR, Snell, Trojan, VMess, VLESS, Hysteria v1, Hysteria2, TUIC,
  WireGuard, AnyTLS, ShadowTLS, Naive, Mieru, Juicity, MASQUE, OpenVPN, Sudoku, TrustTunnel,
  Tailscale, DNS outbound, Rematch, HTTP, SOCKS5, and SSH

The current tun2proxy-backed TUN capability boundary is documented in
`docs/tun-capabilities.md`. Unsupported advanced options fail explicitly instead of being silently
ignored.

## Commands

```bash
cargo run -- example-config
cargo run -- check -c supercore.example.yaml
cargo run -- probe -c supercore.example.yaml
cargo run -- probe -c supercore.example.yaml --timeout-ms 500
cargo run -- import-subscription --url https://example.com/sub
cargo run -- import-subscription --file ./subscription.yaml --output ./subscription.json
cargo run -- subscriptions import --url https://example.com/sub --id profile-id --name MySub
cargo run -- subscriptions list
cargo run -- subscriptions use <subscription-id>
cargo run -- subscriptions update-all --timeout-secs 10 --retries 1 --concurrency 4
cargo run -- subscriptions export-active-config --base supercore.example.yaml --output active.yaml --use-first-node
cargo run -- run -c supercore.example.yaml
```

`subscriptions import` keeps the current active subscription when one already exists. The first
imported subscription becomes active automatically; later imports are saved only unless `--switch`
is passed.

## Control API

- `GET /health`
- `GET /v1/version`
- `GET /v1/schema`
- `GET /v1/status`
- `GET /v1/connections`
- `GET /v1/outbounds`
- `POST /v1/outbounds/use`
- `GET /v1/groups`
- `GET /v1/countries`
- `POST /v1/countries/use`
- `POST /v1/probes`
- `POST /v1/probes/group`
- `POST /v1/route/decision`
- `GET /v1/subscriptions`
- `POST /v1/subscriptions/import`
- `POST /v1/subscriptions/use`
- `POST /v1/subscriptions/reload-active`
- `POST /v1/subscriptions/update`
- `POST /v1/subscriptions/update-all`
- `POST /v1/subscriptions/active-config`
- `GET /v1/providers/proxies`
- `GET /v1/providers/rules`
- `POST /v1/providers/update`
- `POST /v1/providers/update-all`
- `GET /v1/rules`
- `GET /v1/traffic`
- `GET /v1/traffic/subscriptions`
- `GET /v1/smart-rules`
- `GET /v1/smart-rules/rules`
- `GET /v1/smart-rules/observations`
- `GET /v1/smart-rules/recommendations`
- `POST /v1/smart-rules`
- `POST /v1/smart-rules/enabled`
- `POST /v1/smart-rules/delete`
- `POST /v1/smart-rules/apply-recommendations`
- `POST /v1/smart-rules/apply-recommendation`
- `GET /v1/logs`
- `GET /v1/config`
- `POST /v1/config/reload`
- `GET /v1/tun`
- `GET /v1/doctor`
- `POST /v1/doctor/run`
- `POST /v1/diagnostics/export`
- `POST /v1/geo/update`
- `GET /v1/tasks`
- `GET /v1/tasks/{id}`
- `POST /v1/tasks/{id}/cancel`
- `GET /v1/events`

Collection endpoints accept a common query contract: `limit` (default `200`, maximum `500`), an
opaque `cursor`, case-insensitive `filter`, endpoint-specific `sort`, and `order=asc|desc`. Their
response includes `pagination.limit`, `returned`, `total`, `next_cursor`, `sort`, `order`, and
`filter`. Cursors are tied to the original filter/sort query and return an explicit stale-cursor
error when their anchor no longer exists. This contract applies to outbounds, groups, countries,
subscriptions, providers, rules, smart-rule collections, subscription traffic, connections, logs,
and tasks.

The control listener is restricted to loopback addresses. `GET`, `HEAD`, and `OPTIONS` are
read-only operations. Every write request must send `Authorization: Bearer <token>`. The macOS App
generates a fresh 256-bit token for each user-mode core process. The TUN LaunchDaemon reads its
token from a root-owned `0600` file; the token is never embedded in the launchd plist.
`GET /v1/schema` exposes the current OpenAPI 3.1 control-plane contract. A compatibility test
checks every declared operation against the registered route paths so route-domain refactors cannot
silently remove an endpoint.

Full and group probes, subscription imports, single/all subscription updates, provider updates,
Geo updates, deep Doctor runs, and diagnostic exports return HTTP `202` with a `task_id` and
`trace_id`. Clients read `/v1/tasks/{id}` for bounded progress, structured failures, and results,
or cancel the underlying operation through `/v1/tasks/{id}/cancel`. Cancellation propagates into
HTTP downloads and provider resolution. Terminal task records are retained for up to 24 hours with
a default maximum of 512 records, without evicting active work.
`/v1/events` streams versioned task, probe progress, runtime status, subscription, connection,
traffic, log, and outbound-health events over SSE with event IDs and timestamps. Live connection
updates and traffic samples are throttled to a 250ms interval, and the bounded event channel never
blocks the proxy data plane on a slow consumer.
The macOS client consumes this stream for live rates, incremental logs, and task progress. It falls
back to one-second traffic and two-second log polling while SSE is unavailable, then refreshes full
snapshots before returning to event-driven updates after reconnect.

Subscription, proxy-provider, rule-provider, and Geo downloads use direct `no_proxy` HTTP clients,
enforce response size limits, and expose only a scheme/host source label in task results. Provider
refresh failures retain the last usable cache or normalized provider payload. Diagnostic exports
are redacted JSON artifacts stored under the subscription data directory with `0600` permissions,
bounded retention, and no subscription URLs, node credentials, raw logs, or connection targets.

`POST /v1/probes` accepts an optional JSON body:

```json
{ "timeout_ms": 500, "url": "http://cp.cloudflare.com/generate_204" }
```

`POST /v1/probes/group` accepts a group name in JSON body and expands nested groups on the core side:

```json
{
  "group": "节点选择/香港",
  "url": "http://cp.cloudflare.com/generate_204",
  "timeout_ms": 500,
  "concurrency": 50
}
```

`POST /v1/outbounds/use` switches the runtime default outbound and any `match` fallback rule
to a concrete outbound or generated group:

```json
{ "name": "HK-01" }
```

`POST /v1/subscriptions/import` accepts either raw subscription text or a URL:

```json
{
  "name": "My Sub",
  "url": "https://example.com/sub",
  "switch": false
}
```

or:

```json
{
  "name": "Local Sub",
  "text": "proxies:\n  - name: HK-01\n    type: ss\n    server: hk.example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: secret\n"
}
```

`POST /v1/subscriptions/active-config` returns the current runtime config with active
subscription nodes merged in. When `use_first_node` is true, the default outbound and fallback
`match` rule are moved to the first supported subscription node.

Subscription `proxy-groups` are exported as native `group` outbounds. `select`, `url-test`,
`auto`, `latency`, and `load-balance` race members in parallel and use the first successful
connection; `fallback` keeps ordered failover behavior.

Convertible subscription rules replace the base static `rules` when an active subscription is
merged. `DIRECT` is normalized to Supercore's built-in `direct` outbound. `RULE-SET` and
`GEOSITE` providers are downloaded or read from local paths, cached under the subscription, and
compiled into native rule sets. `GEOIP` can match configured CIDR ranges or an optional MaxMind
`.mmdb` file through `geoip_database`.

When `geo.auto_update` and `geo.update_on_start` are enabled, Supercore downloads configured
`geo.geoip_url` and `geo.geosite_url` files into `geo.cache_dir` before building runtime state.
If `geoip_database` is not set and a cached `geoip.mmdb` exists, Supercore uses that cached file
for native `GEOIP` matching.

`supercore run` always starts from the saved local subscription cache and never downloads a
subscription during proxy startup. When `subscriptions.auto_update` is enabled, refreshes run only
after the configured `subscriptions.update_interval_secs` delay.
Each update batch is bounded by `subscriptions.update_timeout_secs`,
`subscriptions.update_retries`, and `subscriptions.update_concurrency`.

`GET /v1/groups` returns each proxy group, its members, health, measured latency, and current best
member. `GET /v1/countries` returns country buckets inferred from node names and server metadata.
`POST /v1/countries/use` selects a generated `country:<CODE>` url-test group:

```json
{ "code": "JP" }
```

`GET /v1/traffic/subscriptions` returns lifetime upload/download totals persisted per
subscription.

`GET /v1/smart-rules` returns the lightweight learning summary. Rules, observations, and
recommendations are exposed as independently paginated collections through
`/v1/smart-rules/rules`, `/v1/smart-rules/observations`, and
`/v1/smart-rules/recommendations`.

`POST /v1/smart-rules` inserts or replaces a smart override:

```json
{
  "target": "domain-suffix",
  "value": "example.com",
  "outbound": "direct",
  "enabled": true
}
```

`POST /v1/smart-rules/enabled` toggles one smart override:

```json
{ "target": "domain-suffix", "value": "example.com", "enabled": false }
```

`POST /v1/smart-rules/delete` removes one smart override:

```json
{ "target": "domain-suffix", "value": "example.com" }
```

`POST /v1/smart-rules/apply-recommendations` enables current recommendations as smart rules:

```json
{ "action": "direct" }
```

Omit the body to enable both direct and proxy recommendations.

`POST /v1/smart-rules/apply-recommendation` enables one recommendation:

```json
{ "target": "domain-suffix", "value": "example.com" }
```

Route targets include `domain`, `domain-suffix`, `domain-keyword`, `ip`, `ip-cidr`,
`app-name`, `app-path`, `app-bundle`, and `match`.

`POST /v1/route/decision` accepts a destination with optional app identity:

```json
{
  "host": "example.com",
  "port": 443,
  "app": { "bundle_id": "com.apple.Safari", "name": "Safari" }
}
```

Basic Shadowsocks outbound:

```yaml
outbounds:
  - type: shadowsocks
    name: hk-01
    server: hk.example.com
    port: 8388
    method: aes-128-gcm
    password: secret
    plugin:
      mode: http
      host: edge.example.com
```

Subscription nodes with `plugin=simple-obfs;obfs=http;obfs-host=...` or
`plugin=simple-obfs;obfs=tls;obfs-host=...` are converted into runnable Shadowsocks outbounds.
UDP is supported for plain AEAD Shadowsocks nodes; `simple-obfs` UDP is still reported as an
unsupported capability.

Basic Trojan outbound:

```yaml
outbounds:
  - type: trojan
    name: tr-01
    server: tr.example.com
    port: 443
    password: secret
    sni: cdn.example.com
    skip_cert_verify: false
```

Trojan URI subscriptions like `trojan://password@host:443?sni=example.com#name` are converted into
runnable outbounds. TCP CONNECT and pooled UDP ASSOCIATE streams are implemented.

Basic VLESS outbound:

```yaml
outbounds:
  - type: vless
    name: vl-01
    server: vl.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    sni: cdn.example.com
    skip_cert_verify: false
    network: h2
    ws_path: /ray
```

VLESS URI subscriptions like `vless://uuid@host:443?security=tls&type=tcp&sni=example.com#name`
are converted into runnable outbounds. TCP, WebSocket, gRPC, and HTTP/2 transports are implemented.
`flow=xtls-rprx-vision` is preserved in the VLESS request Addons for TLS-over-TCP nodes. Reality
subscription fields are parsed and validated, and dialing uses a local rustls patch plus a
Supercore-owned X25519 key-share to seal the TLS 1.3 ClientHello Session ID. Command-UDP uses a
per-destination session pool for TLS and Reality nodes, so repeated UDP exchanges reuse established
outer streams instead of reconnecting per packet.

Basic VMess outbound:

```yaml
outbounds:
  - type: vmess
    name: vm-01
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alter_id: 0
    cipher: auto
    tls: true
    sni: cdn.example.com
    network: h2
    ws_path: /ray
```

VMess AEAD nodes with `alterId=0` and legacy nodes with a positive `alterId` are runnable.
Supported transports are `tcp`, `ws`, `grpc`, `h2`, `http`, and `httpupgrade`; supported body
ciphers are `auto`, `aes-128-gcm`, `chacha20-poly1305`, and `none`. Command-UDP uses a bounded
per-destination session pool. `xhttp` is rejected before network dialing with a precise unsupported
error.

Basic Hysteria v1 outbound:

```yaml
outbounds:
  - type: hysteria
    name: hy1-01
    server: hy1.example.com
    port: 443
    auth-str: secret
    up: 100 Mbps
    down: 100 Mbps
    sni: cdn.example.com
    protocol: udp
    skip_cert_verify: false
```

Hysteria v1 accepts `hysteria://` subscriptions and numeric or unit-bearing bandwidth values. It
implements the official v3 ClientHello/ServerHello and TCP/UDP framing, server-assigned UDP session
IDs, endpoint-independent sessions, fragmentation/reassembly, connection single-flight, fast-open,
rate-aware congestion control, and `xplus`/`wechat-video` packet modes. The native TCP and UDP path
interoperates with the official Hysteria `hy1` server. `faketcp` requires a supported Linux packet
backend and is rejected explicitly on macOS.

Basic Hysteria2 outbound:

```yaml
outbounds:
  - type: hysteria2
    name: hy2-01
    server: hy2.example.com
    port: 443
    password: secret
    sni: cdn.example.com
    skip_cert_verify: false
```

Hysteria2 URI subscriptions using `hysteria2://` or `hy2://` are converted into runnable native
QUIC TCP outbounds. UDP exchange uses a small QUIC datagram session pool per outbound and supports
datagram fragmentation/reassembly. Salamander obfuscation is implemented at the QUIC packet socket
layer; Gecko obfuscation wraps Salamander and fragments QUIC long-header handshake datagrams into
randomly padded frames before sending. Authentication strictly validates status 233 and the
required `Hysteria-UDP`/`Hysteria-CC-RX` response headers. Upload/download bandwidth settings feed
the negotiated receive-rate header and a rate-aware BDP controller. Plain QUIC, Salamander, and
Gecko all have local HTTP/3 server authentication and bidirectional relay coverage.

Basic TUIC outbound:

```yaml
outbounds:
  - type: tuic
    name: tuic-01
    server: tuic.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    password: secret
    sni: cdn.example.com
    alpn: h3
    skip_cert_verify: false
```

TUIC URI subscriptions using `tuic://` are converted into runnable native QUIC TCP outbounds.
UDP exchange uses a small associate session pool per outbound for both `native` QUIC datagram mode and
`quic` unidirectional-stream mode, with packet fragmentation/reassembly. Parallel multi-session UDP
is handled by per-association dispatchers so concurrent sessions cannot consume each other's
packets. Heartbeat and Dissociate commands, packet-size limits, persistent TLS session resumption,
and accepted resumed handshakes are covered by a local TUIC v5 server. Authentication and user
traffic are intentionally held until handshake acceptance so replayable early data is never used.

## Real Subscription Compatibility Tests

The checked-in fixture covers a sanitized mixed Clash subscription. Private external subscription
URLs are tested without persisting their contents:

```bash
SUPERCORE_TEST_SUBSCRIPTION_URLS='https://example.com/sub1,https://example.com/sub2' \
  ./scripts/check_real_subscriptions.sh
```

## macOS Integration

User-mode launch:

```bash
./scripts/install_macos_launch_agent.sh
```

TUN/root launch without repeated password prompts:

```bash
./scripts/install_macos_launch_daemon.sh
```

Manual TUN diagnosis:

```bash
./scripts/run_macos_tun.sh supercore.example.yaml
```

See `docs/macos-system-integration.md` for permission boundaries and installed paths.
