# Supercore

Supercore is a Rust-native proxy core for 玥球电梯.

This is not a Mihomo compatibility wrapper. It has its own config model, routing model, telemetry, and control API.

## Current MVP

Protocol capability is described by `docs/protocol-matrix.md` (full/partial/parse-only/unsupported).
Items in this section are capabilities that exist in the current product; protocol-level completeness is
governed by the matrix and may be partial for specific transports, codecs, or fields.

- Mixed inbound listener with SOCKS5 and HTTP CONNECT.
- SOCKS5 UDP ASSOCIATE with bounded concurrent routed UDP exchange.
- HTTP absolute-form proxy requests for plain HTTP.
- Direct, HTTP proxy, and SOCKS5 proxy outbounds, with Direct UDP and pooled SOCKS5 UDP ASSOCIATE.
- Proxy group outbounds for subscription `select`, `url-test`, `fallback`, and similar groups.
- Shadowsocks AEAD TCP and pooled UDP outbound for `aes-128-gcm`, `aes-256-gcm`, and
  `chacha20-ietf-poly1305`.
- Shadowsocks 2022 TCP and UDP for `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`, including SIP022 request and
  response headers, SIP023 extensible identity headers, UDP sessions, and replay windows.
- Shadowsocks `simple-obfs` HTTP/TLS modes for subscriptions that use `obfs=http` or `obfs=tls`.
  Simple-obfs UDP is still restricted by matrix limitations (see `docs/protocol-matrix.md` `Shadowsocks` row).
- Shadowsocks `v2ray-plugin` WebSocket transport with optional TLS, real WebSocket framing, and
  independent response salts.
- ShadowsocksR origin TCP/UDP for AES-CFB, RC4-MD5, ChaCha20, and ChaCha20-IETF; authenticated
  `verify_simple`, `auth_simple`, `auth_sha1`, `auth_sha1_v2`, `auth_sha1_v4`,
  `auth_aes128_md5`/`auth_aes128_sha1`, and `auth_chain_a` through `auth_chain_f`.
  Supported combinations include TCP/UDP, multi-user `uid:key` parameters, HTTP simple/post,
  and TLS ticket obfuscation; protocol-specific UDP boundaries remain explicit in the matrix.
- Snell v1-v5 TCP with independent response salts, HTTP/TLS obfuscation, and v3-v5
  UDP-over-TCP. v5 follows the public v4-compatible wire format. v4/v5 support opt-in
  `reuse: true` with a bounded 10-connection pool, 15-second idle eviction, protocol zero-frame
  half-close, and stale pooled-connection retry. v1/v2 UDP remains an explicit protocol boundary.
- Trojan TCP and pooled UDP outbound over TLS, WebSocket, gRPC, HTTP/2, and HTTPUpgrade, with SNI
  and optional certificate verification bypass. Custom transport headers, explicit ALPN, gRPC
  trailer errors, and UDP over WebSocket/gRPC are covered; wider server compatibility remains
  partial as documented in the protocol matrix.
- VLESS TCP and command-UDP outbound with TLS, SNI, and response-header stripping.
- VLESS WebSocket, gRPC, and HTTP/2 transports for common subscription nodes.
  VLESS remains `partial` in matrix terms due transport/Reality-Vision boundary limits.
- VMess AEAD TCP and command-UDP over TCP, WebSocket, gRPC, and HTTP/2 outbound for modern
  `alterId=0` subscriptions. All listed paths have public `build_outbounds` end-to-end tests;
  legacy alterId and broader compatibility combinations remain partial.
- Hysteria2 and TUIC native QUIC TCP outbounds for common subscription nodes.
- Hysteria2 QUIC datagram UDP exchange with a session pool, UDP fragmentation, and Salamander
  obfuscation.
  Hysteria2 and TUIC remain partial until complete local QUIC server end-to-end tests are present.
- TUIC UDP exchange for `native` QUIC datagram mode and `quic` unidirectional-stream mode, with a
  session pool and UDP fragmentation.
- Structured YAML config.
- Native versioned control API under `/v1/*`.
- Shared transport modules for TCP, TLS, HTTP CONNECT, WebSocket, HTTP/2, gRPC, HTTPUpgrade, and
  QUIC client configuration.
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

- **full**: parse + TCP/UDP probe + dialing path are complete for common usage
- **partial**: parsed and runnable, but with known feature gaps (for example: UDP mode, Reality options, or limited codec/protocol variants)
- **parse-only**: config is recognized but native dialing is not implemented yet
- **unsupported**: not currently implemented or intentionally blocked

Current matrix details are in `docs/protocol-matrix.md`:

- **parse-only**: `mieru`, `juicity`, `masque`, `openvpn`, `hysteria`
- **unsupported**: parse failures and unknown configs with explicit parse errors
- **partial**: includes Shadowsocks, SSR, Trojan, VMess, VLESS, Hysteria2, TUIC, Snell, WireGuard,
  AnyTLS, ShadowTLS, Naive, HTTP, and SSH while their documented gaps remain
- **full**: currently limited to SOCKS5 as a complete protocol capability; individual paths in
  partial protocols may still have stable real-dial tests

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
- `POST /v1/subscriptions/update-all`
- `POST /v1/subscriptions/active-config`
- `GET /v1/providers/proxies`
- `GET /v1/providers/rules`
- `GET /v1/rules`
- `GET /v1/traffic`
- `GET /v1/traffic/subscriptions`
- `GET /v1/smart-rules`
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
- `GET /v1/tasks`
- `GET /v1/tasks/{id}`
- `POST /v1/tasks/{id}/cancel`
- `GET /v1/events`

The control listener is restricted to loopback addresses. `GET`, `HEAD`, and `OPTIONS` are
read-only operations. Every write request must send `Authorization: Bearer <token>`. The macOS App
generates a fresh 256-bit token for each user-mode core process. The TUN LaunchDaemon reads its
token from a root-owned `0600` file; the token is never embedded in the launchd plist.

Full and group probes, subscription imports, and update-all requests return HTTP `202` with a
`task_id`. Clients read `/v1/tasks/{id}` for bounded progress, structured failures, and results, or
cancel the underlying operation through `/v1/tasks/{id}/cancel`. Terminal task records are retained
for up to 24 hours with a default maximum of 512 records, without evicting active work.
`/v1/events` currently streams versioned task updates over SSE with event IDs and timestamps. The
same event surface will carry traffic, connection, and log events after the telemetry event bus is
completed.

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
    cipher: auto
    tls: true
    sni: cdn.example.com
    network: h2
    ws_path: /ray
```

VMess AEAD nodes with `alterId=0`, `tcp`, `ws`, `auto`, `aes-128-gcm`,
`chacha20-poly1305`, or `none` are converted into runnable outbounds. Command-UDP uses a
per-destination session pool to keep UDP flows warm across packets. Legacy VMess alterId and
Reality-like extensions are rejected or reported as protocol limitations.

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
randomly padded frames before sending.

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
is handled through the pool.

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
