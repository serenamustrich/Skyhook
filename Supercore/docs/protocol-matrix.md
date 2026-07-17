# Supercore 协议矩阵

本文档记录 Supercore 对各协议的支持状态。

## 状态说明

- **full**: 完整支持，可解析、拨号、传输
- **partial**: 部分支持，某些功能缺失
- **parse-only**: 仅能解析配置，无法真实拨号
- **unsupported**: 不支持

## 协议列表

| 协议 | YAML 解析 | URI 解析 | TCP 拨号 | UDP 支持 | 传输层 | 状态 | 备注 |
|------|-----------|----------|----------|----------|--------|------|------|
| Shadowsocks | full | full | full | full | tcp/simple-obfs/v2ray-ws/UoT | full | 覆盖 legacy stream、stream、AEAD、扩展 AEAD 与 Shadowsocks 2022 方法；TCP/UDP、SIP022、SIP023 多用户 EIH、response salt、session/replay protection、simple-obfs HTTP/TLS、v2ray-plugin WebSocket/TLS 和 UoT v1/v2 均有真实拨号；SIP003 TCP plugin 的 UDP 通过 UoT 承载 |
| ShadowsocksR | full | full | full | full | tcp/random_head/http_simple/http_post/tls1.2_ticket | full | `none/dummy`、AES-CTR/CFB、RC4-MD5、ChaCha20/IETF、XChaCha20 共 11 种 stream cipher；origin、verify_simple、auth_simple、auth_sha1/v2/v4、auth_aes128_md5/sha1、auth_chain_a-f、TCP/UDP、多用户、random_head、HTTP simple/post、TLS ticket auth/fastauth 均有真实拨号；auth_sha1_v4 的 UDP 为协议自身不适用边界 |
| Trojan | full | full | full | full | tcp/ws/grpc/h2/httpupgrade | full | TLS+TCP、UDP、WS、gRPC、H2、HTTPUpgrade 均有 `build_outbounds` 真实 mock 拨号；支持自定义 transport headers、显式/默认 ALPN、UDP over WS/gRPC、gRPC trailer 与 HTTPUpgrade 状态；覆盖 96KB 双向流、半关闭、错误密码、TLS/transport 超时、空密码/未知 network 拨号前拒绝、8192 字节 UDP 边界、空闲 UDP 隧道复用和超时会话淘汰 |
| VMess | full | full | full | full | tcp/ws/grpc/h2/http/httpupgrade | full | alterId=0 AEAD 与 legacy alterId 均为真实 wire 实现；TCP、UDP、WS、gRPC、H2、HTTP camouflage、HTTPUpgrade、自定义 headers、ALPN、AES-128-GCM/ChaCha20-Poly1305/none 均有独立 mock 对端实拨；覆盖 96KB 多帧双向流、认证 EOF、时钟窗口、错误 UUID/响应认证、8192 字节 UDP 边界、多目的 association 和超时会话淘汰；XHTTP 在拨号前明确返回 unsupported，属于冻结配置边界 |
| VLESS | full | full | full | full | tcp/ws/grpc/h2/http/httpupgrade/reality/vision | full | TCP/command-UDP、TLS/无 TLS、WS、gRPC、H2、HTTP camouflage、HTTPUpgrade、自定义 headers 和 ALPN 均有真实拨号；Reality 实现 X25519/HKDF/AES-GCM ClientHello 认证、short ID、时间戳、临时证书 HMAC 校验和 fingerprint profile；Vision 实现双向 padding、TLS record 状态机与独立 direct copy 边界；覆盖 96KB 双向半关闭、多目的 UDP、会话复用和超时淘汰恢复 |
| Hysteria v1 | parse-only | parse-only | none | none | quic | parse-only | `outbound` 走 `UnsupportedProtocolOutbound`（见 `src/outbound/mod.rs:377-380`），native 拨号当前未实现；doctor `classify_outbound_with_capability` 在 `core/mod.rs:1300-1301` 返回 ParseOnly（`tcp_supported=false`, `udp_supported=false`, `limitations` 包含 `hysteria is recognized in config/subscriptions but native dialing is not implemented yet`）。测试断言：`tests/remaining_protocols.rs::hysteria_v1_dial_returns_unsupported_error` + `hysteria_v1_capability_marks_unsupported` + `hysteria_v1_routes_through_runtime_to_unsupported`。 |
| Hysteria2 | full | full | full | full | quic/h3/salamander/gecko | full | 严格 H3 auth、TCP、QUIC datagram UDP、fragmentation/reassembly、连接与会话复用、上下行带宽协商、速率感知拥塞控制均已实现；普通 QUIC、Salamander、Gecko 具有本地真实 QUIC/H3 服务端往返，错误状态/缺失头/错误混淆密码均有拒绝证据 |
| TUIC | full | full | full | full | quic | full | v5 TLS exporter 认证、TCP、native datagram/QUIC 单向流 UDP、fragmentation/reassembly、association 隔离、heartbeat、Dissociate、max packet 和持久 TLS 恢复均有本地真实服务端验证；恢复确认前不发送认证或业务数据，避免 0-RTT replay |
| Snell | full | full | full | full | tcp/http/tls | full | 默认 v1；v1-v5 TCP、v3-v5 UDP-over-TCP、独立响应 salt 与 HTTP/TLS obfs 均有真实拨号测试；v5 使用公开的 v4 兼容 wire format；v4/v5 支持 `reuse: true`、10 条连接池、15 秒空闲淘汰、零帧半关闭、并发流和陈旧连接自动重拨；空 PSK 在拨号前拒绝，v1/v2 UDP 为协议自身不适用边界 |
| WireGuard | full | full | full | partial | udp | partial | required: private/public key/ip；缺失字段会进入 parse-only/unsupported 分支；仅用户态隧道能力 |
| AnyTLS | full | full | partial | none | tcp | partial | anytls over UDP 尚未实现 |
| ShadowTLS | full | full | partial | none | tcp | partial | v3 支持；udp 与独立隧道行为保留限制 |
| Naive | full | full | partial | none | tcp | partial | HTTP/1.1 CONNECT，UDP 与扩展能力未完成 |
| HTTP | full | full | partial | none | tcp | partial | UDP not implemented |
| SOCKS5 | full | full | full | full | tcp | full | - |
| SSH | full | full | partial | none | tcp | partial | SSH-ASSOC/tcp stream path 已支持，UDP 未实现 |
| Mieru | parse-only | parse-only | none | none | - | parse-only | 解析器可识别配置，native 拨号未实现 |
| Juicity | parse-only | parse-only | none | none | - | parse-only | 解析器可识别配置，native 拨号未实现 |
| MASQUE | parse-only | parse-only | none | none | - | parse-only | 解析器可识别配置，native 拨号未实现 |
| OpenVPN | parse-only | parse-only | none | none | - | parse-only | 解析器可识别配置，native 拨号未实现 |

## 传输层支持

| 传输层 | 支持状态 | 备注 |
|--------|----------|------|
| TCP | full | 基础传输 |
| WebSocket | full | path/headers/early-data |
| gRPC | full | serviceName/multi-mode |
| HTTP/2 | full | host/path |
| HTTPUpgrade | full | Trojan、VMess 与 VLESS 均有真实拨号、自定义 headers 和非 101 状态校验 |
| QUIC | full | Hysteria2/TUIC 具有普通、Salamander、Gecko、native datagram、单向流 UDP 和 TLS 恢复的本地真实服务端 E2E |
| XTLS Vision | full | VLESS 双向 padding、TLS 1.3 ServerHello 判定、方向独立切换和 direct copy 均有真实 mock 拨号 |
| Reality | full | X25519/HKDF/AES-GCM ClientHello、short ID、时间窗口、临时证书认证、失败拒绝和 fingerprint profile 均有真实 mock 拨号 |
| 公共 UDP runtime | full | 有界 association/session、两种 NAT keying、队列背压、空闲淘汰、重放/重组保护与每出站统计；具体协议是否支持 UDP 仍以协议行能力为准 |

## 实现边界

- Shadowsocks 的 legacy stream、AEAD/2022、UDP session、UoT、plugin、obfs、framing 和
  relay 位于 `src/outbound/shadowsocks.rs`，Rabbit128 兼容流位于
  `src/outbound/rabbit_compat.rs`。
- ShadowsocksR 的 cipher、protocol、obfs、UDP 和 relay 位于
  `src/outbound/ssr.rs`。
- Snell v1-v5、connection reuse、UDP-over-TCP 和 obfs 位于
  `src/outbound/snell.rs`。
- Trojan 的 TLS、transport、UDP associate、ALPN 和 framing 位于
  `src/outbound/trojan.rs`。
- VMess AEAD/legacy alterId、TCP/UDP command、stream framing 和 transport 位于
  `src/outbound/vmess.rs`。
- VLESS、Reality、TCP/UDP command 和 transport 位于 `src/outbound/vless.rs`，Vision
  padding、TLS record 与 direct copy 状态机位于 `src/outbound/vless_vision.rs`。
- VMess/VLESS 按目标隔离的 session 轮转能力由
  `src/outbound/udp/session_pool.rs` 提供。
- Hysteria2 的 H3 auth、TCP/UDP framing、Salamander/Gecko obfs 和 reassembly 位于
  `src/outbound/hysteria2.rs`。
- TUIC v5 auth、TCP stream、native/QUIC UDP relay 和 reassembly 位于
  `src/outbound/tuic.rs`。
- 跨协议 UDP association、NAT key、session pool、背压、idle eviction、reassembly、
  replay window 和统计位于 `src/outbound/udp/`；协议私有 wire format 保留在各协议模块。
- 两者共用的 endpoint 连接生命周期、QUIC varint 和连接超时位于
  `src/outbound/transports/quic.rs`。
- 跨协议精确读取 helper 位于 `src/outbound/io.rs`；协议私有 crypto/framing 不进入
  公共 outbound 根模块。

## 与 Mihomo 差距

1. **WireGuard**: 用户态 userspace 版本已到位，但字段校验缺失时会走 parse-only/unsupported 限制
2. **Hysteria v1**: Mihomo 完整支持，Supercore 仍为 `parse-only`
3. **SSR public interoperability**: 当前目标协议、混淆、TCP/UDP 与多用户路径均已实拨；仍可继续扩大公开服务端组合互操作覆盖

## 已有测试

- Shadowsocks: `tests/ss_real_dial.rs`
- ShadowsocksR: `tests/ssr_real_dial.rs`
- Snell: `tests/snell_real_dial.rs`
- Trojan / VMess: `tests/trojan_vmess_real_dial.rs`
- VLESS/Reality/Vision: `src/outbound/tests.rs`、`tests/vless_hy2_tuic.rs`
- Hysteria2 / TUIC: `src/outbound/tests.rs`、`tests/vless_hy2_tuic.rs`
- AnyTLS: `tests/real_subscription_compat.rs`
- SSR / Snell capability boundaries and WireGuard / AnyTLS / ShadowTLS / Naive / Hysteria v1: `tests/remaining_protocols.rs`
