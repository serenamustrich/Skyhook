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
| Hysteria v1 | full | full | full | full | quic/xplus/wechat-video | full | 原生实现官方 v3 ClientHello/ServerHello、auth/auth-str、上下行带宽协商、速率感知拥塞控制、TCP、QUIC datagram UDP、服务端 session ID、fragmentation/reassembly、单飞连接池、UDP 会话复用、fast-open、窗口/MTU/keepalive/timeout；已与官方 `hy1` 分支 `ac56271` 服务端完成 TCP/UDP 互通。`faketcp` 依赖 Linux packet backend，在 macOS 上拨号前明确拒绝 |
| Hysteria2 | full | full | full | full | quic/h3/salamander/gecko | full | 严格 H3 auth、TCP、QUIC datagram UDP、fragmentation/reassembly、连接与会话复用、上下行带宽协商、速率感知拥塞控制均已实现；普通 QUIC、Salamander、Gecko 具有本地真实 QUIC/H3 服务端往返，错误状态/缺失头/错误混淆密码均有拒绝证据 |
| TUIC | full | full | full | full | quic | full | v5 TLS exporter 认证、TCP、native datagram/QUIC 单向流 UDP、fragmentation/reassembly、association 隔离、heartbeat、Dissociate、max packet 和持久 TLS 恢复均有本地真实服务端验证；恢复确认前不发送认证或业务数据，避免 0-RTT replay |
| Snell | full | full | full | full | tcp/http/tls | full | 默认 v1；v1-v5 TCP、v3-v5 UDP-over-TCP、独立响应 salt 与 HTTP/TLS obfs 均有真实拨号测试；v5 使用公开的 v4 兼容 wire format；v4/v5 支持 `reuse: true`、10 条连接池、15 秒空闲淘汰、零帧半关闭、并发流和陈旧连接自动重拨；空 PSK 在拨号前拒绝，v1/v2 UDP 为协议自身不适用边界 |
| WireGuard | full | full | full | full | udp/userspace-netstack | full | BoringTun Noise 握手与计数器、真实用户态 TCP/UDP、IPv4/IPv6、隧道内 DNS（UDP 截断后回退 TCP）、MTU、reserved、pre-shared key、persistent keepalive、多 Peer 和 allowed IP 最长前缀路由；配置错误在拨号前明确拒绝 |
| AnyTLS | full | full | full | full | tcp/UoT-v2 | full | v2 TLS auth、官方 padding 与服务端动态更新、SYNACK、心跳、会话复用、空闲回收、TCP 和 sing-box UoT v2 UDP；独立 TLS 服务端覆盖 96KB TCP、并发流、UDP、单会话复用和超时淘汰 |
| ShadowTLS | full | full | full | not-applicable | tcp/ss-plugin/dialer-proxy | full | 严格 v3 TLS 1.3 ClientHello HMAC、握手 ApplicationData 校验/XOR 还原、HelloRetryRequest、TLS camouflage、证书与密码错误边界均已实现；独立 SOCKS5 data backend、dialer-proxy 和 Shadowsocks `shadow-tls` SIP003 plugin 有真实拨号。ShadowTLS 原生是 TCP transport，Shadowsocks UDP 通过 UoT 承载 |
| Naive | full | full | full | not-applicable | h1/h2/h3 | full | 默认 HTTP/2 CONNECT，支持显式 HTTP/3 CONNECT 和 HTTP/1.1 兼容路径；Basic Auth、官方 16-32 字节非索引 header padding、双向前 8 帧 payload padding、H2/H3 单连接多流复用、IPv6 authority、407/证书/状态错误边界均已实现。NaiveProxy 只承载 TCP 流，协议没有 CONNECT-UDP；H3 与仅 TCP 的 dialer-proxy 组合会在拨号前明确拒绝，避免静默直连泄漏 |
| HTTP | full | full | full | not-applicable | tcp/tls | full | HTTP/HTTPS CONNECT、Basic Auth、SNI/证书策略、IPv4/IPv6 authority、2xx/非 2xx 状态和握手同包预读数据均有真实拨号；HTTP CONNECT 原生仅承载 TCP |
| SOCKS5 | full | full | full | full | tcp/udp-associate | full | 无认证与用户名密码认证、域名/IPv4/IPv6 CONNECT、UDP ASSOCIATE、relay 来源校验、最大 payload 和 4 会话轮转池均有真实拨号 |
| SSH | full | full | full | not-applicable | direct-tcpip | full | OpenSSH 公钥/SHA-256 指纹固定、主机密钥算法策略、密码/内联或文件私钥认证、keepalive、并发通道共享会话和服务端断线重连均已实现；SSH 无标准 UDP relay |
| Mieru | full | full | full | full | tcp/udp | full | 原生 Mieru v3：PBKDF2-HMAC-SHA256、XChaCha20-Poly1305、用户名/密码认证、官方 `mierus://` 与完整 protobuf `mieru://` 分享格式、固定端口和 `port-range`、TCP/UDP underlay、标准/no-wait 握手、off/low/middle/high multiplexing、随机 padding、MTU 分片、累计 ACK、重排、RTT/RTO、快速重传、CUBIC、心跳和 SOCKS5 UDP ASSOCIATE；已与官方 `mita` 服务端完成 TCP/UDP、多路复用、UDP ASSOCIATE 及丢包乱序互通 |
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
| HTTP/3 CONNECT | full | Naive 显式 H3 传输支持 Basic Auth、padding 和多流复用 |
| HTTPUpgrade | full | Trojan、VMess 与 VLESS 均有真实拨号、自定义 headers 和非 101 状态校验 |
| QUIC | full | Hysteria v1 具有官方服务端 TCP/UDP 互通及 xplus/wechat-video 包装验证；Hysteria2/TUIC 具有普通、Salamander、Gecko、native datagram、单向流 UDP 和 TLS 恢复的本地真实服务端 E2E |
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
- Hysteria v1 的 v3 auth、TCP/UDP framing、fast-open、xplus/wechat-video、会话复用和
  fragmentation/reassembly 位于 `src/outbound/hysteria.rs`。
- Mieru v3 的认证、stateful/stateless cipher、TCP/UDP underlay、multiplexing、可靠 UDP、
  MTU 分片、拥塞控制和 SOCKS5 relay 位于 `src/outbound/mieru.rs`。
- Hysteria2 的 H3 auth、TCP/UDP framing、Salamander/Gecko obfs 和 reassembly 位于
  `src/outbound/hysteria2.rs`。
- TUIC v5 auth、TCP stream、native/QUIC UDP relay 和 reassembly 位于
  `src/outbound/tuic.rs`。
- WireGuard 的 BoringTun 会话、用户态 TCP/IP 栈、TCP/UDP socket、DNS、Peer 路由、
  keepalive 和 replay/counter 处理位于 `src/outbound/wireguard.rs`。
- AnyTLS v2 的认证、padding、会话/流调度、SYNACK、心跳、空闲回收和 UoT v2 位于
  `src/outbound/anytls.rs`。
- ShadowTLS v3 的 ClientHello 认证、TLS handshake wrapper、camouflage、data HMAC 和 backend
  组合位于 `src/outbound/shadowtls.rs`；Shadowsocks plugin 接入位于
  `src/outbound/shadowsocks.rs`。
- Naive 的 HTTP/1.1、HTTP/2、HTTP/3 CONNECT、Basic Auth、padding、连接复用和错误边界
  位于 `src/outbound/naive.rs`；H3 遇到仅支持 TCP 的 dialer-proxy 时会明确拒绝。
- HTTP/HTTPS CONNECT、TLS 和响应预读保留位于 `src/outbound/http_proxy.rs` 与
  `src/outbound/transports/http_connect.rs`；SOCKS5 TCP/UDP 位于 `src/outbound/socks5.rs`；
  SSH host key policy、认证、会话复用与 direct-tcpip relay 位于 `src/outbound/ssh.rs`。
- 跨协议 UDP association、NAT key、session pool、背压、idle eviction、reassembly、
  replay window 和统计位于 `src/outbound/udp/`；协议私有 wire format 保留在各协议模块。
- 两者共用的 endpoint 连接生命周期、QUIC varint 和连接超时位于
  `src/outbound/transports/quic.rs`。
- 跨协议精确读取 helper 位于 `src/outbound/io.rs`；协议私有 crypto/framing 不进入
  公共 outbound 根模块。

## 未完成协议边界

1. **Juicity / MASQUE / OpenVPN**: 当前仍为 `parse-only`
2. **DNS outbound / Rematch / Sudoku / Tailscale / TrustTunnel**: 尚未进入正式出站模型
3. **SSR public interoperability**: 当前目标协议、混淆、TCP/UDP 与多用户路径均已实拨；仍可继续扩大公开服务端组合互操作覆盖

## 已有测试

- Shadowsocks: `tests/ss_real_dial.rs`
- ShadowsocksR: `tests/ssr_real_dial.rs`
- Snell: `tests/snell_real_dial.rs`
- Trojan / VMess: `tests/trojan_vmess_real_dial.rs`
- VLESS/Reality/Vision: `src/outbound/tests.rs`、`tests/vless_hy2_tuic.rs`
- Hysteria v1: `tests/hysteria_v1_real_dial.rs`，覆盖真实 QUIC TCP/UDP、错误鉴权、
  fast-open 和认证超时；`src/outbound/hysteria.rs` 覆盖官方 wire、xplus、wechat-video、
  UDP fragmentation/reassembly；另有官方 `hy1` 服务端 TCP/UDP 互通验证
- Mieru: `src/outbound/mieru.rs` 覆盖 TCP/UDP underlay 真实拨号、stateful/stateless wire、
  MTU、配置和端口段；`src/subscription/mod.rs` 覆盖官方简单/完整分享格式。另与官方
  `mita` 服务端完成 TCP/UDP、多会话、UDP ASSOCIATE 和丢包乱序互通验证
- Hysteria2 / TUIC: `src/outbound/tests.rs`、`tests/vless_hy2_tuic.rs`
- WireGuard: `src/outbound/wireguard.rs` 的本地双端 E2E，覆盖 IPv4/IPv6、TCP/UDP、
  DNS、96KB 数据、多 Peer、最长前缀、保活、reserved 和重放拒绝
- AnyTLS: `tests/anytls_real_dial.rs`、`src/outbound/anytls.rs` 单元测试和
  `tests/remaining_protocols.rs`
- ShadowTLS: `tests/shadowtls_real_dial.rs`，覆盖独立服务端 96KB TCP、HelloRetryRequest、
  Shadowsocks plugin、错密码、证书拒绝和 camouflage
- Naive: `tests/naive_real_dial.rs`，覆盖 H2/H3 单连接双流复用、每流 96KB 数据、Basic Auth、
  header/payload padding 和 407 不重拨；H1 兼容与 UDP 不适用边界位于 `tests/remaining_protocols.rs`
- HTTP/HTTPS CONNECT: `tests/http_proxy_real_dial.rs`，覆盖 TLS/明文、认证、IPv6、96KB、
  预读数据、407 和证书拒绝
- SOCKS5: `tests/socks5_real_dial.rs`，覆盖域名/IPv4/IPv6、96KB、认证拒绝、UDP ASSOCIATE
  和会话池复用
- SSH: `tests/ssh_real_dial.rs`，覆盖密码/私钥、host key 拒绝、96KB、并发会话复用和断线重连
- SSR / Snell capability boundaries and WireGuard 配置边界 / AnyTLS / Hysteria v1 capability: `tests/remaining_protocols.rs`
