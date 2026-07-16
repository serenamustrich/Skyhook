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
| Shadowsocks | full | full | full | full | tcp/simple-obfs/v2ray-ws | partial | 旧 AEAD 与 2022-blake3 三种方法均有 TCP/UDP 双向真实拨号；下载方向使用独立 response salt，2022 UDP 含 session/replay protection；SIP023 TCP/UDP 多用户 EIH、simple-obfs HTTP/TLS 与 v2ray-plugin WS 已实拨；plugin UDP 仍明确不支持 |
| ShadowsocksR | full | full | full | partial | tcp/http_simple/http_post/tls1.2_ticket_auth | partial | origin、verify_simple、auth_simple、auth_sha1、auth_sha1_v2、auth_sha1_v4、auth_aes128_md5/sha1 与 auth_chain_a-f 均有真实拨号测试；支持 6 种 stream cipher、TCP/UDP、多用户 `uid:key`、HTTP simple/post 和 TLS ticket 混淆；auth_sha1_v4 按协议边界仅支持 TCP |
| Trojan | full | full | full | full | tcp/ws/grpc/h2/httpupgrade | partial | TLS+TCP、UDP、WS、gRPC、H2、HTTPUpgrade 均有 `build_outbounds` 真实 mock 拨号；支持自定义 transport headers、显式 ALPN、UDP over WS/gRPC 和明确失败分类，其他边界组合仍持续验证 |
| VMess | full | full | full | full | tcp/ws/grpc/h2 | partial | alterId=0 AEAD 的 TCP、WS、gRPC、H2、per-destination UDP 均有 `build_outbounds` 真实集成测试；legacy alterId 和更广泛兼容组合未覆盖 |
| VLESS | full | full | full | partial | tcp/ws/grpc/h2/httpupgrade | partial | Reality/Vision 字段兼容；Vision/Reality 边界字段仍有既定限制 |
| Hysteria v1 | parse-only | parse-only | none | none | quic | parse-only | `outbound` 走 `UnsupportedProtocolOutbound`（见 `src/outbound/mod.rs:377-380`），native 拨号当前未实现；doctor `classify_outbound_with_capability` 在 `core/mod.rs:1300-1301` 返回 ParseOnly（`tcp_supported=false`, `udp_supported=false`, `limitations` 包含 `hysteria is recognized in config/subscriptions but native dialing is not implemented yet`）。测试断言：`tests/remaining_protocols.rs::hysteria_v1_dial_returns_unsupported_error` + `hysteria_v1_capability_marks_unsupported` + `hysteria_v1_routes_through_runtime_to_unsupported`。 |
| Hysteria2 | full | full | partial | partial | quic | partial | wire-format、fragmentation、config 已覆盖；仍缺完整 QUIC/H3 mock server 端到端验证 |
| TUIC | full | full | partial | partial | quic | partial | v5 wire-format、config、UDP mode 已覆盖；仍缺完整 QUIC mock server 端到端验证 |
| Snell | full | full | full | partial | tcp/http/tls | partial | v1-v5 TCP、v3-v5 UDP-over-TCP、独立响应 salt 与 HTTP/TLS obfs 均有真实拨号测试；v5 使用公开的 v4 兼容 wire format；v4/v5 支持 `reuse: true`、10 条连接池、15 秒空闲淘汰、零帧半关闭和陈旧连接自动重拨；v1/v2 UDP 按协议边界在拨号前拒绝 |
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
| HTTPUpgrade | partial | Trojan 已有真实拨号；自定义 headers 与其他协议组合待补 |
| QUIC | partial | Hysteria2/TUIC 已有实现和协议单元测试，完整 mock server E2E 待补 |
| XTLS Vision | partial | 基础支持 |
| Reality | partial | 基础支持 |

## 实现边界

- Shadowsocks 的 AEAD/2022、UDP session、plugin、obfs、framing 和 relay 位于
  `src/outbound/shadowsocks.rs`。
- ShadowsocksR 的 cipher、protocol、obfs、UDP 和 relay 位于
  `src/outbound/ssr.rs`。
- Snell v1-v5、connection reuse、UDP-over-TCP 和 obfs 位于
  `src/outbound/snell.rs`。
- 跨协议精确读取 helper 位于 `src/outbound/io.rs`；协议私有 crypto/framing 不进入
  公共 outbound 根模块。

## 与 Mihomo 差距

1. **WireGuard**: 用户态 userspace 版本已到位，但字段校验缺失时会走 parse-only/unsupported 限制
2. **Hysteria v1**: Mihomo 完整支持，Supercore 仍为 `parse-only`
3. **Snell**: 计划内 v1-v5 TCP、v3-v5 UDP、HTTP/TLS obfs 和 v4/v5 connection reuse 已完成；继续扩大公开服务端、长连接与协议指纹互操作覆盖
4. **SSR**: 当前目标协议、混淆、TCP/UDP 与多用户路径均已实拨；仍需扩大公开服务端组合互操作覆盖
5. **Reality/Vision**: Mihomo 完整支持，Supercore 部分支持
6. **Trojan compatibility edges**: WS/gRPC/H2/HTTPUpgrade、自定义 headers、ALPN、UDP over WS/gRPC 已实拨，更多服务端差异组合仍需兼容验证
7. **VMess compatibility**: alterId=0 的 TCP/WS/gRPC/H2/UDP 已实拨，legacy alterId 与更多边界组合待补
8. **QUIC E2E**: Hysteria2/TUIC 缺完整本地服务端端到端验证

## 已有测试

- Shadowsocks: `tests/ss_real_dial.rs`
- ShadowsocksR: `tests/ssr_real_dial.rs`
- Snell: `tests/snell_real_dial.rs`
- Trojan / VMess: `tests/trojan_vmess_real_dial.rs`
- VLESS: `tests/config_and_runtime.rs`
- Hysteria2 / TUIC: `tests/vless_hy2_tuic.rs`
- AnyTLS: `tests/real_subscription_compat.rs`
- SSR / Snell capability boundaries and WireGuard / AnyTLS / ShadowTLS / Naive / Hysteria v1: `tests/remaining_protocols.rs`
