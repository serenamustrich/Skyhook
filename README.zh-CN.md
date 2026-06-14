# Skyhook

[![CI](https://github.com/serenamustrich/Skyhook/actions/workflows/ci.yml/badge.svg)](https://github.com/serenamustrich/Skyhook/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)

[English](README.md)

**Skyhook** 是一个 Rust 原生的智能代理核心。  
中文名：**玥球核心**。

Skyhook 把代理协议拨号、TUN 流量捕获、订阅管理、流量遥测、节点测速、国家择优和智能规则放在同一个独立 Rust 核心里。

它适合桌面代理客户端、菜单栏 App、自动化工具和本地网络控制面使用，核心目标是提供快速、可观测、可编程的代理引擎。

## 下载

1. macOS App DMG：[玥球电梯.dmg](https://github.com/serenamustrich/Skyhook/releases/download/v0.1.1/%E7%8E%A5%E7%90%83%E7%94%B5%E6%A2%AF.dmg)
2. Skyhook 核心二进制会发布在 GitHub Releases。

## 核心能力

### Inbound 和 TUN

1. Mixed inbound 代理服务。
2. SOCKS5 TCP 代理。
3. SOCKS5 UDP ASSOCIATE。
4. HTTP CONNECT 代理。
5. 普通 HTTP absolute-form 代理。
6. TUN 模式。
7. DNS hijack。
8. 虚拟 DNS。
9. Native TUN metrics。
10. macOS utun 支持。
11. Linux `/dev/net/tun` 支持。
12. 路由和地址 setup plan。
13. 私有网络自动 bypass。
14. IP literal endpoint 自动 bypass。
15. Session 数量限制和 idle cleanup。
16. SNI sniffing。
17. HTTP Host sniffing。
18. macOS/Linux process metadata lookup。

### NativeL3

1. 从 TUN 读取原始 IP packet。
2. WireGuard L3 packet bridge。
3. 从 outbounds 自动发现 L3 profile。
4. L3 profile start/stop API。
5. WireGuard Noise handshake engine。
6. WireGuard keepalive 和 timer。
7. WireGuard packet encapsulation/decapsulation。
8. L3 packet subscription channel。
9. Direct/routed path TCP forwarding。
10. Direct/routed path UDP relay。
11. Response packet 注入回 TUN stack。
12. DNS cache 支持 IP 到域名反查。
13. packets、bytes、errors、active targets 等 native metrics。

### DNS

1. UDP DNS listener。
2. TCP DNS listener。
3. DoH upstream。
4. DoT upstream。
5. Default nameserver。
6. Fallback nameserver。
7. Direct/proxy-server nameserver 分离。
8. Fake-IP 分配。
9. Fake-IP reverse lookup。
10. Fake-IP filter。
11. DNS timeout controls。
12. TUN virtual-DNS integration。

### 订阅

1. Clash 风格 YAML 订阅解析。
2. URI-list 订阅解析。
3. 多订阅存储。
4. 订阅导入。
5. Active subscription 切换。
6. Update-all 订阅刷新。
7. 启动时订阅刷新。
8. 后台订阅刷新。
9. Active subscription config 导出。
10. 节点元数据保留。
11. 代理组保留。
12. Proxy provider 解析和节点落地。
13. Provider-only 订阅支持。
14. 订阅规则保留。
15. 规则提供者保留。
16. 订阅刷新强制直连。
17. Provider 刷新强制直连。
18. 国家元数据提取。
19. 按订阅累计 lifetime traffic。

### 代理组

1. `select` 组。
2. `url-test` 组。
3. `fallback` 组。
4. `auto` 组。
5. Latency-oriented 组。
6. Load-balance 类组。
7. 控制 API 输出 group snapshot。
8. Best-latency reporting。
9. 显式选择代理组。
10. 国家组选择。

### 规则

1. Domain 规则。
2. Domain suffix 规则。
3. Domain keyword 规则。
4. IP 规则。
5. CIDR 规则。
6. App bundle 规则。
7. Process 规则。
8. Rule-set 规则。
9. Geosite 规则。
10. GeoIP 规则。
11. Match/final 规则。
12. 订阅规则转换。
13. 配置文件内联规则。
14. 高优先级 smart-rule override。

### 智能路由

1. 域名观察。
2. IP 观察。
3. App/process 观察。
4. 直连可达性探测。
5. 代理推荐列表。
6. 直连推荐列表。
7. 单条推荐启用。
8. 全部推荐启用。
9. 持久化 smart-rule state。
10. 可配置 direct-probe timeout。
11. 可配置 probe concurrency。
12. 可配置 confidence threshold。
13. 智能规则优先级高于订阅规则。

### 流量和遥测

1. Runtime connection table。
2. Per-outbound traffic counters。
3. Live rate snapshots。
4. Lifetime traffic counters。
5. Per-subscription traffic counters。
6. TUN packet counters。
7. TUN byte counters。
8. TUN error counters。
9. Event logs。
10. Runtime health snapshots。
11. Outbound capability reporting。

### 控制 API

Skyhook 暴露本地 HTTP API，用于 runtime 控制和监控。

| API | 功能 |
| --- | --- |
| `GET /health` | 健康检查。 |
| `GET /skyhook/version` | 版本信息。 |
| `GET /skyhook/status` | Runtime 状态。 |
| `GET /skyhook/connections` | 连接和流量表。 |
| `GET /skyhook/outbounds` | Outbound 列表、健康和 capabilities。 |
| `POST /skyhook/outbounds/use` | 切换默认 outbound。 |
| `POST /skyhook/probe/outbounds` | 测速 outbounds。 |
| `GET /skyhook/groups` | 代理组快照。 |
| `GET /skyhook/countries` | 国家组快照。 |
| `POST /skyhook/countries/use` | 选择国家组。 |
| `GET /skyhook/tun/profile` | TUN 启动画像。 |
| `GET /skyhook/tun/status` | TUN 运行状态。 |
| `GET /skyhook/tun/metrics` | Native TUN 指标。 |
| `GET /skyhook/l3` | L3 profile 状态。 |
| `POST /skyhook/l3/start` | 启动 L3 profiles。 |
| `POST /skyhook/l3/stop` | 停止 L3 profiles。 |
| `GET /skyhook/subscriptions` | 已保存订阅。 |
| `POST /skyhook/subscriptions/import` | 导入订阅。 |
| `POST /skyhook/subscriptions/use` | 切换 active subscription。 |
| `POST /skyhook/subscriptions/update-all` | 刷新全部订阅。 |
| `GET /skyhook/traffic/subscriptions` | 按订阅统计 lifetime traffic。 |
| `GET /skyhook/smart-rules` | 智能规则快照。 |
| `GET /skyhook/smart-rules/stats` | 智能规则统计。 |
| `GET /skyhook/smart-rules/recommendations` | 智能推荐。 |
| `POST /skyhook/route/decision` | 查询 route decision。 |
| `GET /skyhook/config` | 当前 runtime config。 |
| `POST /skyhook/config/reload` | 重载配置。 |

## 协议能力

| 协议 | TCP | UDP | 状态 | 功能 |
| --- | --- | --- | --- | --- |
| Direct | yes | yes | production | 原生直连出口。 |
| HTTP proxy | yes | no | production | HTTP CONNECT 和 absolute-form 代理。 |
| SOCKS5 | yes | yes | production | TCP connect 和 UDP ASSOCIATE。 |
| Shadowsocks AEAD | yes | yes | production | AES-GCM 和 ChaCha20-Poly1305。 |
| Shadowsocks simple-obfs | yes | partial | production | TCP HTTP/TLS obfs。 |
| SSR | partial | no | partial | Origin AES-CFB TCP 和首包 obfs 路径。 |
| Trojan | yes | yes | production | TLS TCP 和 UDP relay。 |
| VMess AEAD | yes | yes | production | TCP、WebSocket、gRPC、HTTP/2、command UDP。 |
| VLESS | yes | yes | production | TCP、TLS、Reality、WebSocket、gRPC、HTTP/2、command UDP。 |
| Hysteria2 | yes | yes | production | QUIC TCP stream 和 datagram UDP。 |
| Hysteria v1 | partial | partial | partial | QUIC runtime path 和 env-gated real-server coverage。 |
| TUIC | yes | yes | partial | QUIC TCP、datagram UDP 和 stream UDP。 |
| Naive | yes | no | production | TLS HTTP CONNECT。 |
| SSH | yes | no | partial | direct-tcpip，支持密码和私钥认证。 |
| Snell | yes | no | partial | AEAD TCP 和 HTTP obfs 首包。 |
| AnyTLS | yes | no | production | TLS auth、settings、stream open、SOCKS address handoff。 |
| ShadowTLS v3 | yes | no | production | v3 ClientHello HMAC 和 application-data framing。 |
| WireGuard | L3 | L3 | experimental | Native L3 manager 和 WireGuard Noise packet engine。 |
| OpenVPN | parser only | no | parser-only | `.ovpn` parser 和 profile 注册。 |
| Mieru | parser only | no | parser-only | 配置解析面。 |
| Juicity | parser only | no | parser-only | 配置解析面。 |
| MASQUE | parser only | no | parser-only | 配置解析面。 |

状态标签：

1. **production**：支持 runtime 能力，并有本地自动化覆盖。
2. **partial**：支持 runtime 表面，变体覆盖有限。
3. **experimental**：可用于高级场景的 runtime 表面。
4. **parser-only**：配置或订阅解析能力。

## 配置能力

Skyhook 配置覆盖：

1. Core listen addresses。
2. Mixed inbound settings。
3. TUN settings。
4. DNS settings。
5. Outbound definitions。
6. Proxy group definitions。
7. Rule definitions。
8. Rule provider definitions。
9. Subscription store settings。
10. Smart-rule settings。
11. Traffic store paths。
12. Probe timeout and concurrency。
13. NativeL3 profile settings。
14. L3 tunnel settings。

示例配置：

1. [minimal-direct.yaml](examples/minimal-direct.yaml)
2. [proxy-groups.yaml](examples/proxy-groups.yaml)
3. [smart-rules.yaml](examples/smart-rules.yaml)
4. [native-tun.yaml](examples/native-tun.yaml)
5. [skyhook.example.yaml](skyhook.example.yaml)

## 文档

1. [API reference](docs/API.md)
2. [Protocol support matrix](docs/PROTOCOL_SUPPORT_MATRIX.md)
3. [Security notes](docs/SECURITY.md)
4. [macOS system integration](docs/macos-system-integration.md)
5. [Native TUN real-test notes](docs/NATIVE_TUN_REAL_TEST_REPORT.md)
6. [Performance benchmarks](docs/PERFORMANCE_BENCHMARKS.md)

## Clean-Room 声明

Skyhook 是独立 Rust 实现。仓库包含 Skyhook 源码、测试、示例、脚本和构建依赖；不包含私人订阅、用户配置，也不包含其他代理核心源码。

## License

双协议授权：

1. Apache License, Version 2.0
2. MIT License

用户可任选其一。
