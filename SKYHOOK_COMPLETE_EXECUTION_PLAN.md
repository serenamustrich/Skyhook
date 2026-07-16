# Skyhook（玥球核心）完整开发执行计划

> 项目根目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore`  
> Rust 核心目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore`  
> macOS App 目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Sources/YueqiuElevatorSupercore`  
> 计划版本：2026-07-17  
> 目标平台：Apple Silicon macOS，正式发布基线暂定 macOS 13+  
> 执行主体：由 Codex 直接开发、验证和发布，不是交接说明

## 0. 文档定位

本文档取代旧计划作为后续唯一执行主线。旧文档保留用于追溯，但不再单独决定完成状态。

开发目标不是给现有 App 包一层兼容壳，也不是把 Mihomo 二进制换个名字，而是完成：

1. 独立 Rust-native 代理核心 Skyhook，中文名“玥球核心”。
2. 只使用 Skyhook 的 macOS App“玥球电梯”。
3. 在固定参考版本上达到 Mihomo 的主要协议、代理组、规则、DNS、Provider 和 TUN 能力。
4. 在 macOS TUN 安全、节点测速、智能规则、应用级路由和故障恢复方面超过参考实现的用户体验。
5. 最终提供可签名、公证、安装、升级和卸载的 DMG。

本计划不允许通过以下方式缩短工作：

- 引入 Mihomo 二进制或双核心回退。
- 只解析配置但把协议标记为可用。
- 把未执行的测速任务标记为超时。
- 用单元测试代替真实协议拨号。
- 用“代码写完”代替 TUN、DNS 和网络恢复实机验收。
- 为了兼容旧 App 保留永久性的错误架构。

## 1. 对标范围与版本冻结

### 1.1 Mihomo 参考基线

第一阶段固定对标：

- 稳定版：Mihomo `v1.19.28`。
- 文档快照日期：2026-07-17。
- 对标内容：
  - outbound 协议。
  - transport。
  - proxy groups。
  - proxy providers。
  - rule providers。
  - DNS。
  - TUN。
  - routing rules。
  - health check。
  - 连接、流量、日志和控制面能力。

后续 Mihomo 新版本不自动扩大当前里程碑。每次正式发布前生成一次差异报告，新能力进入下一版本，不允许无限追赶导致当前版本永远无法交付。

### 1.2 第一阶段协议清单

Mihomo 参考清单：

- DIRECT。
- DNS outbound。
- Rematch。
- HTTP。
- SOCKS5。
- Shadowsocks。
- ShadowsocksR。
- Snell。
- VMess。
- VLESS。
- Trojan。
- AnyTLS。
- Mieru。
- Sudoku。
- Hysteria v1。
- Hysteria2。
- TUIC。
- WireGuard。
- Tailscale。
- SSH。
- MASQUE。
- TrustTunnel。
- OpenVPN。

Skyhook 已有或计划额外支持：

- ShadowTLS。
- Naive。
- Juicity。
- 原生智能规则。
- 域名/IP/App 指定节点。
- 按国家自动择优。

### 1.3 “同等能力”的验收定义

某协议只有同时满足以下条件才算完成：

1. Clash/Mihomo 风格 YAML 能解析。
2. 公开 URI 格式能解析；协议没有标准 URI 时明确标记不适用。
3. 配置字段有完整校验。
4. TCP 能真实拨号并交换双向 payload。
5. 协议支持 UDP 时，UDP 能真实交换数据报。
6. 支持的 transport 有真实握手和数据测试。
7. 错误能区分 DNS、连接、TLS、认证、协议、超时和服务端拒绝。
8. 节点能被独立 probe 引擎测试。
9. capability、Doctor、UI 和文档状态一致。
10. 至少有本地可重复 mock server E2E；关键协议再补公开服务端互操作测试。

`parse-only`、`partial` 和 `unsupported` 都不等于完成。

## 2. 当前真实基线

### 2.1 已确认状态

- 2026-07-17 当前 `cargo check` 通过。
- 完整 Rust 回归为 `263 passed, 0 failed, 1 ignored`；ignored 项仅为需要外部订阅 URL 环境变量的兼容测试。
- VMess TCP、WebSocket、gRPC、HTTP/2、UDP 曾完成真实拨号验证。
- Trojan TCP、UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade 曾完成真实拨号验证。
- Shadowsocks 旧 AEAD、2022、SIP022、SIP023、simple-obfs 和 v2ray-plugin WebSocket 已有真实拨号路径。
- Snell v1-v5 TCP、HTTP/TLS obfs、v3-v5 UDP-over-TCP 和 v4/v5 connection reuse 已有真实拨号路径，定向测试 18 个通过。
- SSR origin、旧 verify/auth 系列、auth_aes128_md5/sha1、auth_chain_a-f 与 tls1.2_ticket_auth 已写入实现，定向测试 41 个通过。
- Swift 完整回归为 `89 passed, 0 failed`。
- M0 Rust 与 Swift release build 均通过；Rust 完整 LTO release 构建耗时 15m39s，M4 后按统一门策略未重复执行完整 LTO。

### 2.2 当前阶段状态

- M0 已通过 Rust 263/0/1、Swift 89/0、双 release build 和 Git 基线验收。
- M4 的 Shadowsocks、SSR 与 Snell 计划内实现、capability 和真实拨号测试已经对齐。
- Snell v4/v5 connection reuse 已覆盖 v4/v5、HTTP/TLS obfs、零帧半关闭、连接池和陈旧连接自动重拨。
- 下一阶段进入 M1，拆分公共 transport、UDP、连接池和错误层。

### 2.3 明确的结构问题

- `Supercore/src/outbound/mod.rs` 约 13,759 行，协议、transport、加密、UDP 和测试辅助逻辑高度集中。
- `Supercore/src/core/mod.rs` 约 2,098 行。
- `AppState.swift` 约 2,855 行。
- `SettingsWindow.swift` 约 1,614 行。
- 项目目录已经建立本地 Git 基线，但尚未与现有 Rust-only GitHub 仓库完成产品级远端布局迁移。
- `Cargo.toml` 仍声明 `license = "Proprietary"`，与公开仓库目标不一致。
- 当前 API 同时存在 `/proxies` 等兼容入口和 `/supercore/*`，最终需要收敛成 Skyhook 自己的版本化 API。

## 3. 最终完成定义

只有以下条件全部满足，项目才能称为最终完成：

- M0-M16 全部达到 `VERIFIED`。
- 固定基线协议全部达到计划要求，没有未声明的 parse-only。
- 所有标记 `full` 的协议都有真实 TCP/UDP/transport 证据。
- TUN 正常退出、强杀、core 崩溃、网络切换和休眠唤醒后不会让 macOS 断网。
- 未启动代理时可以测试节点，测速不启用 TUN、不改系统代理、不更新订阅。
- 启动代理只使用本地缓存和已选节点，不同步订阅、不做全局测速。
- 上次节点失败时按同组、同国家、全局的顺序降级。
- 多订阅切换为本地即时切换。
- 订阅套餐流量、到期日期、更新时间和累计流量正确显示并持久化。
- 智能规则、域名/IP/App 指定节点真实生效。
- 实时速率、累计流量和连接表准确。
- 1000 节点场景下 App 可流畅使用。
- 严格 clippy、Swift 测试、release build、稳定性测试全部通过。
- GitHub 仓库不包含用户订阅、凭证、私钥、日志和本地 profile。
- DMG 完成签名、公证、安装、覆盖安装、退出、卸载验证。

## 4. 总体执行顺序

| 里程碑 | 内容 | 当前状态 | 依赖 |
|---|---|---|---|
| M0 | 冻结基线、恢复 Git、收口当前半成品 | VERIFIED | 无 |
| M1 | 公共 transport、UDP、错误和 API 架构 | NOT_STARTED | M0 |
| M2 | VMess 再验收 | PREVIOUSLY_VERIFIED | M0、M1 |
| M3 | Trojan 再验收 | PREVIOUSLY_VERIFIED | M0、M1 |
| M4 | Shadowsocks、SSR、Snell 完成 | VERIFIED | M0，随后接 M1 |
| M5 | VLESS、Reality、Vision | PARTIAL | M1 |
| M6 | QUIC、Hysteria、Hysteria2、TUIC | PARTIAL | M1 |
| M7 | WireGuard、AnyTLS、ShadowTLS、Naive、HTTP、SOCKS5、SSH | PARTIAL | M1 |
| M8 | Mieru、Sudoku、Tailscale、MASQUE、TrustTunnel、OpenVPN、Juicity | NOT_STARTED/PARSE_ONLY | M1 |
| M9 | 独立测速和自动择优 | PARTIAL | M2-M8 capability |
| M10 | TUN、DNS、Fake-IP 和网络恢复 | PARTIAL/P0 | M1、M9 |
| M11 | 多订阅、Provider、Rule Provider | PARTIAL | M1 |
| M12 | 智能规则和 App 级路由 | PARTIAL | M10、M11 |
| M13 | 流量、连接、日志、Doctor | PARTIAL | M9-M12 |
| M14 | macOS App UI、交互和状态架构 | PARTIAL | M9-M13 |
| M15 | 性能、质量、安全、许可证 | NOT_STARTED | M1-M14 |
| M16 | 全量验收、签名、公证、DMG、Release | NOT_STARTED | M0-M15 |

执行原则：

- 先完成代码，再做对应的定向测试。
- 不在每个小改动后重复全量测试。
- M0、M4、M8、M10、M16 是统一全量回归门。
- 任一门失败，先修复当前门，不带着未知回归继续扩大功能。

## 5. M0：冻结基线并收口当前半成品

### 5.1 恢复可审计源码状态

1. 确认远端 GitHub 仓库和默认分支。
2. 在当前目录恢复 `.git`，或从远端干净克隆后迁移当前源码。
3. 保留当前 SSR/Snell 已通过定向测试的改动，不覆盖。
4. 建立 `.gitignore`：
   - `.build/`
   - `Supercore/target/`
   - `dist/`
   - 用户 profile。
   - runtime YAML。
   - 日志。
   - Keychain 导出。
   - 真实订阅 fixture。
5. 增加提交前敏感信息扫描。
6. 建立基线 tag 或保护分支。

### 5.2 收口 SSR 当前改动

涉及：

- `Supercore/src/outbound/mod.rs`
- `Supercore/src/core/mod.rs`
- `Supercore/tests/ssr_real_dial.rs`
- `Supercore/tests/remaining_protocols.rs`

任务：

1. 保持 auth_chain_a-f TCP/UDP 编码、解码和状态链测试通过。
2. 保持 RC4 内层流、外层 SSR cipher、HMAC 链和随机 padding 的独立 mock server 验证。
3. 保持多用户 `uid:key` 测试。
4. 使用确实不存在的 `auth_chain_g` 验证明确拒绝路径。
5. capability、Doctor、UI 和文档正确显示 TCP/UDP 能力。
6. 在 M4 门禁执行完整 Rust/Swift 回归。

### 5.3 冻结当前构建结果

执行：

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo test
cargo build --release

cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test
swift build -c release
```

记录：

- passed/failed/ignored 数量。
- 所有 warning。
- 所有 `TODO/FIXME/todo!/unimplemented!`。
- 所有 parse-only/unsupported。
- 当前协议矩阵快照。
- 当前 API 路由快照。

### 5.4 M0 退出条件

- 当前 SSR/Snell 实现与 capability、测试不再冲突。
- Rust 和 Swift 全量测试通过。
- release build 通过。
- 源码处于可审计 Git 工作区。
- 文档只描述当前真实能力。

## 6. M1：重构核心基础设施

M1 不改变协议 wire format，只重构公共边界。M4 当前半成品必须先收口，再开始大规模移动代码。

### 6.1 目标目录

```text
Supercore/src/outbound/
  mod.rs
  registry.rs
  capability.rs
  context.rs
  error.rs
  target.rs
  direct.rs
  dns.rs
  rematch.rs
  http.rs
  socks5.rs
  ssh.rs
  shadowsocks/
  ssr/
  snell/
  vmess/
  vless/
  trojan/
  anytls/
  hysteria/
  hysteria2/
  tuic/
  wireguard/
  mieru/
  sudoku/
  tailscale/
  masque/
  trusttunnel/
  openvpn/
  transports/
    tcp.rs
    tls.rs
    websocket.rs
    http2.rs
    grpc.rs
    http_upgrade.rs
    quic.rs
  udp/
    association.rs
    fragmentation.rs
    replay.rs
    session_pool.rs
```

### 6.2 公共接口

- `Outbound`
  - `connect_tcp`
  - `exchange_udp`
  - `health_probe`
  - `capability`
  - `shutdown`
- `Transport`
  - 原始双向字节流。
  - 半关闭。
  - 超时。
  - 取消。
  - backpressure。
- `DialContext`
  - 目标。
  - 来源。
  - App 标识。
  - 规则。
  - 超时。
  - trace id。
  - cancellation token。
- `OutboundError`
  - DNS。
  - TCP。
  - TLS。
  - Authentication。
  - Protocol。
  - HTTP status。
  - Timeout。
  - Cancelled。
  - Unsupported。
- `Capability`
  - parser。
  - TCP。
  - UDP。
  - transport。
  - 限制。
  - 测试证据。

### 6.3 公共 transport

完成并独立测试：

- TLS：SNI、ALPN、证书校验、skip verify、session resumption。
- WebSocket：path、Host、headers、early data、ping/pong、close frame。
- HTTP/2：flow control、半关闭、RST、GOAWAY。
- gRPC：5 字节 framing、分片、连续消息、trailers、取消。
- HTTPUpgrade：请求构造、101 校验、双向数据。
- QUIC：连接池、stream、datagram、keepalive、MTU、关闭。

### 6.4 UDP 公共层

- 单目标和多目标会话。
- session 生命周期。
- NAT 映射。
- fragmentation/reassembly。
- replay window。
- endpoint-independent NAT。
- 最大并发和空闲回收。
- 取消与超时。

### 6.5 Skyhook API

废弃永久兼容入口，建立版本化接口：

```text
/v1/status
/v1/outbounds
/v1/groups
/v1/probes
/v1/subscriptions
/v1/providers
/v1/rules
/v1/smart-rules
/v1/traffic
/v1/connections
/v1/logs
/v1/tun
/v1/doctor
```

要求：

- 只监听 loopback 或 Unix domain socket。
- 每次启动随机 token。
- 写操作必须认证。
- 长任务返回 task id。
- 进度使用 SSE 或 WebSocket。
- API schema 生成并版本化。
- Swift 客户端不依赖 Mihomo API 语义。

### 6.6 M1 退出条件

- `outbound/mod.rs` 只保留 registry 和公共导出。
- 协议实现不复制 transport 状态机。
- 现有协议测试全部通过。
- API 有版本、鉴权和错误 schema。

## 7. M2-M4：已开发协议的最终收口

### 7.1 M2 VMess

- alterId=0 AEAD：
  - TCP。
  - UDP。
  - WS。
  - gRPC。
  - H2。
  - TLS。
- 增加 legacy alterId 的明确策略：
  - 实现完整兼容；或
  - 明确标记不支持，不得误报 timeout。
- 补充：
  - 错误 UUID。
  - 错误响应头。
  - 服务端提前关闭。
  - UDP 多目标。
  - transport 组合验证。

退出条件：VMess 能力矩阵细化到 cipher、transport、UDP 和 alterId。

### 7.2 M3 Trojan

- TCP、UDP、WS、gRPC、H2、HTTPUpgrade 全部迁入公共 transport。
- 覆盖：
  - 自定义 headers。
  - ALPN。
  - TLS 证书错误。
  - 密码错误。
  - gRPC trailer。
  - UDP over transport。
  - 半关闭和超时。

退出条件：所有公开支持组合均有真实 payload 测试。

### 7.3 M4 Shadowsocks

- 旧 AEAD TCP/UDP。
- Shadowsocks 2022 TCP/UDP。
- SIP022。
- SIP023 EIH 多用户。
- replay protection。
- simple-obfs HTTP/TLS。
- v2ray-plugin WebSocket。
- UDP-over-TCP。
- plugin 与 UDP 的合法组合校验。
- method、salt、session 和 packet id 错误路径。

### 7.4 M4 ShadowsocksR

按顺序完成：

1. origin。
2. auth_sha1_v4。
3. auth_aes128_md5。
4. auth_aes128_sha1。
5. tls1.2_ticket_auth。
6. auth_chain_a。
7. auth_chain_b。
8. 仍在目标订阅中出现的旧 verify 系列。

逐项覆盖：

- TCP。
- UDP。
- protocol_param。
- obfs_param。
- 多用户。
- HTTP simple/post。
- TLS ticket。
- cipher 组合。
- 错误认证。

不再出现“整个 SSR full”，只按 cipher/protocol/obfs 组合标记。

### 7.5 M4 Snell

- v1、v2、v3 保持真实实现。
- 评估并实现 v4/v5 当前公开 wire format。
- 支持对应 method、obfs、UDP 和 connection reuse。
- v1/v2 不支持 UDP 时保持明确拒绝。
- 不使用 Shadowsocks framing 近似替代。

### 7.6 M4 退出条件

- SS、SSR、Snell capability 与真实实现一致。
- 不存在用普通 timeout 表示协议未实现的节点。
- M0-M4 全量 Rust/Swift 回归通过。
- 协议矩阵更新。

## 8. M5：VLESS、Reality 和 Vision

### 8.1 VLESS 基础

- TCP。
- UDP。
- WebSocket。
- gRPC。
- HTTP/2。
- HTTPUpgrade。
- TLS。
- multiplex。
- 合法 flow/transport 组合校验。

### 8.2 Reality

- X25519。
- public key。
- short id。
- server name。
- fingerprint。
- spiderX。
- 握手认证。
- 服务端拒绝。
- 时间偏差。
- TLS ClientHello 边界。

### 8.3 Vision

- Vision flow。
- padding。
- TLS record 识别。
- direct copy/splice 边界。
- UDP 限制。
- Reality + Vision。
- TLS + Vision。

### 8.4 M5 退出条件

- Reality/Vision 不再只是保存字段。
- 每种声明支持的组合有真实服务端模拟。
- 非法组合在启动前失败。

## 9. M6：QUIC 协议族

### 9.1 QUIC 公共能力

- 统一 `quinn` 配置。
- TLS 1.3。
- stream/datagram。
- 0-RTT 策略。
- connection pool。
- keepalive。
- congestion control。
- MTU。
- fragmentation。
- 重传、乱序、重复包。
- 连接迁移。
- 取消和关闭。

### 9.2 Hysteria v1

- auth。
- bandwidth。
- obfs。
- TCP。
- UDP。
- QUIC transport。
- 本地协议服务端 E2E。

### 9.3 Hysteria2

- auth。
- TCP tunnel。
- UDP datagram。
- Salamander。
- Gecko。
- bandwidth。
- session pool。
- packet fragmentation。

### 9.4 TUIC

- v5 authentication。
- TCP connect。
- native UDP。
- QUIC stream UDP。
- fragmentation。
- congestion controller。
- max streams。
- session pool。

### 9.5 M6 退出条件

- 三个协议都有独立本地 QUIC 服务端。
- packet loss、乱序和网络切换下无 task/session 泄漏。
- probe 能给出准确失败阶段。

## 10. M7：其余已有部分实现协议

### 10.1 WireGuard

- private/public/preshared key。
- multi-peer。
- allowed IPs。
- reserved bytes。
- IPv4/IPv6。
- MTU。
- keepalive。
- rekey。
- counter rollover。
- TCP 流量和 UDP 数据报。
- DNS destination。
- per-peer reserved。

### 10.2 AnyTLS

- 真实认证。
- multiplex。
- padding。
- session 生命周期。
- TCP。
- UDP 能力按规范实现或明确拒绝。
- 证书和服务端拒绝。

### 10.3 ShadowTLS

- v3 完整握手。
- SNI。
- 伪装站点。
- 与底层代理组合。
- standalone 边界。
- UDP 能力说明。

### 10.4 Naive

- HTTP/2 CONNECT。
- authentication。
- padding。
- TLS/ALPN。
- HTTP/1.1 回退。
- fingerprint 边界。

### 10.5 HTTP、SOCKS5、SSH

HTTP：

- CONNECT。
- Basic/Bearer authentication。
- TLS。
- 错误状态。
- IPv4/IPv6/domain。

SOCKS5：

- TCP。
- UDP ASSOCIATE。
- 用户名密码。
- IPv4/IPv6/domain。
- BIND 明确支持或拒绝。

SSH：

- host key 校验。
- password/key/agent authentication。
- connection multiplex。
- keepalive。
- 重连。
- TCP forwarding。
- UDP 明确为不适用或扩展能力。

## 11. M8：补齐参考基线剩余协议

按依赖和价值顺序实现：

1. Mieru。
2. Sudoku。
3. MASQUE。
4. TrustTunnel。
5. OpenVPN。
6. Tailscale。
7. Juicity。

每个协议必须完成：

- 配置 schema。
- YAML/URI parser。
- validation。
- 原生 Rust 拨号。
- TCP/UDP。
- transport。
- mock server。
- probe。
- capability。
- 错误分类。
- 文档。

特殊要求：

- MASQUE 使用 HTTP/3 CONNECT-UDP/CONNECT-IP 的规范语义。
- OpenVPN 覆盖 TLS auth、数据通道、重连和路由。
- Tailscale 明确是节点/网络接入能力，不伪装成普通单服务器代理。
- Sudoku 和 TrustTunnel 以固定 Mihomo 参考版本的公开字段和协议行为为准。
- 未完成前保持 parse-only，UI 显示“协议尚未实现”，不能显示普通超时。

M8 退出条件：

- 固定参考基线协议清单无未知缺口。
- 所有 parse-only 项都有明确下一版本声明或已经完成。
- 完成一次协议全量回归门。

## 12. M9：独立测速和自动择优

### 12.1 测速运行时

- 使用独立 lightweight Skyhook runtime。
- 只加载本地缓存节点。
- 强制关闭 TUN。
- 不修改系统代理。
- 不修改系统 DNS。
- 不更新订阅。
- 不启动后台 Provider 更新。
- 测速结束后 core 自动退出，无残留进程。

### 12.2 测速正确性

- 每个请求节点必须产生一个结果。
- 未进入 worker 的节点不能标记 timeout。
- 排队时间不计入节点延迟。
- 延迟从实际拨号开始，到收到符合条件的 HTTP 响应结束。
- 结果分类：
  - success。
  - dns_error。
  - connect_timeout。
  - tls_error。
  - auth_error。
  - protocol_error。
  - http_status_error。
  - empty_response。
  - cancelled。
  - protocol_unsupported。
  - outbound_not_found。
- 用户设置 500ms 时，只有实际执行超过 500ms 的节点才标记超时。

### 12.3 调度器

- 固定 worker pool。
- 按协议成本分配并发。
- TCP/QUIC/复杂插件可使用不同 semaphore。
- 支持取消。
- 支持进度。
- 支持单节点、当前组、当前国家、全部节点、失败节点。
- “测试所有节点”必须包含历史超时节点。
- 后台测速使用低优先级资源池，不能与真实代理连接争抢。

### 12.4 测试 URL

- 默认使用可配置的 204 URL。
- 支持 expected status。
- 支持 HTTP 和 HTTPS。
- DNS、TCP、TLS、TTFB 分阶段记录。
- 允许用户自定义 URL、Host 和 timeout。
- 对同一轮测试固定 URL 和 resolver，保证可比性。

### 12.5 自动择优

启动代理：

1. 使用用户当前选中节点。
2. 没有当前选择时使用上次成功节点。
3. 节点失败时先查近期有效缓存。
4. 再测同代理组。
5. 再测同国家。
6. 最后才允许全局测速。

评分：

- 延迟。
- 成功率。
- 抖动。
- 连续失败。
- 最近成功时间。
- 切换冷却。

### 12.6 对比验收

与成熟客户端使用相同订阅、URL、expected status、timeout 和时间窗口对比：

- 可用率。
- P50。
- P90。
- 超时率。
- 各协议失败率。
- DNS/TLS/HTTP 失败分布。

要求：

- 可用节点集合差异可以定位。
- 延迟差异有阶段数据解释。
- 不以降低验证标准换取“看起来更快”。

## 13. M10：TUN、DNS、Fake-IP 和网络恢复

### 13.1 产品定义

玥球电梯 TUN 是“虚拟网卡模式”，UI 不再使用“虚拟 DNS”或含糊的“安装 TUN”。

界面用语：

- 安装网络服务。
- 启用虚拟网卡模式。
- 停用虚拟网卡模式。
- 修复网络。

DNS over TCP 只表示 DNS 查询通过 TCP 发送，不是虚拟网卡，也不等于 TUN。

### 13.2 macOS 权限模型

- 安装一次签名的 privileged helper/LaunchDaemon。
- 优先采用现代 `SMAppService` 管理方式。
- 日常启动/停止代理不重复要求管理员密码。
- App 和 helper 使用最小权限协议。
- helper 只接受签名匹配的 App 请求。
- runtime 文件权限限制到 root/helper。
- App 退出时通过 lease/heartbeat 自动停用 TUN。

### 13.3 TUN 数据面

- IPv4。
- IPv6。
- TCP。
- UDP。
- ICMP 基础处理。
- DNS hijack。
- auto route。
- route exclude。
- MTU/PMTU。
- session timeout。
- backpressure。
- 防路由环路。
- 网络切换。
- 休眠唤醒。

为达到并超过参考体验，Skyhook 在 macOS 上至少提供：

- 启动前网络快照。
- 原子启停事务。
- 自动回滚。
- core 崩溃 watchdog。
- App 强杀恢复。
- 下次启动残留修复。
- 一键网络修复。
- 真实节点预检后再接管默认路由。
- TUN 热重载不切断现有网络。

### 13.4 TUN stack

分阶段提供：

1. `system`：当前稳定后端。
2. `userspace`：Rust 用户态 TCP/IP 栈。
3. `mixed`：TCP system + UDP userspace。

任何 UI 开关只有在真实后端生效后才显示。暂未实现的 stack 必须在配置校验时拒绝。

### 13.5 启动事务

1. 检查 helper 和 core。
2. 保存系统代理、DNS、默认路由、活跃接口快照。
3. 读取本地 active profile。
4. 验证已选节点。
5. 生成 runtime。
6. 校验 runtime。
7. 启动 core。
8. 验证 control/mixed port。
9. 创建 TUN。
10. 安装路由。
11. 启动 DNS hijack。
12. 验证 DIRECT。
13. 验证当前代理节点。
14. 成功后更新 UI 为运行中。

任一步失败：

- 停止新 core。
- 删除 TUN 路由。
- 恢复 DNS。
- 恢复系统代理。
- 终止 helper task。
- 显示具体失败步骤。

### 13.6 停止和崩溃恢复

- 停止后台测速和自动切换。
- 保存流量 checkpoint。
- 停止接受新连接。
- 等待短时间优雅关闭。
- 移除 DNS hijack。
- 移除 TUN 路由。
- 恢复 DNS。
- 恢复系统代理。
- 终止 core。
- 验证默认网络可用。

异常恢复检查：

- 残留 core。
- 残留 helper task。
- 残留 `utun`。
- 残留 `198.18.0.0/15` 路由。
- 残留系统代理。
- 残留 DNS。
- 失效 runtime。

### 13.7 DNS 引擎

- 系统 DNS。
- UDP DNS。
- DNS over TCP。
- DoT。
- DoH。
- DoH3。
- direct resolver。
- proxy resolver。
- nameserver policy。
- fallback。
- fallback filter。
- IPv4/IPv6。
- CNAME。
- hosts。
- cache。
- UDP 失败后 TCP fallback。
- 防递归。
- 防 DNS 泄漏。

### 13.8 Fake-IP

- IPv4/IPv6 地址池。
- blacklist。
- whitelist。
- rule mode。
- DOMAIN/DOMAIN-SUFFIX/GEOSITE/RULE-SET/MATCH。
- TTL。
- 正向和反向映射。
- 地址池回收。
- 持久化。
- 与 SNI、路由和 DNS cache 联动。
- 地址池循环不能覆盖有效 entry。

### 13.9 macOS 验收矩阵

- Wi-Fi。
- 有线网络。
- Wi-Fi 切换。
- DHCP 变化。
- IPv4-only。
- IPv6-only。
- 双栈。
- 休眠/唤醒。
- VPN 共存。
- 防火墙开启。
- App 正常退出。
- App 强杀。
- core 崩溃。
- helper 重启。
- 无管理员权限。
- DNS 不可达。
- 节点不可达。

任何场景退出后断网都属于 P0。

## 14. M11：多订阅、Provider 和规则资产

### 14.1 订阅下载

- 默认优先 DIRECT。
- 是否允许代理重试由用户设置决定。
- redirect。
- gzip/br/zstd。
- User-Agent。
- 自定义 headers。
- ETag。
- Last-Modified。
- timeout。
- retry。
- exponential backoff。
- size limit。
- TLS/HTTP 错误分类。
- 后台更新不阻塞代理。

### 14.2 本地 profile 数据

每个订阅保存：

- Keychain 中的 URL/认证引用。
- 原始 payload。
- 解析后的节点。
- 代理组。
- group selection。
- selected node。
- provider payload。
- rules。
- rule providers。
- subscription-userinfo。
- upload/download/total。
- 到期日期。
- 更新时间。
- ETag/Last-Modified。
- 上次成功节点。
- 生命周期累计流量。

要求：

- 原子写入。
- schema version。
- migration。
- checksum。
- 损坏回退。
- 权限限制。

### 14.3 订阅交互逻辑

- App 启动后后台自动更新，但立即显示本地缓存。
- 切换订阅只切本地 profile。
- 切换不下载、不测速、不重启无关服务。
- 添加新订阅时：
  - 已有 active profile：只保存，不自动切换。
  - 没有 active profile：自动启用新订阅。
- “更新订阅”默认更新全部订阅。
- 更新失败保留旧缓存。
- 页面显示逐订阅进度和错误。

### 14.4 Proxy Provider

- http/file/inline。
- 缓存。
- interval。
- proxy 下载路径。
- header。
- size limit。
- health check。
- lazy。
- expected status。
- override。
- filter。
- exclude-filter。
- exclude-type。
- include-all。
- 特殊字符名称。
- 嵌套组。

### 14.5 Rule Provider

- http/file/inline。
- domain/ipcidr/classical。
- yaml/text/mrs。
- 缓存和回退。
- interval。
- size limit。
- header。
- rule set 编译索引。

## 15. M12：代理组、规则和原生智能学习

### 15.1 代理组

支持：

- select。
- url-test。
- fallback。
- load-balance。
- relay。
- DIRECT/DNS/Rematch。
- proxies/use。
- default-selected。
- empty-fallback。
- lazy。
- timeout。
- max-failed-times。
- disable-udp。
- include-all。
- include-all-proxies。
- include-all-providers。
- filter/exclude-filter/exclude-type。
- expected-status。
- hidden/icon。

交互规则：

- 点击代理组只查看内容。
- 使用代理组必须通过单独操作确认。
- 选择代理组自动择优时，由组策略决定实际节点。
- UI 始终显示“组名 + 当前实际节点 + 延迟”。

### 15.2 路由规则

至少支持：

- DOMAIN。
- DOMAIN-SUFFIX。
- DOMAIN-KEYWORD。
- DOMAIN-WILDCARD。
- DOMAIN-REGEX。
- IP-CIDR。
- IP-CIDR6。
- IP-SUFFIX。
- SRC-IP-CIDR。
- DST-PORT。
- SRC-PORT。
- IN-PORT。
- NETWORK。
- PROCESS-NAME。
- PROCESS-PATH。
- APP-BUNDLE。
- RULE-SET。
- GEOSITE。
- GEOIP。
- SUB-RULE。
- MATCH/FINAL。

### 15.3 固定优先级

1. 用户手动规则。
2. 用户已启用的智能规则。
3. 域名/IP/App 指定节点或代理组。
4. 订阅规则。
5. 自动学习建议，不直接参与路由。
6. fallback。

### 15.4 智能学习

观察：

- domain。
- resolved IP。
- destination port。
- network。
- process/bundle。
- 命中规则。
- 实际 outbound。
- DNS/TCP/TLS/HTTP 结果。

学习：

- 在隔离 runtime 中做 DIRECT probe。
- DNS 成功不代表目标可直连。
- 记录样本数、成功率、P50、P90、最近成功和失败。
- 达到最小样本后产生建议。
- CDN、动态 IP、QUIC 和短时故障使用保守阈值。
- 规则有 TTL、冷却和滞后，避免抖动。

用户能力：

- 推荐直连。
- 推荐代理。
- 单条启用。
- 批量启用。
- 撤销。
- 删除。
- 清空学习数据。
- 域名走指定节点。
- IP/CIDR 走指定节点。
- App 走指定节点。
- 目标走指定代理组自动择优。

### 15.5 macOS App 归属

优先实现：

- privileged helper 维护 socket 五元组到 PID 的映射。
- PID 映射 bundle id、executable path、process name。
- 映射带时间戳和置信度。
- 无法可靠识别时退化到域名/IP 规则，不错误归属。

若采用 Network Extension：

- 先确认 Developer ID 和所需 entitlement。
- 不把需要受限 entitlement 的能力写成默认可用。

## 16. M13：流量、连接、日志和 Doctor

### 16.1 流量

- 实时上传/下载速率。
- 当前 runtime 总量。
- 当前连接总量。
- 按订阅生命周期累计。
- App 重启不丢失。
- core 重启不重复。
- profile 切换不串数据。
- 单调计数器。
- checkpoint。
- 崩溃恢复去重。

### 16.2 连接表

- domain/IP。
- source App。
- protocol/network。
- 命中规则。
- 代理组。
- 实际节点。
- 上传/下载。
- 开始时间。
- 持续时间。
- RTT。
- 关闭原因。

### 16.3 日志

最新在上，Tab：

- 全部。
- 代理。
- 直连。
- 规则。
- DNS。
- TUN。
- 错误。
- 系统。

要求：

- 内存 ring buffer。
- 文件轮转。
- 级别过滤。
- 搜索。
- trace id。
- token、密码、UUID、私钥和 Authorization 脱敏。
- 诊断包二次脱敏。

### 16.4 Doctor

检查：

- core。
- helper。
- 配置。
- 端口。
- API token。
- 系统代理。
- TUN。
- 路由。
- DNS。
- Fake-IP。
- active profile。
- selected node。
- provider cache。
- protocol capability。
- 残留进程。

一键修复网络前必须先保存恢复快照。

## 17. M14：macOS App 最终交互

### 17.1 状态架构

拆分 `AppState.swift`：

- CoreRuntimeStore。
- SubscriptionStore。
- NodeStore。
- ProbeStore。
- TunStore。
- TrafficStore。
- SmartRuleStore。
- DiagnosticsStore。

拆分 `SettingsWindow.swift` 为独立页面和组件，避免整个窗口因一项状态变化全部刷新。

### 17.2 全局

- 启动/停止只有一个状态按钮。
- 顶部、菜单栏、窗口和 About 统一为“玥球电梯”。
- 双击菜单栏图标打开主界面。
- 所有长任务显示阶段、进度、取消和错误。
- Core 版本、状态和完整值可显示。

### 17.3 节点页

- 当前订阅。
- 当前代理组。
- 当前实际节点。
- 当前延迟。
- 代理组整行可点击。
- 国家网格可完整滚动。
- 不重复提供国家下拉框。
- 节点搜索、协议、国家、延迟筛选。
- 节点虚拟化列表。
- 测速当前、组、国家、全部、失败节点。
- 可取消。
- 只显示可用节点。

延迟颜色：

- `<50ms` 绿色。
- `50-150ms` 蓝色。
- `150-499ms` 红色。
- `>=500ms` 超时。

### 17.4 订阅页

- 多订阅列表。
- active 状态。
- 节点数。
- 不支持数。
- 套餐已用/剩余/总量。
- 到期日期。
- 更新时间。
- 添加、删除、切换、更新全部。
- 更新过程不闪页面。
- 后台任务进度可见。

### 17.5 智能规则页

- 顶部统计。
- “当前走代理但直连可用”比例。
- 推荐直连。
- 推荐代理。
- 域名/IP/App 分类。
- 单条/批量启用。
- 搜索、筛选、撤销、删除。

### 17.6 设置页

- 系统代理。
- 虚拟网卡模式。
- DNS 模式解释。
- Fake-IP 风险提示。
- 测速 URL、超时、并发。
- 后台测速周期。
- 后台订阅更新周期。
- 自动择优策略。
- 一键恢复网络。
- Doctor。

### 17.7 大数据 UI 性能

- 1000+ 节点使用 Lazy 容器和稳定 id。
- 搜索、排序、国家识别在后台执行。
- 日志和连接增量更新。
- 不在 SwiftUI body 中做昂贵计算。
- 订阅切换只替换内存快照。
- 避免全局 `objectWillChange` 风暴。

## 18. M15：性能、质量、安全和开源治理

### 18.1 Benchmark

新增：

- routing 1K/10K/100K。
- subscription parse 1MB/10MB。
- node cache 100/1K/10K。
- probe 10/50/100/256 并发。
- fake-ip 10K/100K。
- TCP relay throughput。
- UDP packets/s。
- QUIC session。
- API event stream。

### 18.2 性能目标

- App/core 空闲 CPU 接近 0。
- 1000 节点本地切换无网络请求。
- 启动代理不更新订阅、不测速。
- 后台测速不明显增加前台代理 P95 延迟。
- 1000 并发连接稳定。
- 24 小时无持续内存增长。
- 日志和 telemetry 有上限。

### 18.3 代码质量

- `cargo clippy --all-targets --all-features -- -D warnings`。
- Swift build 无 warning。
- Rustfmt/SwiftFormat 只处理目标文件。
- 删除死代码和过时兼容 API。
- 公共模块有边界测试。
- parser、frame、订阅输入增加 fuzz。
- 使用 sanitizer/Miri 覆盖可行模块。

### 18.4 安全

- API loopback/Unix socket。
- 启动随机 token。
- 写操作鉴权。
- Keychain 保存敏感信息。
- helper 请求签名校验。
- 配置/cache 权限限制。
- 日志脱敏。
- 订阅下载防 SSRF 和路径穿越。
- Provider 文件限制目录和大小。
- 依赖漏洞扫描。
- secret scan。
- SBOM。

### 18.5 开源和许可证

- 将 Rust package 名称改为 `skyhook-core`，binary 改为 `skyhook`。
- App 仍为“玥球电梯”。
- 许可证改为 `MIT OR Apache-2.0`。
- 添加 `LICENSE-MIT`、`LICENSE-APACHE`、`NOTICE`。
- 生成第三方依赖许可证清单。
- 审计协议实现来源和 clean-room 记录。
- README 不使用无法证明的“完全原创”或“全面超越”表述。
- 仓库中不包含 Mihomo 源码、二进制和品牌资源。

## 19. M16：最终验收和发布

### 19.1 自动化门禁

Rust：

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Swift：

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test
swift build
swift build -c release
```

检查：

- 无未登记 ignored。
- 无假测试。
- full 协议无 ignored E2E。
- 无 warning。
- 无用户敏感数据。

### 19.2 真实功能验收

- 首次安装。
- 首次授权。
- 第二次启动不重复要求密码。
- 导入多个订阅。
- 关闭代理测速。
- 选择节点。
- 快速启动代理。
- 系统代理上网。
- TUN 上网。
- TCP/UDP/QUIC。
- 切换节点。
- 选择代理组自动择优。
- 国家自动择优。
- 切换订阅。
- 更新所有订阅。
- 后台更新。
- 后台测速。
- 流量累计。
- 智能规则。
- App/域名/IP 指定节点。
- 正常退出。
- 强杀。
- core 崩溃。
- 网络切换。
- 休眠唤醒。

### 19.3 稳定性

- 24 小时运行。
- 1000 并发连接。
- 长连接。
- 高频 DNS。
- UDP/QUIC 长时会话。
- Provider 更新。
- 后台测速。
- core 热重载。
- helper 重启。

### 19.4 发布流程

1. 更新中英文 README，只描述真实功能。
2. 更新协议矩阵和对标证据。
3. 运行 secret scan 和许可证检查。
4. 构建 arm64 Skyhook release。
5. 嵌入玥球电梯 App。
6. codesign。
7. notarization。
8. staple。
9. 使用已经确认的 DMG 背景和 Finder 布局打包。
10. 确认 DMG 不包含订阅和本地缓存。
11. 安装、覆盖安装和卸载测试。
12. 创建 Git tag。
13. 创建 GitHub Release。
14. 上传 DMG、校验和和 SBOM。
15. README 增加 Release 下载链接。

## 20. 状态和报告规则

每个里程碑只允许以下状态：

- `NOT_STARTED`
- `IN_PROGRESS`
- `CODE_COMPLETE`
- `VERIFIED`
- `BLOCKED`

定义：

- `CODE_COMPLETE`：代码写完，但完整验收未完成。
- `VERIFIED`：该里程碑的测试、构建和真实运行证据全部通过。
- 历史测试结果不能直接作为当前提交的 `VERIFIED`。
- 计划文本不能作为完成证据。
- README 和协议矩阵必须晚于或等于代码状态，不能提前宣布。

每次阶段报告固定包含：

1. 完成了什么。
2. 修改了哪些文件。
3. 跑了哪些测试。
4. 通过/失败/ignored 数量。
5. 当前剩余项。
6. 是否达到该阶段退出条件。

## 21. 立即开始时的第一批任务

下一次开始开发时严格执行：

1. 提交 M4 的 Snell connection reuse 变更和 263/89 回归证据。
2. 拆分 outbound 公共 transport、UDP、连接池和错误层。
3. 按 M5、M6、M7、M8 顺序补齐协议。
4. 再进入测速、TUN、订阅、智能规则和 App。
5. 最后统一做性能、安全、DMG 和 Release。
