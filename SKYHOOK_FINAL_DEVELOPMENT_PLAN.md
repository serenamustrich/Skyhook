# Skyhook（玥球核心）最终开发计划

> 项目根目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore`  
> Rust 核心目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore`  
> macOS App 目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Sources/YueqiuElevatorSupercore`  
> 计划版本：2026-07-16  
> 本文档是后续开发的唯一主计划。实现状态必须以代码、测试和真实运行证据为准。

## 当前执行进度（2026-07-17）

- M0：`VERIFIED`
  - 本轮 Rust 全量测试通过：263 passed、0 failed、1 个需要外部订阅环境变量的测试 ignored。
  - Swift 全量测试通过：89 passed、0 failed。
  - M0 Rust 与 Swift release build 均通过；Rust 完整 LTO release 构建耗时 15m39s，M4 后未重复执行完整 LTO。
  - 测速 runtime、Fake-IP filter、系统 DNS resolver、TUN 配置校验和 SSR/Snell 扩展均已进入统一回归。
  - 当前目录已建立独立 Git 工作区，可回滚基线提交为 `a8a55e0`。
- M1：`IN_PROGRESS`
  - TCP/TLS、UDP resolver/session pool、DialContext、结构化 OutboundError 已开始拆分。
  - Swift 已全部迁移到独立 `/v1` API；旧根路径与 `/supercore/*` 入口已删除。
  - 控制 API 仅监听 loopback，写请求使用启动级 Bearer Token，错误响应包含稳定
    code/kind/trace id。
  - `supercore run` 不再在启动时下载订阅，定时测速首次执行等待完整配置间隔。
  - 当前回归：Rust lib 78 passed、Swift full 91 passed。
  - `outbound/mod.rs` 尚未完成模块拆分。
- M2：`VERIFIED`
  - VMess gRPC、H2、UDP 的 3 个 ignored 测试已取消 ignore。
  - VMess TCP、WS、gRPC、H2、UDP 的公开 `build_outbounds` 真实拨号测试全部通过。
- M3：`VERIFIED`
  - Trojan TLS+TCP、UDP、WS、gRPC、H2、HTTPUpgrade 的真实拨号测试全部通过。
  - 订阅 YAML/URI 已能保存并生成 Trojan transport 配置。
  - 自定义 transport headers、显式 ALPN、UDP over WS/gRPC、TLS/HTTP/gRPC trailer/timeout 错误路径已验证。
- M4：`VERIFIED`
  - Shadowsocks 旧 AEAD 与 2022-blake3 三种方法的 TCP/UDP 双向真实拨号已完成。
  - 下载方向独立 response salt、SIP022 请求/响应头、UDP session、packet ID 和重放窗口已完成。
  - SIP023 TCP/UDP 多用户 EIH、simple-obfs HTTP/TLS 与 v2ray-plugin WebSocket 已完成真实拨号。
  - SSR origin、旧 verify/auth 系列、auth_aes128_md5/sha1、auth_chain_a-f、6 种 stream cipher、TCP/UDP、多用户参数、HTTP simple/post 与 tls1.2_ticket_auth 已完成真实拨号。
  - Snell v1-v5 TCP、独立响应 salt、HTTP/TLS obfs 与 v3-v5 UDP-over-TCP 已完成真实拨号。
  - Snell v4/v5 connection reuse 已完成，覆盖 v4/v5、HTTP/TLS obfs、同一物理连接双目标、零帧半关闭和陈旧连接自动重拨。
- 下一步：推进 M1 模块化，拆分公共 transport、UDP、连接池和错误层。

## 1. 最终目标

完成一套不依赖 Mihomo 二进制、由 Rust 原生实现的代理核心 Skyhook，以及使用 Skyhook 的玥球电梯 macOS App。

最终版本必须满足：

1. 用户导入订阅后，可以离线保存、即时切换和后台更新多套订阅。
2. 未启动系统代理或 TUN 时，也可以通过独立测速 runtime 测试节点。
3. 用户选择节点后，启动代理直接使用已选节点，不同步订阅、不做无关测速。
4. 上次节点失效时，优先切换同组或同国家可用节点，再按策略扩大测速范围。
5. 系统代理和 TUN 都能稳定上网，退出、崩溃、强杀后能够恢复网络。
6. 节点协议必须真实拨号，不允许只解析配置后宣称支持。
7. 原生支持智能规则、应用级路由、域名/IP 指定节点和自动直连学习。
8. 实时速率、累计流量、连接、规则、DNS 和 TUN 状态可准确观测。
9. App 在 1000 个以上节点时仍能流畅切换、筛选、滚动和测速。
10. 正式版本具备签名、公证、DMG、升级和故障恢复能力。

## 2. 不可违反的开发规则

1. Skyhook 是唯一核心，不增加 Mihomo 兼容核心、双核心或运行时回退。
2. 可以参考公开协议规范和配置语义，不复制其他项目受版权保护的实现代码。
3. `full` 协议必须同时具备解析、校验、真实拨号、传输、错误分类和 E2E 测试。
4. `parse-only` 和 `unsupported` 节点不能在 UI 中显示为普通网络超时。
5. 测速 runtime 永远不得开启 TUN、修改系统代理、修改系统 DNS 或更新订阅。
6. TUN/DNS 变更必须采用事务模型：保存快照、执行、验证、失败回滚、退出恢复。
7. 启动代理只读取本地缓存；订阅更新和节点测速是独立后台任务。
8. 不把订阅 URL、节点密码、UUID、私钥、Token、Keychain 数据和运行 profile 提交到仓库或打进 DMG。
9. 不使用永真断言、仅统计数组长度或仅验证“不崩溃”的方式冒充协议测试。
10. 每个里程碑完成后更新协议矩阵和 README，但 README 只写真实功能，不记录开发过程。

## 3. 当前开发基线

### 3.1 已有能力

- Swift macOS 菜单栏 App 和独立设置窗口。
- Rust-native Skyhook/Supercore 核心。
- 多订阅导入、保存、切换、更新和本地节点缓存。
- 节点、代理组、国家分组、节点选择和上次节点保存。
- 未启动代理时的轻量测速 runtime。
- 节点测速、组测速、失败分类和失败汇总。
- 系统代理管理、TUN LaunchDaemon 管理和网络诊断入口。
- 流量统计、订阅维度累计数据和智能规则基础数据。
- 自定义域名、IP、App 规则。
- Doctor 和协议能力矩阵。
- Fake-IP filter、系统 DNS resolver 发现、TUN 配置校验等安全修复已经写入当前工作区。

### 3.2 当前明确未完成

1. Shadowsocks 2022、插件、SSR、Snell、Reality/Vision、QUIC 协议仍缺完整 E2E 证据。
2. Hysteria v1、Mieru、Juicity、MASQUE、OpenVPN 仍处于 parse-only 或 unsupported。
3. TUN 生命周期、系统 DNS 恢复、强杀恢复和真实 macOS 网络矩阵尚未完成。
4. 测速结果与成熟客户端的可用率、P50、P90 还没有形成稳定对比基线。
5. `outbound/mod.rs` 过于集中，协议和传输实现需要模块化。
6. 严格 `clippy -D warnings` 尚未收口。
7. 缺少完整 benchmark、长稳测试、安全审计和正式发布验收。

## 4. 总体开发顺序

严格按以下顺序推进：

1. M0：冻结基线并收口当前改动。
2. M1：重构公共拨号与传输基础设施。
3. M2：修完 VMess，清零现有 ignored 协议测试。
4. M3：补齐 Trojan 全传输。
5. M4：补齐 Shadowsocks、SSR 和 Snell。
6. M5：补齐 VLESS、Reality 和 Vision。
7. M6：补齐 Hysteria2、TUIC 和 Hysteria v1。
8. M7：补齐 WireGuard、AnyTLS、ShadowTLS、Naive、HTTP、SSH。
9. M8：实现剩余 parse-only 协议。
10. M9：完成独立测速引擎和自动择优。
11. M10：完成 TUN、DNS、Fake-IP 和网络恢复。
12. M11：完成订阅、Provider 和规则资产。
13. M12：完成原生智能规则与应用级路由。
14. M13：完成流量、连接、日志和诊断。
15. M14：完成 App UI 与交互。
16. M15：完成性能、代码质量和安全。
17. M16：完成全量验收、签名、公证、DMG 和 Release。

协议实现和 TUN 安全可以分支开发，但进入最终验收前必须全部合并到同一运行链路。

## 5. M0：冻结基线并收口当前改动

### 5.1 当前安全修复

完成并验证：

- 测速 runtime 强制：
  - `tun.enabled=false`
  - `tun.setup=false`
  - `dns.enabled=false`
  - 不调用 LaunchDaemon
  - 不修改系统代理
- Fake-IP blacklist、whitelist、rule filter 不再返回 `0.0.0.0`。
- 系统 DNS 优先从 macOS `scutil --dns` 获取，其次读取 `/etc/resolv.conf`。
- 排除核心自己的 DNS listen 地址，避免递归查询。
- TUN 后端不支持的配置必须明确报错，不能只写日志后假装生效。

### 5.2 基线验收

- 全量执行 Rust 和 Swift 测试。
- 执行 Rust/Swift release build。
- 记录所有 ignored、warning、TODO 和 unsupported 分支。
- 生成一次协议矩阵快照和 API 路由快照。
- 不在本阶段扩大功能范围。

### 5.3 完成标准

- 当前安全改动没有回归。
- 测速前后系统代理、DNS、路由表无变化。
- 除明确登记的协议测试外没有未知 ignored test。
- release 构建通过。

## 6. M1：公共拨号和传输基础设施

当前 `Supercore/src/outbound/mod.rs` 需要拆分，避免每个协议重复实现 TLS、WS、H2、gRPC 和 UDP 会话。

### 6.1 目录结构

建议拆分为：

```text
Supercore/src/outbound/
  mod.rs
  registry.rs
  capability.rs
  error.rs
  target.rs
  direct.rs
  socks5.rs
  http.rs
  ssh.rs
  shadowsocks.rs
  ssr.rs
  trojan.rs
  vmess.rs
  vless.rs
  hysteria.rs
  hysteria2.rs
  tuic.rs
  snell.rs
  wireguard.rs
  anytls.rs
  shadowtls.rs
  naive.rs
  mieru.rs
  juicity.rs
  masque.rs
  openvpn.rs
  transports/
    mod.rs
    tcp.rs
    tls.rs
    websocket.rs
    http2.rs
    grpc.rs
    http_upgrade.rs
    quic.rs
  udp/
    mod.rs
    association.rs
    fragmentation.rs
    session_pool.rs
```

### 6.2 公共抽象

建立统一能力：

- `Outbound`：TCP connect、UDP exchange、能力描述、健康检查。
- `Transport`：原始双向字节流，统一 TCP/TLS/WS/H2/gRPC/HTTPUpgrade。
- `UdpSession`：单目标、多目标、连接型 UDP、无连接 UDP。
- `SessionPool`：按协议、节点和目标复用，具备空闲回收和容量限制。
- `DialContext`：目标、来源、App、规则、超时、取消令牌、trace id。
- `OutboundError`：DNS、TCP、TLS、认证、协议、HTTP、超时、取消、服务端拒绝。
- `Capability`：parser、TCP、UDP、transport、限制和测试证据。

### 6.3 传输层要求

- TLS：SNI、ALPN、证书校验、skip verify、fingerprint 边界。
- WebSocket：path、Host、headers、early data、关闭帧。
- HTTP/2：flow-control、半关闭、RST、GOAWAY、窗口更新。
- gRPC：5 字节 framing、分片、连续 frame、trailers、取消。
- HTTPUpgrade：请求、101 校验、双向数据流。
- QUIC：连接池、0-RTT 策略、datagram、stream、迁移和关闭。

### 6.4 完成标准

- 协议代码不再自行复制传输层状态机。
- 公共 transport 有独立 mock server 测试。
- 取消、超时、半关闭和服务端异常有明确错误。
- 重构前已有测试全部通过。

## 7. M2：VMess 完整实现

涉及：

- `Supercore/src/outbound/vmess.rs`
- `Supercore/src/outbound/transports/`
- `Supercore/tests/trojan_vmess_real_dial.rs`

### 7.1 立即修复

取消并修复：

- `vmess_grpc_transport_real_dial`
- `vmess_h2_transport_real_dial`
- `vmess_udp_real_dial`

### 7.2 修复重点

- mock server 必须流式读取 request body，不能等待客户端 EOF 后才返回。
- H2 正确释放 flow-control capacity。
- gRPC 正确解析跨 DATA frame 的 5 字节头和 payload。
- UDP 明确采用 per-destination session 或 multi-destination session，不允许测试与实现语义不一致。
- VMess UDP setup、响应头、数据块和目标地址必须符合同一会话模型。
- 所有 transport 共享统一 timeout 和 cancellation。

### 7.3 完整覆盖

- TCP。
- WebSocket。
- gRPC。
- HTTP/2。
- UDP。
- TLS 组合。
- alterId=0。
- 非法 UUID、认证失败、服务端提前关闭、错误响应头。

### 7.4 完成标准

- 3 个 ignored test 全部取消 ignore 并通过。
- VMess 的 requested node probe 能真实完成目标 HTTP 请求。
- VMess 文档状态只有在全部能力通过后才升级。

## 8. M3：Trojan 全传输

### 8.1 配置字段

补齐并贯通：

- `network`
- `ws_path`
- `ws_host`
- `ws_headers`
- `grpc_service_name`
- `h2_path`
- `h2_host`
- HTTPUpgrade path/host
- ALPN

### 8.2 拨号能力

- TLS + TCP。
- Trojan UDP。
- Trojan over WebSocket。
- Trojan over gRPC。
- Trojan over HTTP/2。
- Trojan over HTTPUpgrade。

### 8.3 测试

- 每种 transport 使用本地 mock server。
- TCP 与 UDP 都验证真实 payload。
- 覆盖密码错误、TLS 错误、HTTP 状态错误、gRPC trailer 和超时。

### 8.4 完成标准

- 配置解析、URI、runtime、probe 和 E2E 全部通过。
- 不支持的组合在启动前明确拒绝。

## 9. M4：Shadowsocks、SSR 和 Snell

### 9.1 Shadowsocks

- 补齐 AEAD TCP/UDP。
- 补齐 2022-blake3 TCP/UDP 的真实 mock server。
- 完成 replay protection、salt/key derivation 和错误认证。
- simple-obfs HTTP/TLS E2E。
- v2ray-plugin WebSocket E2E。
- plugin 与 UDP 的支持边界必须明确。

### 9.2 ShadowsocksR

- 逐项验证 cipher，不允许只验证可构建。
- 逐项实现 protocol 和 `protocol_param`。
- 逐项实现 obfs 和 `obfs_param`。
- 补齐 UDP，或在 capability 中精确标记缺失组合。
- 增加不同 protocol/obfs 组合的真实帧测试。

### 9.3 Snell

- 分离 v1、v2、v3 状态机。
- 正确实现 method、obfs、认证、UDP。
- 禁止使用 Shadowsocks framing 近似替代。

### 9.4 完成标准

- 协议矩阵细化到版本、cipher、plugin 和 UDP 维度。
- 所有标记 full 的组合都有真实拨号测试。

## 10. M5：VLESS、Reality 和 Vision

### 10.1 VLESS 基础

- TCP。
- UDP。
- WebSocket。
- gRPC。
- HTTP/2。
- HTTPUpgrade。
- TLS。

### 10.2 Reality

- X25519。
- public key。
- short ID。
- server name。
- fingerprint。
- spiderX。
- 握手校验和服务端拒绝路径。

### 10.3 Vision

- flow 选择。
- Vision padding。
- TLS record 处理。
- TCP splice/relay 边界。
- 与 Reality/TLS/不同 transport 的合法组合校验。

### 10.4 完成标准

- Reality 和 Vision 不再只是字段兼容。
- 每一种公开支持的组合有服务端模拟和真实 payload 验证。

## 11. M6：Hysteria2、TUIC 和 Hysteria v1

### 11.1 QUIC 公共能力

- 统一 QUIC client config。
- 连接池。
- stream 和 datagram。
- fragmentation/reassembly。
- congestion control。
- keepalive。
- MTU 和 datagram size。
- 丢包、乱序、重复包测试。

### 11.2 Hysteria2

- 认证。
- TCP tunnel。
- UDP datagram。
- Salamander。
- Gecko。
- 带宽配置。
- session pool。

### 11.3 TUIC

- v5 authentication。
- TCP connect。
- native UDP。
- QUIC stream UDP。
- fragmentation。
- congestion control。
- session pool。

### 11.4 Hysteria v1

- 从 parse-only 升级为原生 QUIC 拨号。
- auth、bandwidth、obfs、TCP、UDP。
- 不复用 Hysteria2 wire format 冒充 v1。

### 11.5 完成标准

- 三个协议都有本地 QUIC mock server E2E。
- 网络抖动场景下不会泄漏 task 或 session。

## 12. M7：其余已部分实现协议

### 12.1 WireGuard

- private/public/preshared key。
- allowed IPs。
- reserved bytes。
- IPv4/IPv6。
- MTU。
- keepalive。
- rekey。
- counter rollover。
- TCP stream 和 UDP datagram。
- DNS destination。

### 12.2 AnyTLS

- 真实认证。
- multiplex。
- padding。
- TCP。
- UDP（协议规范允许时）。
- TLS 证书错误和服务端拒绝。

### 12.3 ShadowTLS

- v3 完整握手。
- SNI、证书和伪装站点。
- 与底层代理组合。
- standalone 行为和 UDP 边界。

### 12.4 Naive

- HTTP/2 CONNECT。
- authentication。
- padding。
- TLS/ALPN。
- HTTP/1.1 仅作为兼容回退，不代表完整实现。

### 12.5 HTTP、SOCKS5、SSH

- HTTP CONNECT 认证、TLS 和错误状态。
- SOCKS5 TCP/UDP、认证、IPv4/IPv6/domain。
- SSH host key、认证、连接复用、断线恢复和 TCP 转发。

## 13. M8：剩余 parse-only 协议

按顺序实现：

1. Mieru。
2. Juicity。
3. MASQUE。
4. OpenVPN。

每个协议必须完成：

- YAML/URI parser。
- config validation。
- 原生 Rust 拨号。
- TCP/UDP 能力。
- 本地 mock server 或可重复的测试服务端。
- probe。
- capability。
- 错误分类。
- 文档。

在完成前：

- 保持 parse-only。
- probe 返回 `protocol_unsupported`。
- UI 不得显示为普通超时。

## 14. M9：独立测速和自动择优

### 14.1 测速链路

- 使用独立 lightweight runtime。
- 只加载本地缓存节点。
- 不更新订阅。
- 不启用 TUN、系统代理或核心 DNS。
- 每个 requested node 必须有且只有一个结果。
- 未真正开始测试的节点不得标记 timeout。
- 延迟计算从开始拨号到收到有效 HTTP 响应。

### 14.2 调度

- 固定 worker/semaphore。
- 默认并发根据 CPU、节点数和协议成本计算。
- 支持取消。
- 每个任务有排队、拨号、TLS、HTTP 独立时间。
- 500ms 为可配置的硬上限；达到上限立即结束该节点。
- 后台测速使用低优先级和独立资源配额。

### 14.3 测速模式

- 当前节点。
- 当前代理组。
- 当前国家。
- 所有节点。
- 包含历史超时节点。
- 仅重测失败节点。
- 后台定时测速。

### 14.4 自动择优

- 启动优先使用用户已选或上次节点。
- 不可用时先查最近有效缓存。
- 再测同代理组。
- 再测同国家。
- 最后才允许全局测速。
- 使用延迟、成功率、抖动和最近失败综合评分，避免频繁切换。

### 14.5 对比验收

使用同一订阅、同一 URL、同一超时和同一时间窗口，与成熟客户端比较：

- 可用率。
- P50。
- P90。
- 超时率。
- 协议不支持率。
- DNS/TLS/HTTP 失败分布。

差异必须能定位到具体协议或失败阶段。

## 15. M10：TUN、DNS、Fake-IP 和网络恢复

### 15.1 TUN 定义

玥球电梯中的 TUN 是虚拟网卡模式：

- 从 macOS 虚拟网络接口接收 IP 数据包。
- 解析 TCP、UDP、ICMP 和 DNS 流量。
- 根据规则选择 DIRECT 或具体代理节点。
- 将返回流量重新注入虚拟网卡。

UI 不再使用容易误解的“安装 TUN”表述，改为：

- 安装网络服务。
- 启用虚拟网卡模式。
- 停用虚拟网卡模式。
- 修复网络。

### 15.2 TUN 能力

- IPv4 和 IPv6。
- TCP。
- UDP。
- ICMP 基础处理。
- DNS hijack。
- 自动路由。
- route exclude/bypass。
- MTU/PMTU。
- 网络切换。
- 休眠唤醒。
- session timeout。
- backpressure。
- 防路由环路。

### 15.3 启动事务

1. 保存系统代理、DNS、默认路由、活跃接口快照。
2. 生成并校验 runtime。
3. 启动 daemon/core。
4. 等待虚拟网卡。
5. 等待 API 和本地代理端口。
6. 验证 DNS。
7. 验证 DIRECT。
8. 验证当前代理节点。
9. 成功后才把 UI 标记为运行中。

任一步失败必须自动回滚。

### 15.4 停止和恢复

- 停止后台测速和切换任务。
- 保存流量。
- 关闭 TUN。
- 恢复系统代理、DNS 和路由。
- 终止残留 core。
- App 正常退出、强杀、core 崩溃后都能恢复。
- 下次启动检测 `utun`、198.18.0.0/15、代理、DNS 和 daemon 残留。

### 15.5 DNS 引擎

- 系统 DNS。
- UDP DNS。
- DNS over TCP。
- DoT。
- DoH。
- 分流 DNS。
- direct/proxy resolver。
- IPv4/IPv6。
- UDP 失败后 TCP fallback。
- 防递归和防泄漏。

### 15.6 Fake-IP

- blacklist。
- whitelist。
- rule mode。
- TTL。
- 正反向映射。
- 地址池回收。
- 持久化策略。
- 与路由、SNI、DNS 缓存联动。

### 15.7 macOS 验收矩阵

- Wi-Fi。
- 有线网络。
- 网络切换。
- DHCP 变化。
- 休眠/唤醒。
- IPv4、IPv6 和双栈。
- VPN 共存。
- App 正常退出。
- App 强杀。
- core 崩溃。
- daemon 重启。
- 无管理员权限。
- DNS 不可达。

任何一项导致退出后断网，都视为 P0 缺陷。

## 16. M11：订阅、Provider 和规则资产

### 16.1 订阅下载

- 默认优先 DIRECT。
- 代理重试由用户设置决定。
- redirect。
- gzip/br。
- User-Agent。
- 自定义 headers。
- ETag。
- Last-Modified。
- timeout、retry、backoff。
- TLS 和 HTTP 错误分类。

### 16.2 本地数据

每个订阅保存：

- URL 的安全引用。
- 原始 payload。
- 解析后的节点。
- 代理组。
- selected node/group。
- provider payload。
- rules。
- rule-providers。
- subscription-userinfo。
- 套餐流量。
- 到期日期。
- 更新时间。
- 上次有效节点。
- 生命周期累计流量。

订阅 URL 和认证信息存 Keychain，普通缓存使用权限受限文件。

### 16.3 切换订阅

- 只切本地 profile。
- 不下载。
- 不测速。
- 不重建无关缓存。
- 不重启正在运行的 core，优先使用热更新。
- 新导入订阅仅在当前没有 active profile 时自动启用。

### 16.4 Provider

- 本地缓存。
- 网络失败回退旧缓存。
- 特殊字符名称。
- 嵌套组。
- include-all。
- filter/exclude-filter。
- health-check。
- override。
- rule-provider 缓存和更新。

## 17. M12：原生智能规则和应用级路由

### 17.1 路由优先级

固定为：

1. 用户手动规则。
2. 用户已启用的智能规则。
3. 应用/域名/IP 指定节点规则。
4. 订阅规则。
5. 自动学习建议，不直接参与路由。
6. fallback。

### 17.2 观察数据

记录：

- domain。
- resolved IP。
- destination port。
- network。
- process name。
- executable path。
- bundle ID。
- 当前规则。
- 当前 outbound。
- 连接结果。
- DNS、TCP、TLS 和 HTTP 结果。

### 17.3 学习模型

- 使用隔离的 DIRECT probe 验证直连能力。
- DNS 成功不等于目标可直连。
- 记录成功次数、失败次数、成功率、P50、最近成功和最近失败。
- 达到最小样本数后才产生建议。
- CDN、动态 IP、QUIC、短时故障使用更保守阈值。
- 使用滞后和冷却时间避免规则抖动。

### 17.4 用户能力

- 推荐直连。
- 推荐代理。
- 单条启用。
- 批量启用。
- 撤销。
- 删除。
- 清空学习记录。
- 指定域名走具体节点。
- 指定 IP/CIDR 走具体节点。
- 指定 App 走具体节点。
- 指定目标走代理组自动择优。

### 17.5 macOS App 识别

TUN 路径中可靠关联：

- PID。
- bundle ID。
- executable path。
- process name。

无法获取进程信息时必须降级为普通域名/IP 规则，不能错误归属。

## 18. M13：流量、连接、日志和诊断

### 18.1 流量

- 实时上传速率。
- 实时下载速率。
- 当前 runtime 总量。
- 按订阅生命周期累计。
- App 重启不丢失。
- core 重启不重复累计。
- profile 切换不串数据。
- 使用单调计数器和持久化 checkpoint。

### 18.2 连接表

显示：

- 目标域名/IP。
- App。
- 命中规则。
- 实际节点。
- 代理组。
- 上传/下载。
- 开始时间。
- 持续时间。
- 关闭原因。

### 18.3 日志

最新日志显示在最上方，按 Tab 分类：

- 全部。
- 代理。
- 直连。
- 规则。
- DNS。
- TUN。
- 错误。
- 系统。

必须实现：

- token、Authorization、密码、UUID、私钥脱敏。
- 大小限制。
- 文件轮转。
- 内存 ring buffer。
- 诊断包导出时再次脱敏。

### 18.4 Doctor

检查：

- core 可执行文件。
- 配置。
- 端口。
- 系统代理。
- TUN daemon。
- 路由。
- DNS。
- Fake-IP。
- 当前节点。
- 订阅缓存。
- 协议能力。
- 残留进程。

提供一键恢复网络，但执行前必须记录可恢复快照。

## 19. M14：macOS App UI 与交互

### 19.1 全局

- 启动/停止代理使用一个状态切换按钮。
- 顶部和菜单栏统一使用“玥球电梯”。
- 双击菜单栏图标打开主界面。
- 所有长任务显示进度、当前阶段、取消和明确错误。
- 不用重复下拉框表达已经可以通过网格完成的选择。

### 19.2 节点页

- 当前订阅、代理组、实际节点和延迟始终可见。
- 点击代理组先查看组内容，不自动切换；单独提供“使用该组自动择优”操作。
- 代理组整行可点击。
- 国家网格完整滚动。
- 节点搜索、协议筛选、国家筛选、延迟排序。
- 当前节点使用清晰、克制的选中状态。
- 测速当前节点、当前组、当前国家、所有节点、失败节点。
- 可取消并显示完成进度。

延迟颜色：

- `<50ms`：绿色。
- `50-150ms`：蓝色。
- `150-499ms`：红色。
- `>=500ms`：超时/不可用。

### 19.3 订阅页

- 多订阅列表。
- active 状态。
- 添加、删除、切换、更新全部。
- 节点数、不可支持数、套餐流量、到期日期、更新时间。
- 更新是后台任务，不闪烁页面。
- 失败保留旧缓存并显示失败原因。

### 19.4 智能规则页

- 顶部统计。
- “当前代理但直连可用”的比例。
- 推荐直连和推荐代理列表。
- 单条/批量启用。
- 搜索、筛选、撤销、删除。

### 19.5 设置页

- 系统代理。
- 虚拟网卡模式。
- DNS 模式及清楚解释。
- Fake-IP 风险确认。
- 测速 URL、超时和并发。
- 后台测速与订阅更新周期。
- 自动择优策略。
- 一键恢复网络。
- Doctor。

### 19.6 性能要求

- 1000 节点使用 Lazy 容器和稳定 identity。
- 搜索、筛选、排序移到后台计算。
- 避免对整个 `AppState` 的无差别刷新。
- 订阅切换只切内存模型和本地缓存。
- 日志和连接使用增量更新。

## 20. M15：性能、质量和安全

### 20.1 Benchmark

新增：

- `Supercore/benches/routing.rs`
- `Supercore/benches/probe_scheduler.rs`
- `Supercore/benches/fakeip.rs`
- `Supercore/benches/protocol_framing.rs`
- `Supercore/benches/subscription_parse.rs`
- `Supercore/benches/tcp_relay.rs`
- `Supercore/benches/udp_relay.rs`

覆盖：

- 1K/10K/100K 规则。
- 100/1K/10K 节点。
- probe 并发 10/50/100/256。
- Fake-IP 10K/100K。
- 订阅 1MB/10MB。
- TCP throughput。
- UDP packets/s。

### 20.2 性能目标

- App 空闲 CPU 接近 0。
- core 空闲无持续 task 增长。
- 后台测速不明显增加代理延迟。
- 1000 节点切换订阅不触发网络下载。
- 1000 节点列表滚动流畅。
- 1000 并发连接稳定。
- 24 小时运行无持续内存增长。

### 20.3 代码质量

- `cargo clippy --all-targets --all-features -- -D warnings` 通过。
- Swift build 无 warning。
- 只格式化本次修改文件，避免无关大改。
- 公共 API 有边界测试。
- 删除失效 TODO、过时兼容入口和死代码。

### 20.4 安全

- Control API 只监听 loopback。
- API 使用每次启动生成的随机 token。
- 所有写操作验证 token。
- Keychain 保存敏感数据。
- 配置和缓存权限限制到当前用户。
- daemon runtime 不含订阅 URL。
- 所有日志脱敏。
- fuzz parser、协议 frame 和订阅输入。
- 依赖漏洞和许可证检查。

## 21. M16：最终验收和发布

### 21.1 自动化测试

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

要求：

- 不存在未登记的 ignored test。
- full 协议不存在 ignored E2E。
- 没有假测试。
- release 构建无 warning。

### 21.2 真实功能测试

- 新用户首次启动。
- 导入多种订阅。
- 关闭代理测速。
- 选择节点后快速启动。
- 系统代理上网。
- TUN 上网。
- TCP、UDP、QUIC。
- 切换节点和代理组。
- 自动择优。
- 切换订阅。
- 更新所有订阅。
- 流量累计。
- 智能规则。
- App 规则。
- 退出、强杀、崩溃、休眠唤醒后的网络恢复。

### 21.3 稳定性

- 24 小时稳定运行。
- 1000 并发连接。
- 长连接。
- 高频 DNS。
- 后台订阅更新。
- 后台测速。
- 网络切换。
- core 热重载。

### 21.4 发布

1. 更新中英文 README，只描述真实能力。
2. 更新协议矩阵。
3. 扫描敏感数据。
4. 构建 arm64 release。
5. 将 Skyhook 嵌入 App。
6. codesign。
7. notarization。
8. staple。
9. 使用已经确认的 DMG 背景和布局打包。
10. 安装、覆盖安装、卸载测试。
11. 创建 tag 和 GitHub Release。
12. 上传 DMG。
13. README 更新 Release 下载链接。

## 22. 阶段状态规则

每个里程碑只能使用以下状态：

- `NOT_STARTED`
- `IN_PROGRESS`
- `CODE_COMPLETE`
- `VERIFIED`
- `BLOCKED`

定义：

- `CODE_COMPLETE`：代码写完，但完整验收未完成。
- `VERIFIED`：本阶段要求的测试、构建和真实运行验收全部通过。
- 任何历史测试结果都不能直接作为当前版本的 `VERIFIED` 证据。

## 23. 最终完成定义

只有以下条件全部满足，项目才能标记为完成：

- M0-M16 全部 `VERIFIED`。
- 所有标记 `full` 的协议有真实拨号和 E2E 测试。
- 没有 full 协议测试处于 ignored。
- TUN 在退出、强杀、崩溃和网络切换后不会导致断网。
- 测速不启用 TUN、不修改系统代理、不下载订阅。
- 节点测试与成熟客户端的差异可解释并达到设定目标。
- 启动代理不更新订阅、不做无关全局测速。
- 多订阅切换只使用本地缓存。
- 智能规则和指定 App/域名/IP/节点路由真实生效。
- 实时速率和累计流量准确且持久化。
- `cargo test`、`swift test`、严格 clippy 和 release build 全部通过。
- 24 小时稳定性测试通过。
- DMG 安装、运行、覆盖安装、退出和卸载通过。
- 发布包不包含任何用户订阅或敏感数据。

在以上条件全部满足前，只能报告具体阶段进度，不能使用“全部完成”。
