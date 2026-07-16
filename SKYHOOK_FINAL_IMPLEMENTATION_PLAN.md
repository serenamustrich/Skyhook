# Skyhook（玥球核心）最终版直接开发计划

> 项目根目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore`
>
> Rust 核心目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore`
>
> macOS App 目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Sources/YueqiuElevatorSupercore`
>
> 计划冻结日期：2026-07-17
>
> 执行方式：本计划由 Codex 直接实施，不作为交接说明，不依赖 Mihomo 二进制、双核心或运行时兼容回退。

## 1. 文档地位

从本文档创建后：

1. 本文档是 Skyhook 当前代码到最终正式版的唯一执行计划。
2. `SUPERCORE_FINAL_COMPLETION_DEVELOPMENT_PLAN.md`、`SKYHOOK_CURRENT_TO_FINAL_EXECUTION_PLAN.md` 等旧计划仅保留历史参考，不再作为当前进度依据。
3. “完成”只按本文档的固定范围和验收门判断，不因后续重复讨论而临时增加完成条件。
4. 本计划全部达到 `VERIFIED` 后，当前版本即视为开发完成；之后提出的新平台、新协议或新产品功能进入下一版本。
5. README 只描述已经交付的功能，不写开发过程、剩余计划和未经验证的能力。

## 2. 最终产品定义

最终交付物是一个完全独立的 Apple Silicon macOS 代理产品：

- 产品名：玥球电梯。
- 核心名：Skyhook，中文名“玥球核心”。
- 数据面：仅使用仓库内 Rust-native Skyhook。
- App：原生 Swift/AppKit 菜单栏应用。
- 网络模式：
  - 系统代理。
  - TUN 虚拟网卡。
- 数据来源：
  - 多订阅。
  - 本地 YAML/URI。
  - Proxy Provider。
  - Rule Provider。
- 选路方式：
  - 具体节点。
  - 代理组策略。
  - 国家内择优。
  - 用户自定义规则。
  - 智能学习规则。
  - 指定 App、域名或 IP 走指定节点/组/国家。
- 运维能力：
  - 未启动代理也能测速。
  - 后台测速和订阅更新不阻塞数据面。
  - 实时速率、累计流量、连接、日志和 Doctor。
  - TUN/DNS 异常退出后自动恢复网络。
- 发布：
  - 签名、公证、可安装的 Apple Silicon DMG。
  - GitHub 源码和 Release。

## 3. 固定范围

### 3.1 本轮必须完成

- macOS 12 及以上。
- Apple Silicon `arm64`。
- Skyhook 是唯一代理核心。
- 系统代理和 TUN 均能通过所选节点正常上网。
- 当前配置枚举中的全部正式协议完成真实拨号，或在协议本身没有对应能力时明确标记 `not-applicable`。
- 补齐 Mihomo 官方文档在 2026-07-17 已列出的 macOS 相关核心能力。
- 完成多订阅、Provider、代理组、规则、测速、流量、日志和 UI。
- 完成真实 macOS 网络恢复、长稳、性能、安全和发布验收。

### 3.2 本轮明确不做

- Windows、Linux、iOS、Android 客户端。
- Intel Mac 和 Universal Binary。
- 浏览器扩展、账号、云同步、收费系统。
- 计划冻结日期之后 Mihomo 新增的协议或字段。
- 未公开、无法合法独立实现和验证的私有协议扩展。
- 为兼容旧玥球电梯而保留 Mihomo API、Mihomo 配置运行时或 Mihomo 二进制。

### 3.3 “对标 Mihomo”的固定含义

以 2026-07-17 的 Mihomo 官方文档为冻结基线：

- 出站协议和内置策略范围参考：
  `https://wiki.metacubex.one/en/config/`
- 通用代理字段参考：
  `https://wiki.metacubex.one/en/config/proxies/`
- TUN 范围参考：
  `https://wiki.metacubex.one/en/config/inbound/tun/`
- DNS 范围参考：
  `https://wiki.metacubex.one/en/config/dns/`
- Provider 范围参考：
  `https://wiki.metacubex.one/en/config/proxy-providers/`

本轮只对标这些文档中适用于 macOS 的行为。Linux-only、Android-only 和 Windows-only 字段不需要在 macOS 实现，但解析时必须给出明确的平台限制，不能静默忽略。

## 4. 完成状态定义

每个阶段只能使用：

- `NOT_STARTED`
- `IN_PROGRESS`
- `IMPLEMENTED`
- `VERIFIED`
- `BLOCKED`

含义：

- `IMPLEMENTED`：代码完成且针对性测试通过。
- `VERIFIED`：阶段全量测试、真实功能验收和文档证据全部通过。
- 只有 `VERIFIED` 才算完成。
- `BLOCKED` 必须写清外部条件、已经完成的部分和解除阻断的方法。

以下情况不能算完成：

- 只能编译。
- 只能解析 YAML/URI。
- outbound 仍返回 `UnsupportedProtocolOutbound`。
- 测试只检查数组长度、字段存在或永真表达式。
- 只有客户端按钮，没有核心行为。
- 只用一次手动连接宣称协议完整。
- 只修改 README 或协议矩阵。

## 5. 当前真实断点

### 5.1 已提交并保留

当前 `main` 分支已包含：

- `a8a55e0 Establish Yueqiu Elevator Supercore baseline`
- `f46fff6 Complete Snell v4 and v5 connection reuse`
- `a0832c8 Secure the versioned control plane`
- `430a927 Modularize outbound transport foundations`
- `ad66698 Add cancellable control tasks and probe progress`
- `a14623b Document the final Skyhook execution plan`
- `422579e Stream unified control telemetry events`
- `76bf497 Drive the macOS client from control events`

已经完成的基础：

- 独立 `/v1` 控制 API。
- loopback 控制地址限制。
- 写接口 Bearer Token。
- 结构化 API 错误。
- Swift 客户端迁移到 `/v1`。
- 启动代理不更新订阅、不立即全局测速。
- `DialContext` 和 cancellation token 基础。
- TCP、TLS、HTTP CONNECT、WebSocket、HTTP/2、gRPC、HTTPUpgrade、QUIC 配置公共模块。
- Direct、Reject、HTTP、Naive、Group、Unsupported 和 registry 初步拆分。
- Snell v4/v5 connection reuse。
- 统一 telemetry event bus 和有界事件通道。
- Swift 标准 SSE parser、断线重连、快照恢复和 polling 回退。
- 实时速率、日志、节点健康和测速进度的事件驱动更新。

### 5.2 当前 M0 任务控制面

提交 `ad66698` 已完成：

- task 状态、查询、取消和有界保留。
- 全量测速、代理组测速、订阅导入和更新全部订阅返回 HTTP `202` + `task_id`。
- Swift task polling 和独立取消请求。
- 每节点测速进度。
- invalid probe URL 下 requested node 结果完整性。
- SSE task 事件包含 schema version、event id 和 timestamp。

本批次验证：

- Rust lib：87 passed、0 failed、0 ignored。
- Swift full：93 passed、0 failed。

后续提交已将 Rust lib 基线提升为 90 passed，并完成统一 telemetry event bus：

- task。
- probe progress。
- status。
- subscription。
- connection opened/updated/closed。
- traffic sample。
- log。
- outbound health。

高频连接/流量事件按 250ms 节流，事件通道有界。Swift 已完成标准 SSE parser、
`Last-Event-ID`、指数退避重连、完整快照恢复和轮询兜底，并使用核心 rate 事件直接
更新实时速率。Swift full 当前为 96 passed。

Provider、Geo、Doctor 和诊断包导出已经迁移到 task。单订阅更新也已补齐；订阅导入、
订阅更新和 Provider 解析全部使用异步可取消的直连下载路径。TUN 安装、启停和恢复
将在 M5 的正式 lifecycle/helper/网络事务完成后接入同一 task/event 框架，不在 M0
增加无法控制真实 TUN 生命周期的假接口。M0 已达到 `VERIFIED`。

### 5.3 当前结构债务

- `Supercore/src/outbound/mod.rs`：约 12,446 行。
- `Supercore/src/core/mod.rs`：约 2,234 行。
- `Supercore/src/api/mod.rs`：约 1,768 行。
- `AppState.swift`：约 3,046 行。
- `SettingsWindow.swift`：约 1,614 行。
- 协议实现仍大量集中在 `outbound/mod.rs`。
- API、核心协调和 UI 状态职责仍过度集中。
- 当前代码中 Hysteria v1、Mieru、Juicity、MASQUE、OpenVPN 仍是 parse-only/unsupported。
- Mihomo 当前官方协议列表中的 Sudoku、Tailscale、TrustTunnel、DNS outbound 和 Rematch 尚未进入 Skyhook 正式模型。
- TUN 当前依赖 `tun2proxy 0.8.1`，不具备最终要求的完整事务恢复能力。

### 5.4 最近验证基线

历史里程碑验证曾达到 Rust 263 passed、0 failed、1 external-subscription ignored，
Swift 89 passed、0 failed，并且 Rust/Swift release build 通过；这些只作为历史基线，
不替代当前阶段重新验证。

M0 最终确认基线：

- Rust lib：92 passed、0 failed。
- Rust subscription store：13 passed、0 failed。
- Rust Geo assets：3 passed、0 failed。
- Swift full：97 passed、0 failed。
- `cargo check --lib`：通过且无 warning。

task/SSE/progress/telemetry 和现有长任务迁移已经完成，M0 关闭。当前直接执行点进入
M1：API、Core、Outbound 模块化和统一网络基础设施。

### 5.5 当前直接执行队列

接下来由 Codex 严格按以下顺序直接开发，不交接给其他开发者或模型：

1. 进入 M1，依次拆分 API、Core、Outbound，并统一错误、DialContext、transport、UDP 和 cancellation。
2. 按 M2-M3 完成所有 partial/parse-only 协议的真实 TCP/UDP 拨号和互操作证据。
3. 按 M4-M5 完成 DNS/Fake-IP、macOS TUN、权限服务、事务回滚和异常恢复。
4. 按 M6-M9 完成独立测速、自动择优、多订阅、Provider、代理组、智能规则、流量、日志和 Doctor。
5. 按 M10-M11 完成 App 架构、最终 UI、性能、安全、CI 和开源治理。
6. 按 M12 完成真实订阅验收、长稳、签名、公证、DMG 和 GitHub Release。

在第 6 项通过前，不把“能编译”“能解析”或“部分协议能连接”表述为最终完成。

## 6. 不可违反的开发规则

1. 不引入 Mihomo 二进制、双核心和运行时回退。
2. 不复制其他项目受版权保护的实现；只使用公开规范、测试向量和合法互操作。
3. 不提交真实订阅 URL、节点密码、UUID、私钥、Token、profile、日志或流量数据。
4. 启动代理只读取本地缓存和已选策略。
5. 启动代理不下载订阅、不全局测速、不重建无关数据。
6. 测速 runtime 不开启 TUN、不修改系统代理、不修改系统 DNS。
7. 订阅和 Provider 下载默认优先直连。
8. TUN/DNS 所有系统变更必须使用快照、journal、验证、回滚和恢复事务。
9. 后台订阅更新、测速、日志写入和统计持久化不得阻塞代理数据面。
10. 代码先完成，测试按阶段集中执行；不在每个小改动后重复完整 LTO 构建。
11. 手工编辑只格式化涉及文件，不对全仓库制造无关格式变更。
12. 每次提交前更新对应功能文档，但 README 不写过程和计划。
13. 每次 GitHub 推送前执行 secret scan 和 DMG/profile 排除检查。
14. 每个提交保持单一主题，可独立编译和回滚。

## 7. 目标架构

### 7.1 Rust 核心

```text
Supercore/src/
  api/
    mod.rs
    auth.rs
    error.rs
    schema.rs
    state.rs
    tasks.rs
    events.rs
    routes/
  core/
    mod.rs
    runtime.rs
    lifecycle.rs
    probe.rs
    reload.rs
    selection.rs
  outbound/
    mod.rs
    registry.rs
    capability.rs
    context.rs
    error.rs
    target.rs
    pool.rs
    direct.rs
    reject.rs
    dns.rs
    rematch.rs
    http/
    socks5/
    shadowsocks/
    ssr/
    snell/
    trojan/
    vmess/
    vless/
    hysteria/
    hysteria2/
    tuic/
    wireguard/
    anytls/
    shadowtls/
    naive/
    ssh/
    mieru/
    juicity/
    sudoku/
    tailscale/
    masque/
    trusttunnel/
    openvpn/
    transports/
    udp/
  inbound/
    mixed/
    tun/
    dns/
    fakeip/
  routing/
  smart/
  subscription/
  providers/
  telemetry/
  platform/macos/
```

目标：

- `outbound/mod.rs` 只做导出和 registry 入口。
- 协议独立模块，不共享隐式全局状态。
- 所有网络操作统一使用 `DialContext`、结构化错误和 cancellation。
- 所有长任务统一使用 task/event 框架。
- 所有运行数据结构有容量和生命周期上限。

### 7.2 macOS 侧

```text
Sources/YueqiuElevatorSupercore/
  App/
  Coordinators/
    CoreCoordinator.swift
    ProbeCoordinator.swift
    SubscriptionCoordinator.swift
    NetworkModeCoordinator.swift
    TrafficCoordinator.swift
    RuleCoordinator.swift
  Stores/
  Services/
  Models/
  UI/
    Dashboard/
    Subscriptions/
    Nodes/
    SmartRules/
    CustomRules/
    Connections/
    Logs/
    Network/
    General/
```

目标：

- App 生命周期只有一个核心所有者。
- 后台网络和解析不占用 `MainActor`。
- 页面拥有独立 ViewModel。
- API event stream 驱动状态更新，轮询仅作为断线回退。
- 1000 到 2000 节点时 UI 仍可流畅筛选、滚动和切换。

## 8. 固定执行顺序

严格按以下顺序开发：

1. M0：保护工作区并收口当前 task/SSE 半成品。
2. M1：完成核心模块化、错误、取消、task 和 event 基础设施。
3. M2：完成通用网络能力和当前 partial 协议。
4. M3：补齐 Mihomo 冻结基线中缺失的协议和内置出站。
5. M4：完成独立 DNS 和 Fake-IP 引擎。
6. M5：完成 macOS TUN、权限服务和网络恢复。
7. M6：完成独立测速、后台测速和自动择优。
8. M7：完成订阅、Provider、代理组和本地数据模型。
9. M8：完成规则、智能学习和 App/域名/IP 指定节点。
10. M9：完成流量、连接、日志和 Doctor。
11. M10：完成 App 架构拆分和最终 UI/交互。
12. M11：完成性能、安全、CI 和开源治理。
13. M12：完成真实验收、签名、公证、DMG 和 GitHub Release。

M2 和 M3 的协议模块可以在同一阶段内并行编写，但不得绕过公共 transport、错误和取消基础。M10 不在 API schema 稳定前进行大规模页面绑定。

## 9. M0：收口当前 task/SSE 工作区

状态：`VERIFIED`

### 9.1 保护和审查

- 记录当前 `git status` 和 diff。
- 确认只保留已知的 task/SSE/progress 文件。
- 不覆盖当前未提交实现。
- 对新增文件补齐模块导出和可见性边界。

### 9.2 TaskManager 完整化

- task 状态：
  - queued
  - running
  - succeeded
  - failed
  - cancelled
- 每个 task 包含：
  - id
  - kind
  - current/total
  - message
  - created/started/finished time
  - result
  - structured error
  - trace id
- 终态不可被后续进度覆盖。
- 取消必须传播到实际 operation，而不是只把 UI 状态改成 cancelled。
- 已完成 task 使用有界保留：
  - 默认最多 512 条。
  - 终态默认保留 24 小时。
  - 活跃 task 不因清理被删除。
- task result 和 error details 有大小限制。
- Core 退出时所有活跃 task 进入 cancelled/failed 终态。

### 9.3 长任务迁移

统一进入 task 框架：

- 全部节点测速。
- 代理组测速。
- 单订阅导入。
- 更新全部订阅。
- 单订阅更新。
- Provider 更新。
- Geo 数据更新。
- Doctor 深度检查。
- 诊断包导出。

TUN 安装、启动、停止和恢复在 M5 完成真实 privileged helper、lifecycle 和网络事务后
接入 task 框架；M0 不增加只改状态、不控制真实系统操作的占位接口。

### 9.4 SSE 初版收口

- `GET /v1/events` 推送：
  - task_updated
  - status_changed
  - probe_progress
  - subscription_updated
  - log_appended
  - traffic_sample
  - connection_opened
  - connection_updated
  - connection_closed
- 每个事件包含 schema version、event id、timestamp 和 trace/task id。
- SSE 有 keepalive、断线重连和 lagged 状态。
- Swift 断线后先重新拉取快照，再恢复事件流。
- polling 仅保留为兼容和事件流失败回退。

### 9.5 当前测速进度修正

- 每个 requested node 必须产生一条终态结果。
- invalid probe URL 时，requested-but-missing 节点也必须返回对应失败。
- `completed` 只能在节点真正结束后递增。
- 排队中的节点不得提前标记 timeout。
- 取消时未执行节点标记 cancelled，不标记 timeout。
- progress listener 生命周期跟随主 task，不能泄漏 detached task。

### 9.6 M0 验收门

- `cargo check`。
- TaskManager 单元测试。
- Router 真实鉴权/task 测试。
- probe progress 定向测试。
- Swift `SupercoreAPIClientTests`。
- Rust lib 全量测试。
- Swift 全量测试。
- 更新 API 文档和中英文 README 的 task/event 说明。
- 创建提交：`Control: migrate remaining long operations to tasks`。

M0 达到 `VERIFIED` 后再进入大规模模块拆分。

## 10. M1：核心模块化和统一基础设施

状态：`IN_PROGRESS`

### 10.1 API 拆分

- 从 `api/mod.rs` 拆出：
  - auth
  - errors
  - tasks
  - events
  - schema
  - routes
- API state 不直接持有无边界的全局可变对象。
- 所有 route 使用统一请求校验、错误 envelope 和 trace id。
- 读接口支持分页、过滤和稳定排序。
- 写接口全部鉴权。
- control listen 仅允许 loopback 或 Unix domain socket。
- 生成 OpenAPI 3.1 或等价 JSON schema。
- 增加 schema compatibility test。

### 10.2 Core 拆分

- 从 `core/mod.rs` 拆出：
  - runtime lifecycle
  - config reload
  - probe scheduler
  - selection
  - background jobs
  - subscription merge
- reload 使用“构建新状态 -> 校验 -> 原子替换”，失败保留旧 runtime。
- Core shutdown 使用 cancellation tree，确保监听器、后台任务、连接池和持久化任务可控退出。

### 10.3 Outbound 统一接口

- `Outbound` 的 TCP/UDP/context 方法统一返回 `Result<_, OutboundError>`。
- 删除业务路径用字符串猜测错误类型。
- `OutboundErrorKind` 至少包含：
  - cancelled
  - timeout
  - dns
  - tcp_connect
  - tls
  - authentication
  - protocol
  - unsupported
  - remote_rejected
  - io
  - configuration
  - internal
- 错误携带：
  - operation
  - protocol
  - node
  - destination
  - retryable
  - source chain
  - trace id
- capability 由实现显式返回，不按协议名字符串推断。

### 10.4 DialContext

固定字段：

- destination
- source address
- inbound name/type
- app identity
- matched rule
- timeout/deadline
- cancellation token
- trace id
- subscription id
- group
- selected node
- network/interface preference
- DNS policy

系统代理、TUN、测速和后台直连测试使用同一上下文。

### 10.5 公共 TCP/TLS

- Happy Eyeballs。
- IPv4/IPv6/dual/prefer 策略。
- connect timeout 和总 deadline。
- interface bind。
- keepalive。
- TCP Fast Open，平台支持时启用。
- MPTCP，macOS 支持且配置启用时使用。
- half-close。
- cancellation。
- TLS SNI、ALPN、证书校验、skip verify。
- TLS session resumption。
- 统一握手阶段计时。

### 10.6 公共 Transport

完成并独立测试：

- WebSocket：
  - path
  - Host
  - headers
  - early data
  - ping/pong
  - close
- HTTP/2：
  - flow control
  - window update
  - half-close
  - RST
  - GOAWAY
- gRPC：
  - 5-byte framing
  - split/combined frames
  - trailers
  - cancellation
- HTTPUpgrade：
  - request
  - 101 validation
  - bidirectional stream
- QUIC：
  - endpoint pool
  - connection/session pool
  - stream
  - datagram
  - keepalive
  - MTU
  - zero-RTT policy
  - close/error mapping

### 10.7 公共 UDP

- 单目标和多目标 association。
- endpoint-dependent 和 endpoint-independent NAT。
- session key 包含协议、节点、目标和必要上下文。
- idle timeout。
- bounded session/socket pool。
- fragmentation/reassembly。
- replay window。
- backpressure。
- cancellation 和 deadline。
- session 创建失败不影响同批其他任务。
- UDP 统计进入连接表和流量计数。

### 10.8 通用代理字段

按冻结的 Mihomo common fields 补齐：

- IP version strategy。
- interface-name。
- routing mark：macOS 不适用时返回平台限制。
- TFO。
- MPTCP。
- dialer-proxy 链式拨号。
- smux：
  - smux
  - yamux
  - h2mux
  - max connections/streams
  - padding
  - only-tcp
- UDP enable/disable。
- certificate fingerprint/config validation。

### 10.9 M1 验收门

- `outbound/mod.rs` 只保留公共导出和构造入口。
- `api/mod.rs` 只保留 router 组合和公共导出。
- `core/mod.rs` 只保留核心公共入口。
- transport/UDP 有独立 mock server 测试。
- cancellation 从 API task 传播到 socket/handshake。
- 现有全部协议回归通过。
- OpenAPI/schema test 通过。
- Swift 只使用 `/v1`。

## 11. M2：完成当前 partial 协议

状态：`NOT_STARTED`

### 11.1 协议完成标准

协议只有同时满足以下条件才能标记 `full`：

1. YAML 解析。
2. 标准 URI 解析，存在标准 URI 时必须支持。
3. 字段校验和明确错误。
4. TCP 真实拨号，协议支持 TCP 时。
5. UDP 真实拨号，协议支持 UDP 时。
6. 所声明 transport 真实工作。
7. 上行、下行、认证、加密、分帧、关闭正确。
8. 本地 mock server E2E。
9. 公开测试向量或公开实现互操作。
10. 错误密码、错误服务端、超时和取消测试。
11. capability、README 和协议矩阵一致。

协议本身没有某项能力时标记 `not-applicable`，不把协议边界写成缺陷。

### 11.2 Shadowsocks

- legacy stream/AEAD 方法矩阵。
- Shadowsocks 2022 三种方法。
- SIP022/SIP023。
- TCP/UDP。
- 多用户 EIH。
- replay protection。
- simple-obfs HTTP/TLS。
- v2ray-plugin WebSocket/TLS。
- plugin UDP 按真实规范处理。
- 大包、分片、长连接、错误密钥、重放测试。

### 11.3 ShadowsocksR

- 当前 auth 协议与 cipher/obfs 组合独立模块化。
- TCP/UDP 能力按协议组合真实声明。
- 多用户参数。
- HTTP simple/post。
- TLS ticket auth。
- auth_chain a-f。
- 不支持组合在拨号前返回 configuration/unsupported，不伪装 timeout。

### 11.4 Snell

- v1-v5 TCP。
- v3-v5 UDP-over-TCP。
- HTTP/TLS obfs。
- v4/v5 reuse。
- pool 上限、空闲淘汰、半关闭和陈旧连接重拨。
- 长连接、并发 stream、错误 PSK 和 server close。

### 11.5 Trojan

- TCP、UDP。
- TLS。
- WS、gRPC、H2、HTTPUpgrade。
- custom headers、ALPN。
- UDP over transport。
- remote status、trailer、half-close。
- 更广泛服务端字段兼容 fixture。

### 11.6 VMess

- alterId=0 AEAD。
- legacy alterId，仅在公开规范和互操作足够时实现。
- TCP、UDP。
- WS、gRPC、H2、HTTPUpgrade/XHTTP 配置边界。
- security/cipher matrix。
- response header、clock skew、bad UUID、bad auth。
- 多目的 UDP association。

### 11.7 VLESS、Reality、Vision

- TCP、UDP。
- TLS/无 TLS。
- WS、gRPC、H2、HTTPUpgrade。
- Reality：
  - public key
  - short id
  - server name
  - fingerprint
  - spider/xver 等已声明字段
- XTLS Vision：
  - flow validation
  - padding
  - TLS record state
  - direct copy boundary
- 真实 mock/interop 覆盖握手成功和失败。

### 11.8 Hysteria2、TUIC

Hysteria2：

- auth。
- Salamander obfs。
- TCP。
- UDP。
- fragmentation。
- session reuse。
- bandwidth/congestion。

TUIC v5：

- UUID/password。
- TCP。
- native/quic UDP relay。
- congestion controller。
- keepalive。
- max packet。
- zero-RTT/replay 策略。

两者必须有本地 QUIC server E2E，不能只测序列化字节。

### 11.9 WireGuard

- private/public/pre-shared key validation。
- userspace handshake。
- IPv4/IPv6 address。
- allowed IP。
- persistent keepalive。
- MTU。
- DNS。
- TCP/UDP through tunnel。
- multi-peer。
- replay/counter/rekey。

### 11.10 AnyTLS、ShadowTLS、Naive

AnyTLS：

- auth。
- padding scheme。
- session/resumption。
- TCP。
- 协议规定范围内 UDP。

ShadowTLS：

- v3 handshake。
- password/auth。
- TLS camouflage。
- backend proxy combination。
- 证书和握手错误。

Naive：

- HTTP/2 CONNECT。
- HTTP/3 CONNECT，配置声明时。
- Basic auth。
- padding。
- TCP。
- CONNECT-UDP，协议支持时。

### 11.11 HTTP、SOCKS5、SSH

- HTTP/HTTPS CONNECT、认证、IPv4/IPv6、非 2xx。
- SOCKS5 TCP、UDP ASSOCIATE、用户名密码、域名/IP。
- SSH host key policy、密码/私钥、TCP channel、keepalive、reconnect。
- SSH UDP 不存在标准实现时标记 `not-applicable`。

### 11.12 M2 验收门

- 当前 matrix 中所有 `partial` 项完成或有协议级 `not-applicable` 解释。
- 每个协议独立模块。
- 每行协议可追溯到测试文件和测试名。
- 不再因未知字符串错误把认证失败写成 timeout。
- 不存在仅依赖 mock client 自己生成并自己验证的循环证明。
- 当前 partial 协议统一回归通过。

## 12. M3：补齐 Mihomo 冻结基线协议

状态：`NOT_STARTED`

### 12.1 必须新增或完成

当前已有配置但不能拨号：

- Hysteria v1。
- Mieru。
- Juicity。
- MASQUE。
- OpenVPN。

Mihomo 冻结基线有、当前 Skyhook 正式模型缺失：

- DNS outbound。
- Rematch。
- Sudoku。
- Tailscale。
- TrustTunnel。

当前 Skyhook 已有但 Mihomo 当前索引未突出、仍需保留：

- ShadowTLS。
- Naive。
- Juicity。
- Reject。

### 12.2 Hysteria v1

- QUIC transport。
- auth。
- up/down bandwidth。
- obfs。
- TCP stream。
- UDP。
- MTU、keepalive、timeout。
- 本地服务端 E2E。

### 12.3 Mieru

- 官方配置字段模型。
- TCP/UDP。
- authentication。
- multiplexing/padding。
- MTU。
- mock server 或官方实现互操作。

### 12.4 Juicity

- UUID/password。
- QUIC/TLS。
- TCP/UDP。
- congestion、keepalive。
- 错误认证和 session 恢复。

### 12.5 MASQUE

- HTTP/3。
- CONNECT-UDP。
- CONNECT-IP，配置声明时。
- authentication。
- datagram capsule。
- flow id。
- QUIC migration 和关闭。

### 12.6 OpenVPN

- 配置和 inline certificate/key。
- TLS control channel。
- data channel cipher/auth。
- TCP/UDP transport。
- route/push option 中与 outbound 有关的部分。
- keepalive、reconnect、renegotiation。
- 不把 OpenVPN 作为系统级外部进程调用。

### 12.7 Sudoku

- 按公开规范完成 parser、handshake、TCP/UDP 和错误分类。
- 配置字段与冻结基线一致。
- 本地 E2E 或公开实现互操作。

### 12.8 Tailscale

- 仅实现作为 Skyhook outbound 所需的 userspace 接入。
- 身份、控制面和 tailnet 状态使用明确配置。
- TCP/UDP。
- DNS/route 与 Skyhook 自身路由隔离。
- 不修改用户已有 Tailscale 系统安装。

### 12.9 TrustTunnel

- 按公开规范完成认证、隧道、TCP/UDP 和重连。
- 不调用外部 TrustTunnel 客户端。
- 真实互操作。

### 12.10 DNS outbound 和 Rematch

DNS outbound：

- 允许规则把请求交给指定 DNS policy。
- 不与 DNS inbound/fake-ip 形成递归。
- 连接和流量可观测。

Rematch：

- 对已解析目标重新进入规则匹配。
- 有循环检测和最大深度。
- trace 中记录前后规则链。

### 12.11 M3 验收门

- 配置枚举中不存在正式协议永远进入 `UnsupportedProtocolOutbound`。
- 冻结协议清单全部具有 parser、runtime、capability 和 E2E。
- 协议矩阵没有 `parse-only`。
- 未知协议仍明确 unsupported，但不影响已知节点。
- 所有新增协议真实拨号测试通过。

## 13. M4：DNS 和 Fake-IP

状态：`NOT_STARTED`

### 13.1 Resolver 类型

- system。
- DHCP/interface resolver。
- UDP。
- TCP。
- DoT。
- DoH。
- DoH3。
- DoQ。
- rcode。
- 每种 resolver 支持独立 timeout、bootstrap、proxy/interface 选择。

### 13.2 macOS 系统 DNS

- 优先解析 `scutil --dns`。
- 回退 `/etc/resolv.conf`。
- 识别多 resolver、scope 和 interface。
- 排除 Skyhook 自身 listen 地址。
- 网络切换后自动刷新 resolver。
- 不把固定 `8.8.8.8` 当系统 DNS。

### 13.3 DNS policy

- default-nameserver。
- nameserver。
- fallback。
- fallback-filter。
- nameserver-policy。
- proxy-server-nameserver。
- proxy-server-nameserver-policy。
- direct-nameserver。
- direct-nameserver-follow-policy。
- respect-rules。
- IPv4/IPv6 控制。
- hosts/system-hosts。

### 13.4 Cache

- TTL。
- negative cache。
- LRU/ARC。
- bounded capacity。
- 并发查询合并。
- stale-if-error。
- 网络环境变化时按 policy 失效。
- cache metrics。

### 13.5 Fake-IP

- IPv4/IPv6 地址池。
- 正向/反向映射。
- blacklist。
- whitelist。
- rule mode。
- 精确域名和 wildcard。
- RULE-SET/GEOSITE。
- TTL 和回收。
- 池循环不覆盖有效 entry。
- 持久化有版本和容量限制。
- filter 命中返回真实 DNS，不返回 `0.0.0.0`。

### 13.6 DNS 安全

- bootstrap 不依赖尚未建立的代理链。
- DNS 查询有循环检测。
- DNS hijack 支持 UDP/TCP 53。
- App 退出或 TUN 停止后系统 DNS 必须恢复。
- DNS over TCP 只表示 DNS 查询通过 TCP 发送，不改写普通网络协议。

### 13.7 M4 验收门

- resolver 类型和 policy 测试通过。
- fake-ip filter/TTL/reverse/pool 测试通过。
- DNS 泄漏和递归测试通过。
- 网络切换、无网、resolver 故障测试通过。
- direct、system proxy、TUN 三种模式均能正确解析。

## 14. M5：macOS TUN 和网络恢复

状态：`NOT_STARTED`

### 14.1 TUN 架构

- 在 `TunBackend` trait 后隔离当前 tun2proxy。
- 评估并选择最终 macOS backend：
  - 继续增强 tun2proxy；或
  - 自建 utun + userspace stack；或
  - 使用合法开源 Rust 网络栈组件。
- 选择标准是：
  - TCP/UDP 完整性。
  - IPv6。
  - 可取消。
  - 可观测。
  - 事务恢复。
  - 性能。
- backend 差异不暴露为用户难懂的“虚拟 DNS”概念。

### 14.2 macOS 适用能力

- utun 创建和销毁。
- auto-route。
- auto-detect-interface。
- strict-route 的 macOS 等价行为。
- route-address。
- route-exclude-address。
- include/exclude interface。
- LAN bypass。
- endpoint-independent NAT。
- UDP timeout。
- IPv4/IPv6。
- MTU。
- DNS hijack UDP/TCP。
- loop prevention。
- 多 network service。

Linux-only `auto-redirect`、GSO、routing mark 和 UID/package 字段在 macOS 返回明确平台限制，不计为 macOS 能力缺口。

### 14.3 权限服务

- 使用受控 privileged helper/daemon。
- macOS 12 使用可支持的正式安装机制。
- 第一次安装需要管理员授权。
- 安装成功后启动/停止代理不重复索要密码。
- App 与 helper 使用最小 XPC/IPC 命令集。
- 校验调用方签名、bundle id 和版本。
- helper 不允许任意 shell、任意文件路径或任意网络配置。
- Token 由 root-only 文件或等价安全通道提供。

### 14.4 网络事务

启动：

1. 获取单实例锁。
2. 检查并恢复上次 journal。
3. 保存系统代理、DNS、默认路由、service 和 active interface 快照。
4. 校验 runtime。
5. 启动 core listener。
6. 创建 utun。
7. 设置地址、MTU、route 和 bypass。
8. 启动 DNS。
9. 验证核心、DNS、路由和外网。
10. 提交 journal。

停止：

1. 停止接收新连接。
2. 停止 TUN 数据面。
3. 删除 Skyhook 路由。
4. 恢复 DNS。
5. 恢复系统代理。
6. 删除快照和 journal。
7. 停止 core/helper 任务。

任何启动步骤失败必须逆序回滚。

### 14.5 异常恢复

- App 正常退出。
- 菜单退出。
- 窗口关闭。
- SIGINT/SIGTERM。
- Force Quit。
- App/core/helper crash。
- `kill -9` 后下次启动恢复。
- watchdog 检测 UI 不存在但网络改动仍残留。
- 一键恢复网络。
- 恢复只删除 Skyhook 自己创建的状态，不破坏用户 VPN、DNS 或其他代理。

### 14.6 超过 Mihomo 的明确目标

Skyhook 的 TUN 优势不靠增加无效开关，而靠以下可验证能力：

- 每次网络修改都有持久 journal。
- 崩溃后自动 fail-open 恢复联网。
- 启动前和停止后自动网络诊断。
- 每条 route/DNS/proxy 改动可追踪。
- 网络切换和睡眠唤醒自动重建事务。
- TUN 失败不影响系统代理模式。
- 后台测速和订阅更新绝不触碰 TUN。
- UI 可以显示当前 utun、route、DNS 和恢复状态。

### 14.7 App 级路由前置

- 评估 Network Extension entitlement。
- 若需可靠获取 source app identity，优先设计正式 Network Extension/透明代理路径。
- entitlement 未取得前，不伪造 TUN App 归属。
- system proxy 可识别路径和 TUN 无法识别路径必须在 capability 中区分。

### 14.8 M5 真实验收矩阵

覆盖：

- Wi-Fi。
- USB/有线网络。
- 多 network service。
- 网络切换 20 次。
- 睡眠/唤醒 20 次。
- TUN 启停 50 次。
- 无网启动。
- DNS 不可达。
- 节点不可达。
- 启动中取消。
- App Force Quit。
- core/helper crash。
- `kill -9`。
- 与其他 VPN/代理共存测试。

每个场景结束后验证：

- 普通直连网络可用。
- 系统 DNS 正常。
- 默认路由正常。
- 系统代理无残留。
- 无异常 utun、helper 或 journal。

## 15. M6：独立测速和自动择优

状态：`NOT_STARTED`

### 15.1 测速 runtime

- 从本地 profile 构建临时 runtime。
- 强制关闭：
  - TUN。
  - DNS listener。
  - 系统代理修改。
  - 订阅/Provider 更新。
- 不依赖主代理是否运行。
- 每个节点通过自己的真实协议拨号。
- 测速结束释放端口、socket、pool 和 task。

### 15.2 测速语义

- 默认 HTTPS 204 URL，允许用户设置。
- 默认单节点 timeout 500ms。
- 500ms 从节点实际开始执行时计时，不包含队列等待。
- 记录：
  - queue duration
  - DNS
  - TCP
  - TLS/QUIC
  - protocol handshake
  - TTFB
  - total
- 每个 requested node 必须有 started 和 finished。
- 失败分类：
  - cancelled
  - timeout
  - dns_error
  - tcp_error
  - tls_error
  - auth_error
  - protocol_unsupported
  - outbound_not_found
  - remote_rejected
  - http_status
  - empty_response
- 未调度节点不能标记 timeout。

### 15.3 并发调度

- 有界队列。
- TCP/TLS/QUIC 分协议并发上限。
- 默认并发根据 CPU、文件描述符和节点协议计算。
- 不在全局锁内 DNS/connect/handshake。
- 单节点卡住不阻塞其他节点。
- 取消后停止新任务并终止活跃任务。
- 500、1000、2000 节点压力测试。

### 15.4 测速入口

- 测速当前节点。
- 测速当前组。
- 测速当前国家。
- 测速可用节点。
- 测速所有节点。
- “所有节点”包含历史超时和不可用节点。
- 支持只显示本轮有延迟结果的节点。
- 历史结果不覆盖本轮未测试节点。

### 15.5 自动择优

用户可选择：

- 具体节点。
- 代理组策略。
- 国家策略。

行为：

- 点击代理组只查看内容，不立即切换。
- 用户显式选择“使用该组择优”才启用组策略。
- 选择国家只在该国家内择优。
- 启动代理直接使用上次节点/策略。
- 上次节点不可用时：
  1. 单测上次节点。
  2. 测试同组或同国家候选。
  3. 选择最低延迟可用节点。
  4. 无可用候选时扩大范围。
- 后台测速不切断现有连接。
- 节点切换只影响新连接，除非用户主动关闭旧连接。

### 15.6 延迟显示

- `<50ms`：绿色。
- `50-150ms`：蓝色。
- `150-500ms`：红色。
- `>500ms`：超时。
- 当前使用节点始终显示名称、协议、组/国家和最近延迟。

### 15.7 对比验收

固定同机、同网、同订阅、同 URL、同 500ms：

- 与 Sparkle/Mihomo 记录成功节点集合。
- Skyhook 可用率差异不超过 5 个百分点。
- 共同成功节点 median 差异不超过 25% 或 30ms，取较大值。
- P90 差异不超过 35%。
- 每个差异节点有阶段级失败证据。

## 16. M7：订阅、Provider、代理组和本地数据

状态：`NOT_STARTED`

### 16.1 下载通道

- 默认直连。
- 支持显式指定代理，但不能默认走当前代理。
- connect timeout 和 total timeout 分开。
- redirect 上限。
- gzip、brotli。
- User-Agent 和自定义 headers。
- ETag、Last-Modified、304。
- 响应大小上限。
- 取消和 task progress。
- 下载失败保留旧缓存。

### 16.2 订阅格式

- Clash/Mihomo YAML。
- Base64 URI list。
- plain URI list。
- HTTP/HTTPS/SOCKS5/SS/SSR/Trojan/VMess/VLESS/HY/HY2/TUIC/Snell/WG/AnyTLS 等已完成协议 URI。
- 兼容常见 `Content-Disposition` 和订阅 headers。
- 读取 `subscription-userinfo`：
  - upload
  - download
  - total
  - expire
- 不把未知节点静默丢失，记录 unsupported reason。

### 16.3 Profile 数据模型

每个订阅独立保存：

- stable id。
- 名称。
- URL 的 Keychain 引用。
- 原始内容。
- 规范化配置。
- 节点、代理组。
- providers。
- rules。
- ETag、Last-Modified。
- 添加时间、更新时间。
- 流量、限额、到期。
- 上次节点/组/国家。
- 累计上传/下载。
- 自定义和智能规则。
- schema version/migration。

写入使用临时文件、fsync 和原子替换。

### 16.4 导入和切换逻辑

- 没有任何订阅时，首个导入自动成为当前订阅。
- 已有当前订阅时，新导入只保存，不自动切换。
- 切换订阅只读取本地缓存。
- 未运行代理时切换不联网。
- 运行中切换使用原子热重载。
- 热重载失败继续使用旧 runtime。
- 1000 节点 profile 切换 P95 小于 150ms。

### 16.5 更新逻辑

- “更新全部”更新所有订阅。
- 每个订阅提供独立更新。
- 后台定时更新。
- 更新不自动切换当前订阅。
- 当前订阅更新成功后原子 reload。
- 非当前订阅只更新本地缓存。
- 页面显示每个订阅的 task、进度、结果和更新时间。

### 16.6 Proxy Provider

- HTTP/file。
- interval。
- health-check。
- lazy。
- expected status。
- headers。
- cache。
- 原子更新。
- provider 节点 override。
- provider 更新失败保留旧节点。
- provider 下载默认直连。

### 16.7 Rule Provider

- domain。
- classical。
- ipcidr。
- text/yaml/mrs 等实际声明格式。
- 本地和远程。
- interval/cache。
- RULE-SET 编译。
- provider 不可用时继续使用旧缓存。

### 16.8 代理组

- select。
- url-test。
- fallback。
- load-balance。
- relay。
- nested group。
- `use`、`filter`、`exclude-filter` 等 provider 过滤。
- 循环检测。
- 点击整行进入详情。
- 点击查看不切换。
- 显式“使用该组”后才按组策略代理。
- 国家组由稳定节点信息自动生成。

### 16.9 M7 验收门

- 两套以上 fixture 订阅可导入、切换、更新和重启恢复。
- 订阅切换不联网。
- 节点和代理组完整显示。
- 流量和到期显示。
- provider 缓存失败回退。
- 1000/2000 节点切换和显示性能达标。
- 无真实订阅 URL 进入测试、Git 或 DMG。

## 17. M8：规则、智能学习和指定节点

状态：`NOT_STARTED`

### 17.1 固定优先级

从高到低：

1. 用户指定 App + 域名/IP + 节点规则。
2. 用户自定义域名/IP/App 规则。
3. 用户启用的智能推荐。
4. 订阅规则。
5. 智能学习的未确认策略。
6. 默认策略。

### 17.2 匹配目标

- DOMAIN。
- DOMAIN-SUFFIX。
- DOMAIN-KEYWORD。
- IP-CIDR/IP-CIDR6。
- GEOIP。
- GEOSITE。
- PROCESS-NAME。
- PROCESS-PATH。
- BUNDLE-ID。
- RULE-SET。
- INBOUND/NETWORK，配置模型需要时。
- MATCH/FINAL。

### 17.3 动作

- DIRECT。
- REJECT。
- 指定节点。
- 指定代理组。
- 指定国家择优。
- DNS outbound。
- Rematch。

### 17.4 App identity

- PID。
- executable path。
- process name。
- bundle id。
- code signing identity。
- PID cache 处理退出和复用。
- system proxy 和可识别 TUN 流量使用同一 identity model。
- 无法可靠识别时标记 unknown，不猜测。

### 17.5 智能学习

每个观察记录：

- 域名/IP。
- App。
- 网络环境。
- 当前规则。
- 代理结果。
- 受控直连结果。
- DNS/TCP/TLS/HTTP 阶段。
- RTT。
- 时间。
- 样本数和置信度。

推荐：

- 订阅规则走代理，但直连持续成功：推荐直连。
- 订阅规则走直连，但直连持续失败且代理成功：推荐代理。
- 单次失败不产生推荐。
- 按网络环境隔离。
- 使用最小样本、时间衰减和失败惩罚。
- 学习探测限并发、限速，不影响正常代理。

### 17.6 智能规则页面

- 顶部统计：
  - 订阅走代理但直连可达比例。
  - 推荐直连数。
  - 推荐代理数。
  - 已启用数。
- 推荐直连列表。
- 推荐代理列表。
- 单条启用。
- 全部启用。
- 忽略。
- 撤销。
- 查看证据。
- 启用后规则立即高于订阅规则。

### 17.7 M8 验收门

- 域名、IP、CIDR、App 到节点/组/国家真实路由通过。
- 优先级冲突测试通过。
- 智能推荐不因单次失败误判。
- 学习任务不影响前台连接延迟。
- 用户规则可导出、迁移和恢复。

## 18. M9：流量、连接、日志和 Doctor

状态：`NOT_STARTED`

### 18.1 流量

- 当前上传/下载速率。
- 全局累计上传/下载。
- 按订阅累计。
- 按节点、组、规则、App。
- 64-bit 单调计数器。
- 固定采样窗口。
- App/core 重启不清零。
- 订阅切换不清零。
- 原子、节流持久化。
- 避免重启重复累计。

### 18.2 连接表

- id。
- start/end time。
- inbound/source。
- destination。
- app identity。
- rule。
- subscription/group/node。
- protocol stage。
- upload/download。
- current rate。
- error kind。
- trace id。
- 支持筛选和关闭单连接。
- closed history 有 TTL 和容量上限。

### 18.3 日志

- 最新在最上。
- Tab：
  - 全部
  - 核心
  - 代理
  - 直连
  - 规则
  - DNS
  - TUN
  - 订阅
  - 测速
- 结构化字段：
  - timestamp
  - level
  - category
  - message
  - trace/task/subscription/node/rule id
  - error kind
- 环形缓冲。
- 分页。
- 导出诊断包。
- secret redaction。

### 18.4 Doctor

检查：

- App/core/helper 版本。
- control API/auth。
- 端口占用。
- active subscription/node/group/country。
- protocol capability。
- system proxy。
- utun。
- routes。
- system/Skyhook DNS。
- journal/snapshot。
- provider/profile cache。
- 最近失败分类。
- 一键恢复动作。

### 18.5 M9 验收门

- 实际流量通过时速率非 0。
- 累计流量跨重启保留。
- 不同订阅独立累计。
- 连接表和日志字段可追溯。
- 日志倒序。
- Doctor 能发现并修复常见残留网络状态。

## 19. M10：macOS App 架构和最终 UI

状态：`NOT_STARTED`

### 19.1 状态架构

拆分：

- CoreCoordinator。
- SubscriptionCoordinator。
- ProbeCoordinator。
- NetworkModeCoordinator。
- TrafficCoordinator。
- RuleCoordinator。
- Log/Connection stores。
- 页面 ViewModel。

要求：

- 一个核心所有者。
- 后台任务不在 MainActor。
- 状态更新合并和节流。
- task 可取消。
- event stream 驱动 UI。
- App 状态机明确：
  - stopped
  - preparing
  - running system proxy
  - running TUN
  - stopping
  - recovering
  - failed

### 19.2 页面

- Dashboard。
- Subscriptions。
- Nodes。
- Smart Rules。
- Custom Rules。
- Connections。
- Logs。
- Network/TUN。
- General。

每页独立文件和 ViewModel，不继续扩大 `SettingsWindow.swift`。

### 19.3 全局交互

- 启用/停止只有一个状态按钮。
- 显示当前：
  - 订阅
  - 节点或组/国家策略
  - 延迟
  - 网络模式
  - 实时速率
  - 累计流量
- 菜单栏双击打开主窗口。
- 所有长任务有进度、取消、成功和失败。
- 不使用页面闪烁代替加载状态。
- Core 版本和值完整显示。

### 19.4 节点页

- 代理组整行可点击。
- 点击组只查看。
- 选中节点样式清晰、完整、有足够视觉层级。
- 国家使用可横向/纵向滚动网格，不重复放下拉框。
- 搜索。
- 国家、协议、可用性、延迟筛选。
- 测速当前组/国家/可用/全部。
- 显示当前使用节点和延迟颜色。
- 1000+ 节点使用懒加载/虚拟列表。
- 节点完整显示，不因分组、分页或宽度丢失。

### 19.5 订阅页

- 显示：
  - 名称
  - 节点数
  - 使用流量
  - 总流量
  - 到期
  - 更新时间
  - 更新状态
- 多订阅保存、切换、重命名、删除。
- 更新全部。
- 单独更新。
- URL 输入支持 Command-V/A/C/X/Z。
- 导入和更新进度明确。
- 本地切换不显示下载动画。

### 19.6 TUN 页面

- 使用“TUN 虚拟网卡”。
- DNS 处理方式独立解释。
- Fake-IP 独立解释。
- 权限服务安装、版本、状态、卸载分开。
- 启停不重复授权。
- 一键恢复网络。
- 退出时显示恢复结果。

### 19.7 UI 质量

- 1440x900。
- 1280x800。
- 最小窗口。
- 长中文、英文和 emoji。
- 1000/2000 节点。
- 键盘导航。
- VoiceOver labels。
- 颜色对比度。
- 无文字截断、控件重叠、滚动死区和整页无响应。

### 19.8 M10 验收门

- AppState/SettingsWindow 职责拆分完成。
- 页面交互全部连接真实 API。
- 长任务不卡 UI。
- 大 profile 切换和滚动性能达标。
- 菜单栏、主窗口和退出流程一致。

## 20. M11：性能、安全、质量和开源治理

状态：`NOT_STARTED`

### 20.1 Benchmark

Rust：

- 规则匹配。
- DNS cache。
- Fake-IP。
- 常用协议加解密/framing。
- QUIC session。
- UDP fragmentation。
- 订阅解析。
- 1000 节点 runtime 构建。
- 1000/2000 节点 probe 调度。

App：

- profile 切换。
- 节点筛选/排序。
- 页面首屏。
- 日志追加。
- 流量刷新。
- event burst。

### 20.2 性能目标

- 空闲 core CPU P95 小于 1% 单核。
- 空闲 App CPU P95 小于 1%。
- 1000 节点 App + core 常驻内存目标小于 250MB。
- 本地 profile 切换 P95 小于 150ms。
- 系统代理启动 P95 小于 2 秒。
- helper 已安装后的 TUN 启动 P95 小于 3 秒。
- 数据面不被持久化、日志、更新和测速阻塞。
- task、log、connection、DNS cache、UDP session 全部 bounded。

### 20.3 质量门

- `cargo fmt --check`。
- `cargo clippy --all-targets --all-features -- -D warnings`。
- `cargo test --all-targets`。
- `swift test`。
- Rust/Swift release build。
- 零未知 ignored test。
- 业务路径无导致进程崩溃的 `unwrap/expect`。
- sanitizer/fuzz：
  - subscription parser
  - URI parser
  - protocol frame parser
  - DNS packet
  - API JSON
- 故障注入：
  - socket failure
  - partial read/write
  - disk full
  - corrupt cache
  - cancellation race

### 20.4 安全

- control API loopback/UDS + token。
- constant-time token compare。
- privileged helper 调用方验证和最小权限。
- subscription/provider SSRF 和 redirect policy。
- YAML/URI/response 大小限制。
- 路径穿越保护。
- Keychain 存储 URL/credential 引用。
- 节点名和日志安全显示。
- secret redaction。
- secret scan：
  - subscription URLs
  - UUID/password
  - private keys
  - bearer tokens
  - profiles/logs
- 依赖漏洞和许可证审计。

### 20.5 开源治理

- clean-room provenance。
- 第三方依赖许可证清单。
- vendored rustls 来源和变更说明。
- 在开源前将 `license = "Proprietary"` 改为审计确认的许可证。
- 目标可选 `Apache-2.0 OR MIT`，最终以审计为准。
- 添加：
  - LICENSE
  - CONTRIBUTING
  - SECURITY
  - CODE_OF_CONDUCT
  - issue templates
  - PR template
  - CI
- README 不写“全面超过”之类不可验证宣传，使用可复现 benchmark 和 capability matrix。

### 20.6 M11 验收门

- 性能目标达标或有明确、可接受的偏差说明。
- clippy、测试、release build 全绿。
- fuzz/sanitizer 无已知崩溃。
- secret/license/security audit 通过。
- GitHub CI 可以从干净 checkout 重现。

## 21. M12：最终验收和发布

状态：`NOT_STARTED`

### 21.1 自动化门禁

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release

cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test
swift build -c release
```

附加：

- OpenAPI/schema consistency。
- protocol matrix consistency。
- secret scan。
- DMG content scan。
- clean-machine smoke test。
- release binary smoke test。

### 21.2 真实功能

使用至少两套不提交到仓库的真实订阅：

- 导入、保存、重启恢复。
- 新订阅不错误切换。
- 本地切换不联网。
- 更新全部和单独更新。
- 流量、总量、到期显示。
- 节点/代理组完整显示。
- 未启动代理测速。
- 500ms 正确超时。
- 测速所有历史不可用节点。
- 选择具体节点后直接启动。
- 选择代理组后组内择优。
- 选择国家后国家内择优。
- 上次节点恢复和 fallback。
- 系统代理上网。
- TUN 上网。
- TCP/UDP/IPv4/IPv6。
- 域名/IP/App 指定节点。
- 智能规则推荐、启用、撤销。
- 实时速率和累计流量。
- 正常退出、崩溃、强杀后网络恢复。

### 21.3 长稳

- 系统代理 24 小时。
- TUN 24 小时。
- 后台测速和订阅更新同时运行。
- 睡眠/唤醒 20 次。
- 网络切换 20 次。
- 代理启停 100 次。
- TUN 启停 50 次。
- 1000/2000 节点 profile。
- 无持续内存增长。
- 无 task/socket/session 泄漏。
- 无 DNS、route、proxy 残留。

### 21.4 文档

最终更新：

- 根 README。
- 中文 README。
- `Supercore/README.md`。
- protocol matrix。
- API/OpenAPI。
- TUN/DNS 说明。
- 隐私和本地数据说明。
- 故障恢复说明。
- benchmark。
- changelog。

README 只写最终功能、安装、使用、架构、协议状态和可复现验证。

### 21.5 发布

- 版本号。
- Developer ID 签名。
- hardened runtime。
- notarization。
- stapling。
- 使用已经确认的玥球电梯 DMG 背景和 Finder 布局。
- DMG 不包含订阅、profile、日志、缓存或 Token。
- 安装、覆盖升级、卸载、重装。
- 推送 GitHub。
- 创建 Release。
- 上传：
  - DMG
  - SHA256
  - 必要符号/调试文件
- README 放实际 Release 下载链接。

## 22. 固定提交批次

1. `Control: finish cancellable tasks and SSE events`
2. `Core: complete API runtime and outbound modularization`
3. `Network: complete shared TCP TLS transports and UDP`
4. `Protocols: complete SS SSR Snell Trojan VMess`
5. `Protocols: complete VLESS Reality Vision`
6. `Protocols: complete Hysteria2 TUIC WireGuard`
7. `Protocols: complete AnyTLS ShadowTLS Naive HTTP SOCKS SSH`
8. `Protocols: add Hysteria Mieru Juicity`
9. `Protocols: add MASQUE OpenVPN Sudoku`
10. `Protocols: add Tailscale TrustTunnel DNS Rematch`
11. `DNS: complete resolver policies cache and Fake-IP`
12. `TUN: complete privileged helper and network transactions`
13. `Probe: complete isolated probing and auto selection`
14. `Profiles: complete subscriptions providers and groups`
15. `Routing: complete smart rules and application routing`
16. `Telemetry: complete traffic connections logs and doctor`
17. `App: complete architecture and final interaction`
18. `Quality: complete performance security CI and governance`
19. `Release: ship signed notarized Yueqiu Elevator`

每个提交必须：

- 单一主题。
- 针对性测试通过。
- 对应文档同步。
- 无用户数据。
- 可独立回滚。

## 23. 测试节奏

遵循“先开发，阶段集中测试”：

- 小改动：只跑编译和相关模块测试。
- 一个协议或模块完成：跑该模块单元/集成测试。
- 一个提交批次完成：跑 Rust lib + 相关 integration，或 Swift 相关 suite。
- 一个 M 阶段完成：跑 Rust/Swift 全量 debug 测试。
- M2、M3、M5、M11、M12 阶段门：执行 release build。
- 完整 LTO 只在协议大门、质量门和最终发布门执行，不在每个小提交重复。

禁止：

- 永真断言。
- 只检查数组长度。
- 只检查 parser 就宣称拨号完成。
- 使用用户真实订阅作为仓库 fixture。
- 把外部网络偶发失败当唯一自动化证据。

## 24. 最终完成清单

- [x] M0：当前 task/SSE/progress 代码已收口并验证。
- [ ] M1：核心、API、transport、UDP 和 cancellation 基础完成。
- [ ] M2：当前 partial 协议全部完成真实拨号。
- [ ] M3：Mihomo 冻结基线缺失协议全部补齐。
- [ ] M4：DNS 和 Fake-IP 完成。
- [ ] M5：TUN、权限服务和网络恢复完成。
- [ ] M6：独立测速和自动择优完成。
- [ ] M7：订阅、Provider、代理组和本地数据完成。
- [ ] M8：规则、智能学习和 App/域名/IP 指定节点完成。
- [ ] M9：流量、连接、日志和 Doctor 完成。
- [ ] M10：macOS App 架构、UI 和交互完成。
- [ ] M11：性能、安全、质量、CI 和开源治理完成。
- [ ] M12：真实验收、签名、公证、DMG 和 GitHub Release 完成。

当以上 13 项全部达到 `VERIFIED`，本文档定义的 Skyhook 最终版开发任务结束。冻结日期之后新增的需求进入下一版本，不再反向修改本计划的完成结论。
