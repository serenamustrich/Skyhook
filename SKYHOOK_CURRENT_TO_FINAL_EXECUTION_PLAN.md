# Skyhook（玥球核心）从当前代码到最终版执行计划

> 项目根目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore`
>
> Rust 核心目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore`
>
> macOS App 目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Sources/YueqiuElevatorSupercore`
>
> 计划冻结日期：2026-07-17
>
> 本文档从当前真实代码断点开始，作为后续开发、验收和发布的唯一执行清单。旧计划保留作历史参考，但阶段状态和“是否完成”以本文档为准。

## 当前执行状态

- 阶段 A：`IMPLEMENTED`
  - `/v1` API、loopback 限制、Bearer Token、结构化错误和 Swift 客户端已完成。
  - 旧根路径与 `/supercore/*` 兼容入口已删除。
  - 普通核心使用每次启动随机 Token；TUN daemon 使用 root-only `0600` Token 文件。
  - 启动代理不再下载订阅；定时测速不再启动后立即运行。
  - Rust lib 78 passed，Swift full 91 passed。
  - 尚未进行需要管理员权限的 TUN daemon 实机鉴权验证，因此阶段 A 暂不标记
    `VERIFIED`。
- 阶段 B：`IN_PROGRESS`
  - DialContext、OutboundError、通用连接池和 UDP session pool 已进入工作区。
  - TCP、TLS、HTTP CONNECT、WebSocket、H2、gRPC、HTTPUpgrade 和 QUIC client config
    已拆成公共 transport。
  - Direct、Reject、HTTP、Naive、Group、Unsupported 和 registry 已拆成独立模块。
  - DialContext 已支持 cancellation token，并传播订阅、组、节点所需的上下文字段。
  - 其余协议模块、QUIC endpoint/session 公共层和 API task/event 仍待拆分。
- 阶段 C-K：`NOT_STARTED` 或沿用已有功能，尚未达到本文档的最终验收标准。

## 1. 最终交付定义

最终交付物是完全使用 Skyhook 的玥球电梯 macOS App，不包含 Mihomo 二进制、双核心、兼容回退或启动时下载第三方核心。

完成本文档全部阶段后，必须同时交付：

1. Rust-native Skyhook 核心。
2. 使用 Skyhook `/v1` API 的原生 macOS 菜单栏 App。
3. 可真实工作的系统代理模式和 TUN 虚拟网卡模式。
4. 多订阅、Provider、代理组、国家分组、节点选择、后台更新与本地缓存。
5. 未启动代理时也可工作的独立节点测速。
6. 原生智能规则、域名/IP/App 路由和指定节点能力。
7. 实时速率、累计流量、连接、规则命中、DNS、TUN 和错误诊断。
8. Rust/Swift 自动化测试、协议互操作测试、性能基线和 macOS 网络恢复测试。
9. 更新后的中英文 README、协议矩阵、API 文档和故障恢复文档。
10. 已签名、公证、可安装的 Apple Silicon DMG，以及 GitHub Release。

## 2. 完成边界

### 2.1 本计划内必须完成

- macOS 12 及以上、Apple Silicon。
- Skyhook 是唯一数据面核心。
- 当前配置模型中声明的全部协议必须达到本文规定的真实拨号状态。
- 系统代理和 TUN 均可使用已选节点正确上网。
- App 退出、崩溃、强杀、睡眠唤醒和网络切换后不得留下破坏联网的 DNS、路由或代理状态。
- 订阅 URL、节点凭据、私钥、控制 Token 和用户运行数据不得进入 Git 或 DMG。

### 2.2 本计划完成后不再反算为“未完成”

以下内容不属于本轮最终版范围，未来新增时作为新版本功能：

- Windows、Linux、iOS、Android 客户端。
- Intel Mac 或 Universal Binary；本轮最低交付是 Apple Silicon。
- 浏览器扩展、云同步、账号系统、付费系统。
- 计划冻结后才出现的新协议或第三方私有扩展。
- 未公开规范、无法取得合法测试端或无法独立验证的闭源协议变体。

## 3. 不可违反的实现规则

1. 不引入 Mihomo 二进制、双核心、运行时回退或 Mihomo API 兼容层。
2. 只参考公开规范、公开测试向量和网络行为，不复制其他项目受版权保护的实现。
3. “支持协议”必须代表真实拨号和双向传输，不得以 YAML/URI 能解析代替。
4. `parse-only`、`unsupported`、认证失败和网络超时必须是不同状态。
5. 启动代理只读取本地缓存和已选节点，不更新订阅、不全局测速。
6. 测速 runtime 不启用 TUN、不修改系统代理、不修改系统 DNS、不更新订阅。
7. 订阅下载默认优先走直连；只有用户明确配置后才允许走指定代理。
8. TUN/DNS 操作必须执行“快照、变更、验证、失败回滚、退出恢复”事务。
9. 所有控制 API 只监听 loopback 或 Unix domain socket，写操作必须鉴权。
10. 每批代码先完成实现和针对性测试，里程碑结束再跑全量测试；不在每个小改动后重复完整 LTO 构建。
11. 每次提交前更新 README、协议矩阵或对应文档，但 README 只写最终功能，不写开发过程。
12. 不删除或覆盖当前工作区中尚未提交的 M1 改动。

## 4. 当前真实基线

### 4.1 已完成并冻结

- M0 基线、安全修复和回归已完成。
- Rust 全量基线：263 passed、0 failed、1 ignored。
- Swift 全量基线：89 passed、0 failed。
- Rust 和 Swift release build 已通过。
- VMess alterId=0 的 TCP、UDP、WebSocket、gRPC、HTTP/2 已有真实拨号测试。
- Trojan 的 TCP、UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade 已有真实拨号测试。
- Shadowsocks 旧 AEAD、2022、SIP023、多用户、simple-obfs 和 WS 插件主要路径已实拨。
- SSR 已覆盖当前目标 auth/obfs/cipher、TCP/UDP 和多用户路径。
- Snell v1-v5 TCP、v3-v5 UDP、HTTP/TLS obfs 已实拨。
- Snell v4/v5 connection reuse、空闲淘汰、半关闭和陈旧连接重拨已完成。
- 多订阅、本地缓存、国家分组、代理组、流量和智能规则已有基础实现。

### 4.2 当前未提交的 M1 工作

当前工作区已经开始但尚未完成：

- `DialContext`。
- `OutboundError` 和错误分类。
- 通用 `IdlePool`。
- TCP/TLS transport 初步拆分。
- UDP resolver 和 round-robin session pool 初步拆分。
- `Outbound` 的 context-aware 调用。
- `/v1` 路由迁移。
- 控制 API loopback 限制。
- Swift 客户端 `/v1` 路径迁移。

这些改动必须先收口、测试并提交，不能回退。

### 4.3 当前主要结构债务

- `Supercore/src/outbound/mod.rs` 约 13,700 行。
- `Supercore/src/core/mod.rs` 约 2,100 行。
- `Supercore/src/api/mod.rs` 约 1,200 行。
- `AppState.swift` 约 2,850 行。
- `SettingsWindow.swift` 约 1,600 行。
- WebSocket、H2、gRPC、HTTPUpgrade、QUIC、UDP association 尚未全部成为独立公共模块。
- API 尚无最终鉴权、task id、SSE/WebSocket 进度和版本化 schema。
- Hysteria v1、Mieru、Juicity、MASQUE、OpenVPN 仍无法原生拨号。
- TUN/DNS 的真实 macOS 生命周期和异常恢复尚未完成最终验收。

## 5. 固定执行顺序

严格按以下顺序开发：

1. A：收口当前 M1 半成品。
2. B：完成核心模块化和 `/v1` 控制面。
3. C：完成所有协议真实拨号。
4. D：完成独立测速和自动择优。
5. E：完成 TUN、DNS、Fake-IP 和网络恢复。
6. F：完成订阅、Provider、代理组和本地数据。
7. G：完成智能规则和应用级路由。
8. H：完成流量、连接、日志和 Doctor。
9. I：完成 macOS App 架构、UI 和交互。
10. J：完成性能、质量、安全和开源治理。
11. K：完成最终验收、签名、公证、DMG 和 Release。

协议实现可以在独立模块中并行，但 D-K 不得绕过对应前置阶段进入“完成”。

---

## 6. 阶段 A：收口当前 M1 半成品

### A1. 保护当前工作区

- 审核当前 diff，确认只有已知 M1 文件。
- 补齐新增模块的 `mod` 导出和文档说明。
- 对新增 Rust 文件单独执行 `rustfmt --edition 2021`。
- 不执行会格式化全仓库的机械操作。

### A2. 控制 API 启动级 Token

Rust：

- App 启动核心时通过 `SKYHOOK_CONTROL_TOKEN` 传入每次启动随机 Token。
- Token 只保存在进程内存和子进程环境，不写 YAML、日志、UserDefaults 或订阅目录。
- `/v1/version` 可匿名读取，用于启动健康检查。
- 所有 `POST`、`PUT`、`PATCH`、`DELETE` 请求必须携带 `Authorization: Bearer <token>`。
- Token 比较使用固定时序比较。
- 无 Token、错误 Token 返回统一 `401` JSON 错误。
- 控制地址非 loopback 时直接拒绝启动。

Swift：

- `SupercoreManager.start` 每次生成 256-bit 随机 Token。
- 将 Token 注入核心进程环境，并同步设置到 `SupercoreAPIClient`。
- 所有 API 请求自动添加 Authorization header。
- 停止核心后清理内存中的 Token。
- 不在错误信息和调试日志中打印 Token。

测试：

- 正确 Token 可写。
- 缺失/错误 Token 被拒绝。
- `/v1/version` 在无 Token 时仍可做健康检查。
- Swift URLProtocol 测试验证 header 存在且值正确。

### A3. 结构化错误进入 API

- `OutboundErrorKind` 固定为稳定字符串，不把底层英文错误作为业务判断依据。
- API 错误统一包含：
  - `code`
  - `kind`
  - `message`
  - `retryable`
  - `trace_id`
  - `details`
- probe、订阅、reload、TUN 和路由写操作使用同一错误 schema。
- Swift 根据 `kind` 显示 DNS、TCP、TLS、认证、协议不支持、超时、取消等不同状态。

### A4. 当前改动验收

- `cargo check` 零 warning。
- Rust lib、API、UDP 和现有协议针对性测试通过。
- Swift `SupercoreAPIClientTests` 通过。
- 更新 `Supercore/README.md`、`README.zh-CN.md` 的 `/v1` API 说明。
- 创建一次独立提交，作为后续大规模模块拆分的回滚点。

**A 阶段完成标准：** 当前 M1 diff 全部进入一个可编译、可测试、可回滚的提交，API 写操作已完成鉴权。

---

## 7. 阶段 B：核心模块化和独立控制面

### B1. Outbound 目录拆分

目标结构：

```text
Supercore/src/outbound/
  mod.rs
  registry.rs
  capability.rs
  context.rs
  error.rs
  target.rs
  pool.rs
  direct.rs
  reject.rs
  http.rs
  socks5.rs
  ssh.rs
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
  mieru/
  juicity/
  masque/
  openvpn/
  transports/
  udp/
```

要求：

- `outbound/mod.rs` 最终只保留公共导出和 registry 入口。
- 每个协议独立持有 parser-to-runtime 构造、状态机和测试。
- capability 不通过字符串猜测，必须由协议实现显式返回。
- Unknown 协议只能返回 unsupported，不能伪装成 timeout。

### B2. 公共 Transport

分别实现并测试：

- TCP：DNS、Happy Eyeballs、connect timeout、keepalive、half-close。
- TLS：SNI、ALPN、证书校验、skip verify、session resumption。
- WebSocket：path、Host、headers、early data、ping/pong、close frame。
- HTTP/2：flow control、window update、half-close、RST、GOAWAY。
- gRPC：5 字节 framing、分片、连续 frame、trailers、取消。
- HTTPUpgrade：请求构造、101 校验、双向字节流。
- QUIC：连接池、stream、datagram、keepalive、MTU、关闭和错误映射。

公共 transport 不得包含具体协议认证逻辑。

### B3. 公共 UDP

- 单目标和多目标 association。
- 按节点、协议和目标隔离 session。
- NAT 映射与空闲回收。
- fragmentation/reassembly。
- replay window。
- endpoint-independent NAT 行为。
- bounded pool，不允许无限创建 socket/session。
- 每个请求具有 timeout、cancel 和 trace id。
- session 创建失败不能导致同批未执行节点被标记为超时。

### B4. DialContext

补齐字段：

- destination
- source
- app identity
- matched rule
- timeout
- cancellation token
- trace id
- subscription id
- selected group/node

所有 TCP、UDP、probe、TUN、系统代理流量使用同一上下文。

### B5. `/v1` API 最终结构

固定资源：

```text
/v1/version
/v1/status
/v1/outbounds
/v1/groups
/v1/countries
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
/v1/tasks
/v1/events
```

要求：

- 删除 Swift 对 `/supercore/*` 的依赖。
- 待 Swift 全部迁移后删除旧兼容写接口。
- 订阅更新、全量测速、Provider 更新等长任务立即返回 task id。
- `/v1/tasks/{id}` 返回状态、进度、结果和错误。
- `/v1/events` 使用 SSE 推送 task、流量、日志、连接和状态变化。
- 生成并提交 OpenAPI 或等价 JSON schema。
- 所有接口有版本、鉴权、分页、错误和向后兼容策略。

### B6. B 阶段验收

- `outbound/mod.rs` 不再承载协议实现。
- 公共 transport 与 UDP 层有独立 mock server 测试。
- 既有协议测试全部通过。
- API 鉴权、task、SSE、schema 测试通过。
- Swift 客户端只使用 `/v1`。

---

## 8. 阶段 C：协议真实拨号全部完成

### C0. 统一“完整支持”标准

每个协议只有同时满足以下条件才能标记 `full`：

1. YAML 解析。
2. URI 解析，协议存在标准 URI 时必须支持。
3. 字段校验和可读错误。
4. TCP 真实拨号，协议本身支持 TCP 时。
5. UDP 真实拨号，协议本身支持 UDP 时。
6. 所声明 transport 真实工作。
7. 上下行加密、认证、分帧和关闭行为正确。
8. 至少一个本地真实 mock server E2E。
9. 至少一个公开实现互操作或公开测试向量。
10. capability、README 和协议矩阵与代码一致。

协议本身不提供某能力时，矩阵写 `not-applicable`，不因协议边界误记为未完成。

### C1. 已完成协议回归

保持并加强：

- Direct / Reject / DNS。
- SOCKS5 TCP/UDP。
- Shadowsocks legacy AEAD 和 2022。
- ShadowsocksR。
- Snell v1-v5。
- Trojan。
- VMess alterId=0。

补充：

- 长连接。
- 半关闭。
- 取消。
- 错误密码。
- 错误服务端。
- 大包和分片。
- 连接池陈旧连接。
- 真实订阅字段组合。

VMess legacy alterId 只在公开规范和合法互操作证据充分时实现；否则 capability 明确限制，不能伪装 full。

### C2. VLESS、Reality、Vision

- VLESS TCP、UDP。
- WS、gRPC、H2、HTTPUpgrade。
- TLS 与无 TLS。
- Reality：
  - public key
  - short id
  - server name
  - fingerprint
  - spider/xver 等当前配置字段
- XTLS Vision：
  - flow 校验
  - padding
  - direct copy / splice 边界
  - TLS record 状态
- 正确处理 Reality 握手失败、Vision flow 不匹配和服务端拒绝。

### C3. QUIC 协议族

公共 QUIC 完成后实现：

- Hysteria v1：
  - auth
  - bandwidth
  - obfs
  - TCP stream
  - UDP
- Hysteria2：
  - auth
  - Salamander obfs
  - TCP
  - UDP
  - fragmentation
- TUIC v5：
  - UUID/password auth
  - TCP
  - UDP relay mode
  - congestion controller
  - keepalive
  - zero-RTT 策略

必须提供本地 QUIC/H3 server E2E，不能只测序列化后的字节长度。

### C4. WireGuard

- 完整字段校验。
- userspace handshake。
- IPv4/IPv6 address。
- allowed IP。
- persistent keepalive。
- DNS 与 MTU。
- TCP/UDP over tunnel。
- 多 peer。
- key 错误、counter/replay、rekey。

### C5. AnyTLS、ShadowTLS、Naive

AnyTLS：

- padding scheme。
- session ticket/resumption。
- TCP。
- 协议规定范围内的 UDP。
- 认证失败与流量分帧。

ShadowTLS：

- v3 handshake。
- password/auth。
- TLS camouflage。
- 与后端代理协议组合。
- 正确处理证书和握手错误。

Naive：

- HTTP/2 CONNECT。
- HTTP/3 CONNECT，若配置声明。
- Basic auth。
- padding。
- TCP。
- 协议支持范围内的 UDP/CONNECT-UDP。

### C6. HTTP、SOCKS5、SSH

- HTTP/HTTPS CONNECT、认证、IPv4/IPv6、非 200 错误。
- SOCKS5 TCP、UDP ASSOCIATE、用户名密码、域名与 IP。
- SSH host key policy、密码/私钥认证、TCP channel、keepalive、reconnect。
- 不宣称 SSH UDP，除非有明确标准和实现。

### C7. 当前 parse-only 协议

逐个完成：

- Mieru。
- Juicity。
- MASQUE。
- OpenVPN。

每个协议必须：

- 独立模块。
- 配置与订阅 parser。
- 参数校验。
- 原生真实拨号。
- TCP/UDP 按协议能力实现。
- 真实 mock server 或合法互操作环境。
- capability 与错误分类。

如果某协议缺少公开、可独立实现的规范，必须在本阶段明确形成技术阻断记录；不能把 placeholder 合并为正式支持。

### C8. 协议矩阵退出条件

- 配置枚举中不存在“可以导入但永远只能 UnsupportedProtocolOutbound”的正式协议。
- UI 不把 unsupported 显示为网络超时。
- 所有计划内协议有真实拨号证据。
- `protocol-matrix.md` 每一行可追溯到测试文件和测试名称。
- 所有协议测试统一通过后，C 阶段才可完成。

---

## 9. 阶段 D：独立测速和自动择优

### D1. 测速运行时

- 使用本地已缓存订阅建立临时 runtime。
- 强制关闭 TUN、DNS listen、系统代理修改和订阅更新。
- 不依赖主代理进程是否已启动。
- 使用真实节点协议拨号，不通过当前选中代理绕测。
- 测速完成后释放 socket、连接池、临时端口和任务。

### D2. 正确的测速语义

- 默认同一 HTTPS URL，记录 DNS、TCP、TLS、TTFB 和总耗时。
- 500ms 是单节点上限；超过 500ms 才标记 timeout。
- 每个节点必须真实进入调度并产生 started/finished 记录。
- 未调度、被取消、核心无此节点、协议不支持不能写成 timeout。
- HTTP 204/200 按测试目标配置判定成功。
- 支持 IPv4/IPv6 和域名解析失败分类。
- 同一轮结果包含 task id、节点名、trace id、开始时间和完成时间。

### D3. 并发调度

- 有界并发，默认值按机器核数和协议类型确定。
- TCP、TLS、QUIC 可使用不同并发上限。
- 不在持有全局锁时执行 DNS、connect 或 handshake。
- 单节点卡住不阻塞其他节点。
- 支持取消、重试和进度流。
- 500、1000、2000 节点压力测试。

### D4. 自动择优

- 用户可选择具体节点、代理组或国家。
- 选择代理组表示“按组策略择优”，点击代理组查看内容不自动切换。
- 选择国家后只在该国家内择优。
- 后台定时测速不切断现有连接，不阻塞前台网络。
- 启动代理先使用上次节点。
- 上次节点不可用时：
  1. 测试上次节点。
  2. 测试同组或同国家候选。
  3. 切换到可用最低延迟节点。
  4. 仍无可用节点时才扩大范围。
- 节点延迟颜色：
  - `<50ms` 绿色
  - `50-150ms` 蓝色
  - `>150ms` 红色
  - `>500ms` 超时

### D5. 与成熟客户端对比

固定同一机器、同一网络、同一订阅、同一 URL、同一 500ms 超时：

- 记录 Skyhook 与 Sparkle/Mihomo 的成功节点集合。
- Skyhook 可用率不得比对照低超过 5 个百分点。
- 共同成功节点的 median 延迟差异不超过 25% 或 30ms，取较大值。
- P90 延迟差异不超过 35%。
- 每个差异节点必须能看到失败阶段，不能只输出“超时”。

---

## 10. 阶段 E：TUN、DNS、Fake-IP 和网络恢复

### E1. 产品定义

- TUN 是虚拟网卡数据面，不是“虚拟 DNS”。
- DNS 是独立的名称解析子系统。
- UI 使用用户可理解的名称：
  - TUN 虚拟网卡
  - DNS 处理方式
  - Fake-IP
  - 远程 DNS
- 不再使用容易误解的“安装 TUN”按钮；改为“一次性安装 TUN 权限服务”。

### E2. 权限服务

- 使用受控 helper/daemon 创建和维护 TUN。
- 首次安装需要管理员授权，之后启动/停止不重复询问。
- daemon 只接受来自签名 App 的最小命令集。
- 不允许任意命令执行或任意文件路径。
- App、daemon、core 版本不匹配时给出可恢复错误。

### E3. 启动事务

依次执行：

1. 获取单实例锁。
2. 检查上次恢复 journal。
3. 保存系统代理、DNS、默认路由和相关 service 快照。
4. 启动核心监听。
5. 创建 TUN 虚拟网卡。
6. 设置地址和 MTU。
7. 添加必要路由和 bypass。
8. 启动 DNS。
9. 验证核心、DNS、路由、外网访问。
10. 事务提交。

任何一步失败必须逆序回滚。

### E4. 停止和恢复

- 停止接收新连接。
- 关闭 TUN 数据面。
- 删除 Skyhook 添加的路由。
- 恢复系统 DNS。
- 恢复系统代理。
- 删除临时文件和 journal。
- 正常退出、菜单退出、窗口关闭、SIGTERM、SIGINT 都执行恢复。
- 对 `kill -9` 使用下次启动恢复和独立 watchdog/daemon journal。
- App 不得只结束 UI 而留下 daemon/core 持续改写网络。

### E5. DNS 引擎

- 系统 resolver 发现：优先 `scutil --dns`，其次 `/etc/resolv.conf`。
- 排除核心自身 listen，防止 DNS 递归。
- 支持 UDP、TCP、DoT、DoH。
- 支持 fallback、nameserver-policy、rule-aware DNS。
- DNS cache 有 TTL、negative cache、并发请求合并和容量限制。
- bootstrap DNS 不依赖尚未建立的代理链。
- DNS over TCP 只表示 DNS 查询通过 TCP 发送，不修改系统网络协议。

### E6. Fake-IP

- 独立地址池。
- 域名到 Fake-IP 和反向映射持久化。
- blacklist、whitelist、rule filter。
- 命中 filter 时走真实 DNS，不返回 `0.0.0.0`。
- TTL、回收、冲突和容量限制。
- App 退出后不得留下不可解析的系统状态。

### E7. macOS 真实验收矩阵

至少覆盖：

- Wi-Fi。
- 有线网络或 USB 网络。
- 网络切换。
- 睡眠/唤醒。
- TUN 开关 50 次。
- App 正常退出。
- App Force Quit。
- core 崩溃。
- daemon 崩溃。
- `kill -9` App/core。
- 启动中取消。
- 无网络启动。
- DNS 服务不可达。
- 节点不可达。
- 多 network service。

每个场景结束后必须验证：

- 可直连访问互联网。
- 系统 DNS 正常。
- 默认路由正常。
- 系统代理没有残留。
- 无遗留 Skyhook TUN 设备或异常 daemon。

---

## 11. 阶段 F：订阅、Provider、代理组和本地数据

### F1. 订阅下载

- 默认直连。
- 15 秒连接超时、30 秒总超时，可配置。
- 支持 gzip、brotli、重定向、User-Agent 和常见订阅响应。
- 读取 `subscription-userinfo` 流量与到期时间。
- 下载失败保留旧缓存，不清空当前节点。
- 导入有进度、取消和明确失败阶段。
- 新增订阅时：
  - 已有当前订阅：只保存，不自动切换。
  - 没有任何订阅：自动设为当前订阅。

### F2. 本地 profile

每个订阅独立保存：

- id、名称、URL 的安全引用。
- 原始配置。
- 规范化配置。
- 节点和代理组。
- rule/provider 缓存。
- etag、last-modified、更新时间。
- 流量、限额、到期时间。
- 上次节点、组、国家和策略。
- 累计上传/下载流量。
- 自定义规则和智能规则。

URL 中的敏感 Token 使用 Keychain 或加密存储，日志和导出时脱敏。

### F3. 快速切换

- 切换订阅只切换本地已缓存数据。
- 未运行代理时不得联网。
- 运行中可原子热重载；失败继续使用旧 runtime。
- 1000 节点 profile UI 切换 P95 小于 150ms。
- 节点列表不能因分页或代理组解析错误而显示不全。

### F4. Provider

- Proxy Provider：HTTP、file、interval、health-check、缓存、原子更新。
- Rule Provider：domain、classical、ipcidr、text/yaml/mrs 等实际声明格式。
- Provider 下载与订阅下载相同，默认直连且失败保留旧缓存。
- 代理组和规则引用 provider 时，缓存未准备好必须返回明确状态。
- 后台更新不阻塞代理数据面。

### F5. 代理组

- select、url-test、fallback、load-balance、relay 等当前支持类型。
- 点击整个代理组区域都可进入组详情。
- 点击组只查看节点，不自动改变当前代理。
- 用户显式选择“使用该组择优”时才切换策略。
- 组成员、provider 成员和嵌套组自动展开且无循环。

---

## 12. 阶段 G：智能规则和应用级路由

### G1. 固定优先级

从高到低：

1. 用户指定 App + 域名/IP + 节点规则。
2. 用户自定义域名/IP/App 规则。
3. 用户启用的智能推荐。
4. 订阅规则。
5. 智能学习的未确认策略。
6. 默认策略。

### G2. 支持目标和动作

目标：

- DOMAIN
- DOMAIN-SUFFIX
- DOMAIN-KEYWORD
- IP-CIDR / IP-CIDR6
- GEOIP / GEOSITE
- PROCESS-NAME
- PROCESS-PATH
- BUNDLE-ID
- RULE-SET

动作：

- DIRECT
- REJECT
- 指定节点
- 指定代理组
- 指定国家择优

### G3. App 识别

- 从连接所属 PID 获取 executable path、process name、bundle id 和 code signing identity。
- 缓存 PID 映射并处理进程退出/PID 复用。
- TUN 流量无法直接归属 App 时明确标记 unknown，不猜测。
- App 规则在系统代理和可识别 TUN 流量中行为一致。

### G4. 智能学习

为首次或低置信目标记录：

- 域名/IP。
- App。
- 当前规则结果。
- 代理连接结果。
- 受控直连测试结果。
- DNS/TCP/TLS/HTTP 阶段。
- RTT、时间和网络环境。

推荐逻辑：

- 订阅规则走代理但直连持续成功：推荐直连。
- 订阅规则走直连但直连持续失败、代理持续成功：推荐代理。
- 单次失败不直接生成规则。
- 采用最小样本、时间衰减、失败惩罚和网络环境隔离。
- 学习测试限速、限并发，不影响正常代理。

### G5. 智能规则页面

- 顶部显示：
  - 订阅规则走代理但直连可达比例。
  - 推荐直连数量。
  - 推荐代理数量。
  - 已启用数量。
- 推荐直连和推荐代理分列表。
- 支持单条启用、批量启用、忽略、撤销和查看证据。
- 用户启用后立即写入高于订阅规则的持久规则。

---

## 13. 阶段 H：流量、连接、日志和 Doctor

### H1. 流量

- 当前上传/下载速率。
- 全局累计上传/下载。
- 按订阅累计。
- 按节点、代理组、规则、App 统计。
- 使用 64-bit counter。
- 进程重启、App 退出、订阅切换不清零。
- 原子持久化，避免重复累计和崩溃丢失。
- 速率使用固定采样窗口和单调计数器差值，不能长期显示 0。

### H2. 连接表

- id、开始时间、来源、目标、App。
- 匹配规则、订阅、代理组、节点。
- 上传/下载字节、当前速率。
- DNS/TCP/TLS/协议阶段。
- 支持按 App、域名、节点和规则筛选。
- 支持关闭单个连接。
- 已关闭连接保留短期历史，不无限增长。

### H3. 日志

- 最新日志在最上方。
- 分类：
  - 核心
  - 代理
  - 直连
  - 规则
  - DNS
  - TUN
  - 订阅
  - 测速
- 结构化字段包含 trace id、task id、subscription id、node、rule、error kind。
- 敏感字段统一脱敏。
- 环形缓冲、分页和导出诊断包。

### H4. Doctor

输出：

- App/core/daemon 版本。
- 协议 capability。
- control API 鉴权状态。
- 端口占用。
- 当前订阅和节点。
- 系统代理。
- TUN 设备。
- 路由。
- 系统 DNS 和 Skyhook DNS。
- journal/快照是否残留。
- 最近失败分类。
- 恢复建议和可执行的一键恢复动作。

---

## 14. 阶段 I：macOS App 架构、UI 和交互

### I1. 状态架构

拆分 `AppState.swift`：

- CoreCoordinator。
- SubscriptionStore/Coordinator。
- ProbeCoordinator。
- NetworkModeCoordinator。
- TrafficStore。
- SmartRuleCoordinator。
- LogStore。
- UI ViewModel。

要求：

- 后台任务不在 MainActor 做网络和解析。
- UI 更新合并、节流。
- 任务可取消。
- App 生命周期只有一个核心所有者。

### I2. 页面拆分

拆分 `SettingsWindow.swift`：

- Dashboard。
- Subscriptions。
- Nodes。
- Smart Rules。
- Custom Rules。
- Connections。
- Logs。
- Network/TUN。
- General。

每个页面独立文件和 ViewModel，不继续扩大单文件。

### I3. 全局交互

- 启动/停止只有一个状态按钮。
- 清楚显示：
  - 当前订阅
  - 当前节点或组策略
  - 延迟
  - 系统代理/TUN 状态
  - 实时速率
  - 累计流量
- 菜单栏双击打开主窗口。
- 所有长任务有进度、取消、成功和失败状态。
- 任何网络操作都不能只闪一下页面。

### I4. 节点页

- 代理组整行可点击。
- 选中节点使用清晰、克制且完整的高亮样式。
- 国家使用可滚动网格，不重复提供下拉框。
- 支持搜索、国家、协议、可用性、延迟筛选。
- 支持：
  - 测速可用节点
  - 测速所有节点
  - 测试当前组
  - 组内择优
  - 国家内择优
- 1000+ 节点使用懒加载/虚拟列表，不一次创建所有复杂 View。
- 未返回结果的节点保留原状态，不能自动写超时。

### I5. 订阅页

- 显示流量、限额、到期时间、节点数、更新时间和更新状态。
- 多订阅保存、选择、切换、重命名和删除。
- 更新按钮更新全部订阅。
- 单个订阅提供独立更新入口。
- 导入 URL 输入框支持 Command-V、Command-A、Command-C。
- 切换本地缓存时不显示下载动画。

### I6. TUN 页面

- 解释“TUN 虚拟网卡”和“DNS 处理方式”的关系。
- 权限服务安装、状态、版本和卸载分开显示。
- 危险操作有确认，但启动/停止代理不重复索要密码。
- 提供一键恢复网络。
- App 退出时明确展示恢复结果，不静默留下 daemon。

### I7. UI 验收

- 1440x900、1280x800 和最小窗口。
- 长中文、长英文、emoji 节点名。
- 1000、2000 节点。
- 键盘导航、VoiceOver label、对比度和焦点。
- 无文字截断、控件重叠和滚动死区。

---

## 15. 阶段 J：性能、质量、安全和开源治理

### J1. Benchmark

Rust benchmark：

- 规则匹配。
- DNS cache。
- Fake-IP 分配。
- SS/SSR/Snell/VMess/VLESS/Trojan 加解密和 framing。
- UDP fragmentation/reassembly。
- 订阅解析。
- 1000 节点 runtime 构建。
- 1000 节点 probe 调度。

App benchmark：

- profile 切换。
- 节点筛选和排序。
- 日志追加。
- 流量刷新。
- 页面首次渲染。

### J2. 性能目标

- 空闲核心 CPU P95 小于 1% 单核。
- 空闲 App CPU P95 小于 1%。
- 1000 节点常驻 App + core 内存目标小于 250MB。
- 本地 profile 切换 P95 小于 150ms。
- 普通系统代理启动 P95 小于 2 秒。
- 已安装权限服务后的 TUN 启动 P95 小于 3 秒。
- 日志、连接和流量数据结构全部有容量上限。
- 数据面不得被订阅更新、测速或持久化 I/O 长时间阻塞。

### J3. 代码质量

- `cargo fmt --check`。
- `cargo clippy --all-targets --all-features -- -D warnings`。
- `cargo test --all-targets`。
- `swift test`。
- Rust/Swift release build。
- 零未知 ignored test。
- 禁止业务路径 `unwrap()`/`expect()` 导致崩溃。
- 删除死代码、临时兼容入口和无效 feature。

### J4. 安全

- 控制 API loopback/UDS + Token。
- helper 最小权限和调用方验证。
- 路径穿越、SSRF、订阅重定向和恶意 YAML 限制。
- 配置、订阅和 provider 大小上限。
- 节点名称、日志和 UI 文本安全处理。
- Keychain 存储敏感 URL/凭据引用。
- secret scan：
  - 订阅 URL
  - UUID/password
  - private key
  - bearer token
  - 用户 profile
- 依赖许可证和已知漏洞审计。

### J5. 开源治理

- 完成 clean-room provenance 记录。
- 确认第三方依赖和 vendored 文件许可证。
- 将 Rust core 的 `Proprietary` 改为最终选定的开源许可证前，先完成法务和来源审计。
- 推荐目标许可证：Apache-2.0 OR MIT；最终以审计结果为准。
- README 不使用无法证实的“全面超过”表述，功能和 benchmark 必须可复现。
- 仓库添加：
  - LICENSE
  - CONTRIBUTING
  - SECURITY
  - CODE_OF_CONDUCT
  - issue/PR templates
  - CI

---

## 16. 阶段 K：最终验收和发布

### K1. 自动化门禁

必须全部通过：

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

另需：

- API schema test。
- 协议矩阵一致性 test。
- secret scan。
- DMG 内容 scan。
- release binary smoke test。

### K2. 真实功能验收

使用至少两套真实订阅：

- 导入、保存、重启恢复。
- 切换不联网。
- 更新全部订阅。
- 流量和到期时间显示。
- 所有节点完整显示。
- 未启动代理测速。
- 500ms 正确超时。
- 选择具体节点后启动直接使用。
- 选择代理组后按组择优。
- 上次节点恢复和同地区 fallback。
- 系统代理上网。
- TUN 上网。
- 域名/IP/App 指定节点。
- 智能规则推荐、启用和撤销。
- 实时速率和累计流量。
- 退出和异常恢复网络。

### K3. 长稳

- 系统代理 24 小时。
- TUN 24 小时。
- 后台测速与订阅更新同时运行。
- 睡眠/唤醒 20 次。
- 网络切换 20 次。
- 启停代理 100 次。
- TUN 启停 50 次。
- 1000+ 节点 profile。
- 无持续内存增长、任务泄漏、socket 泄漏和 DNS/路由残留。

### K4. 文档

更新：

- 根 README。
- 中文 README。
- `Supercore/README.md`。
- 协议矩阵。
- API 文档。
- TUN/DNS 说明。
- 隐私和数据存储说明。
- 故障恢复说明。

README 只写功能、安装、使用、架构、协议状态和可复现测试，不写开发过程或未来计划。

### K5. 发布

- 版本号和 changelog。
- Apple Developer ID 签名。
- hardened runtime。
- notarization。
- stapling。
- 使用已经确认的玥球电梯 DMG 背景和 Finder 布局。
- DMG 不包含用户订阅、运行 profile、日志或 Token。
- 安装、覆盖升级、卸载和重新安装测试。
- GitHub 推送源码。
- 创建 GitHub Release。
- 上传 DMG、checksum 和必要符号文件。
- README 放置实际 Release 下载链接。

---

## 17. 提交批次

建议固定为以下可回滚提交：

1. `M1-A: secure versioned control API`
2. `M1-B: split transport and UDP infrastructure`
3. `M1-C: add task and event control plane`
4. `Protocols-A: complete VLESS Reality Vision`
5. `Protocols-B: complete QUIC protocol family`
6. `Protocols-C: complete WireGuard and TLS tunnel family`
7. `Protocols-D: complete remaining native outbounds`
8. `Probe: complete independent probing and auto selection`
9. `Network: complete transactional TUN DNS recovery`
10. `Profiles: complete subscriptions providers and groups`
11. `Routing: complete smart and application routing`
12. `Observability: complete traffic connections logs doctor`
13. `App: complete state architecture and final UI`
14. `Quality: complete performance security and CI`
15. `Release: ship signed notarized DMG`

每个提交：

- 只包含一个主题。
- 更新对应文档。
- 不包含用户数据。
- 有针对性测试证据。
- 在进入下一批前可独立回滚。

## 18. 状态规则

每个阶段只能使用：

- `NOT_STARTED`
- `IN_PROGRESS`
- `BLOCKED`
- `IMPLEMENTED`
- `VERIFIED`

含义：

- `IMPLEMENTED`：代码已写完，针对性测试通过。
- `VERIFIED`：全量测试、真实功能和阶段验收全部通过。
- 只有 `VERIFIED` 才算完成。

不得因为以下情况标记完成：

- 能编译。
- 能解析配置。
- 单元测试只检查数组长度。
- 使用 mock 绕过真实握手。
- UI 有按钮但后端没有行为。
- 手动测试一次成功。
- README 已写但代码未实现。

## 19. 最终完成检查表

以下项目全部勾选后，Skyhook 最终版才算完成：

- [ ] A：当前 M1 半成品已安全收口。
- [ ] B：核心模块化和 `/v1` 控制面完成。
- [ ] C：计划内协议均完成真实拨号。
- [ ] D：独立测速与自动择优通过对比验收。
- [ ] E：TUN/DNS/Fake-IP 和异常恢复通过 macOS 矩阵。
- [ ] F：多订阅、Provider、代理组和本地缓存完成。
- [ ] G：智能规则、App 路由和指定节点完成。
- [ ] H：流量、连接、日志和 Doctor 准确。
- [ ] I：App 架构、UI、交互和大数据性能完成。
- [ ] J：性能、质量、安全和开源治理完成。
- [ ] K：签名、公证、DMG 和 GitHub Release 完成。

当这 11 项全部达到 `VERIFIED`，本文档定义的开发任务结束。之后新增的协议、平台或产品功能进入下一版本计划，不再修改本计划的完成结论。
