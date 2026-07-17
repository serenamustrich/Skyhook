# 玥球电梯 Supercore 客户端（中文说明）

这是一个面向 `YueqiuElevatorSupercore` 的 macOS 桌面客户端与 Rust-native 核心组合，客户端不再调用外部核心，所有代理运行由仓库内的 `Supercore` 提供。

## 功能

- 节点配置：支持常见 Clash 风格的订阅与本地 YAML 配置。
- 协议支持按能力等级声明（full / partial / parse-only / unsupported）：
  - 协议能力基线来源：`Supercore/docs/protocol-matrix.md`
  - 仅当 matrix 标注为 `full` 时，才对外宣称“完整可用”。
  - `partial` / `parse-only` / `unsupported` 仅作功能边界说明，不作为“完整支持”承诺。
- full：Shadowsocks、ShadowsocksR、Snell、Trojan、VMess、SOCKS5。其他协议按具体路径提供能力，但尚未满足整个协议标记为 full 的证据标准。
- partial：VLESS、Hysteria2、TUIC、WireGuard（用户态）、AnyTLS、ShadowTLS、Naive、HTTP、SSH。
- Trojan 支持 TLS+TCP、UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、自定义请求头、ALPN 和 UDP over WS/gRPC，并处理 gRPC trailer、HTTPUpgrade 状态、半关闭、UDP 隧道复用、超时会话淘汰与 8192 字节 UDP 兼容边界。VMess 支持 AEAD 与 legacy alterId、TCP/UDP、WebSocket、gRPC、HTTP/2、HTTP camouflage、HTTPUpgrade、自定义请求头和 ALPN，并覆盖多帧长连接、认证 EOF、多目的 UDP、错误认证及超时会话恢复；XHTTP 会在拨号前明确返回不支持。
- Shadowsocks 支持 legacy stream、stream、AEAD、扩展 AEAD 与 Shadowsocks 2022 方法，完成 TCP/UDP 双向真实拨号、SIP022/SIP023 多用户 EIH、重放保护、simple-obfs HTTP/TLS、v2ray-plugin WebSocket/TLS 和 UoT v1/v2；SIP003 TCP plugin 的 UDP 通过 UoT 承载。
- ShadowsocksR 覆盖 `none/dummy`、AES-CTR/CFB、RC4-MD5、ChaCha20/IETF、XChaCha20 共 11 种 stream cipher，支持 origin、verify/auth、auth_aes、auth_chain a-f、TCP/UDP、多用户、random_head、HTTP simple/post 与 TLS ticket auth/fastauth；auth_sha1_v4 的 UDP 是协议自身不适用边界。
- Snell 默认使用 v1，支持 v1-v5 TCP、独立响应 salt、HTTP/TLS 混淆和 v3-v5 UDP-over-TCP；v5 使用公开的 v4 兼容 wire format，v4/v5 支持 `reuse: true`、10 条连接池、15 秒空闲淘汰、零帧半关闭、并发流和陈旧连接自动重拨；空 PSK 会在拨号前拒绝，v1/v2 UDP 是协议本身的明确边界。
- parse-only：Hysteria v1、Mieru、Juicity、MASQUE、OpenVPN。
- 订阅能力：支持多订阅导入、切换、更新、缓存、生命周期计量。
- 规则能力：支持主要规则目标与 RULE-SET 规则源。
- 启动行为：启动/运行 `Supercore`，支持 TUN 与本地 DNS 策略（含 Virtual/Direct/over-tcp）。
- Probe 接口：支持按全部节点、按组进行可配置延迟探测。
- 智能规则：支持观察数据采集、推荐写回与规则持久化。

TUN 后端当前实际支持范围见 `Supercore/docs/tun-capabilities.md`。未实现的高级 TUN 字段会明确返回错误，不会静默假装生效。

## 协议能力状态（简表）

按当前实现与能力快照口径：

- **full**：常见路径可解析、可拨号、可传输，具备可复用实现与已知稳定性。
- **partial**：解析与基本拨号可用，但有明显功能缺口（如 UDP、参数、transport 或边界行为）。
- **parse-only**：能识别配置，但 Native 拨号未完全落地。
- **unsupported**：解析路径已禁止或不支持。

当前以 `Supercore/docs/protocol-matrix.md` 为准；不对外宣称未验证的 `full`。

## Control API 约定

客户端与核心使用独立版本化 HTTP 控制接口（`/v1/*`）：

- `GET /v1/status`
- `GET /v1/outbounds`
- `POST /v1/outbounds/use`
- `GET /v1/groups`
- `GET /v1/countries`
- `POST /v1/probes`
- `POST /v1/probes/group`
- `GET /v1/rules`
- `GET /v1/providers/proxies`
- `GET /v1/providers/rules`
- `GET /v1/subscriptions`
- `POST /v1/subscriptions/use`
- `POST /v1/subscriptions/import`
- `POST /v1/subscriptions/reload-active`
- `POST /v1/subscriptions/update`
- `POST /v1/subscriptions/update-all`
- `POST /v1/subscriptions/active-config`
- `POST /v1/providers/update`
- `POST /v1/providers/update-all`
- `GET /v1/traffic/subscriptions`
- `GET /v1/smart-rules`
- `GET /v1/smart-rules/rules`
- `GET /v1/smart-rules/observations`
- `GET /v1/smart-rules/recommendations`
- `POST /v1/smart-rules`
- `GET /v1/tun`
- `GET /v1/doctor`
- `POST /v1/doctor/run`
- `POST /v1/diagnostics/export`
- `POST /v1/geo/update`
- `GET /v1/tasks`
- `GET /v1/tasks/{id}`
- `POST /v1/tasks/{id}/cancel`
- `GET /v1/events`

控制接口只允许监听本机 loopback。读取接口可直接访问，所有写操作必须携带
`Authorization: Bearer <token>`。普通核心进程每次启动使用新的 256-bit Token；TUN
LaunchDaemon 从 root-only `0600` 文件读取 Token，plist 中不保存明文凭据。

列表接口统一支持 `limit`（默认 200，最大 500）、不透明 `cursor`、不区分大小写的
`filter`、接口允许的 `sort` 字段和 `order=asc|desc`。响应中的 `pagination` 返回本页数量、
筛选后总数、下一页游标和实际排序条件。游标与原筛选/排序条件绑定；锚点失效时接口会
明确返回 stale-cursor 错误。该约定覆盖节点、代理组、国家、订阅、Provider、规则、
智能规则明细、订阅流量、连接、日志和任务列表。

`GET /v1/smart-rules` 返回轻量统计摘要；规则、观察记录和推荐列表分别从
`/v1/smart-rules/rules`、`/v1/smart-rules/observations` 和
`/v1/smart-rules/recommendations` 分页读取。

`POST /v1/probes/group` 使用 JSON body 传递 `group`，避免路径二次编码问题，支持包含 `/`、中文、emoji 的组名。

全量测速、代理组测速、订阅导入、单订阅/全部订阅更新、Provider 更新、Geo 更新、
Doctor 深检和诊断导出使用异步任务模型。写请求会先返回
HTTP `202` 和 `task_id`，客户端随后读取 `/v1/tasks/{id}` 获取真实进度、结果和结构化
错误，并可通过 `/v1/tasks/{id}/cancel` 取消底层操作。任务记录有界保留，终态默认
保留 24 小时且最多 512 条。`/v1/events` 通过 SSE 推送带版本、事件 ID 和时间戳的
task、测速进度、运行状态、订阅更新、连接、流量、日志和节点健康事件。连接更新与
流量采样默认按 250ms 节流，事件通道有界，不会因为慢客户端阻塞代理数据面。
macOS App 默认使用 SSE 驱动实时速率、增量日志和任务进度；断线时自动退回
1 秒流量/2 秒日志轮询，重连后先拉取完整快照，再关闭轮询兜底。

订阅、Proxy Provider、Rule Provider 和 Geo 数据下载默认使用直连 HTTP 客户端，不
继承系统代理。下载支持实际取消和响应大小上限，任务结果只显示来源主机，不返回
可能包含 Token 的完整 URL。Provider 刷新失败时优先继续使用缓存或上次规范化数据。
诊断导出默认不包含订阅 URL、节点凭据、节点名称、原始日志或连接目标，文件权限为
`0600`，并在受控数据目录内有界保留。

启动代理只加载本地订阅缓存，不在启动过程中下载订阅或立即执行全局测速。后台订阅更新和定时测速在各自间隔到期后独立执行。

## 运行提示

- 源码构建后使用仓库内的启动脚本和脚本目录进行启动。
