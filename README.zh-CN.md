# 玥球电梯 Supercore 客户端（中文说明）

这是一个面向 `YueqiuElevatorSupercore` 的 macOS 桌面客户端与 Rust-native 核心组合，客户端不再调用外部核心，所有代理运行由仓库内的 `Supercore` 提供。

## 下载

[下载玥球电梯 v0.2.0 DMG](https://github.com/serenamustrich/Skyhook/releases/download/v0.2.0/YueqiuElevator-v0.2.0-e331d7f.dmg)

## 功能

- 节点配置：支持常见 Clash 风格的订阅与本地 YAML 配置。
- 协议支持按能力等级声明（full / partial / parse-only / unsupported）：
  - 协议能力基线来源：`Supercore/docs/protocol-matrix.md`
  - 仅当 matrix 标注为 `full` 时，才对外宣称“完整可用”。
  - `partial` / `parse-only` / `unsupported` 仅作功能边界说明，不作为“完整支持”承诺。
- full：Shadowsocks、ShadowsocksR、Snell、Trojan、VMess、VLESS、Hysteria v1、Hysteria2、TUIC、WireGuard、AnyTLS、ShadowTLS、Naive、Mieru、Juicity、MASQUE、OpenVPN、Sudoku、TrustTunnel、Tailscale、DNS outbound、Rematch、HTTP、SOCKS5、SSH。具体平台、账号和外部服务端互操作边界以协议矩阵为准。
- Trojan 支持 TLS+TCP、UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、自定义请求头、ALPN 和 UDP over WS/gRPC，并处理 gRPC trailer、HTTPUpgrade 状态、半关闭、UDP 隧道复用、超时会话淘汰与 8192 字节 UDP 兼容边界。VMess 支持 AEAD 与 legacy alterId、TCP/UDP、WebSocket、gRPC、HTTP/2、HTTP camouflage、HTTPUpgrade、自定义请求头和 ALPN，并覆盖多帧长连接、认证 EOF、多目的 UDP、错误认证及超时会话恢复；XHTTP 会在拨号前明确返回不支持。
- Shadowsocks 支持 legacy stream、stream、AEAD、扩展 AEAD 与 Shadowsocks 2022 方法，完成 TCP/UDP 双向真实拨号、SIP022/SIP023 多用户 EIH、重放保护、simple-obfs HTTP/TLS、v2ray-plugin WebSocket/TLS 和 UoT v1/v2；SIP003 TCP plugin 的 UDP 通过 UoT 承载。
- ShadowsocksR 覆盖 `none/dummy`、AES-CTR/CFB、RC4-MD5、ChaCha20/IETF、XChaCha20 共 11 种 stream cipher，支持 origin、verify/auth、auth_aes、auth_chain a-f、TCP/UDP、多用户、random_head、HTTP simple/post 与 TLS ticket auth/fastauth；auth_sha1_v4 的 UDP 是协议自身不适用边界。
- Snell 默认使用 v1，支持 v1-v5 TCP、独立响应 salt、HTTP/TLS 混淆和 v3-v5 UDP-over-TCP；v5 使用公开的 v4 兼容 wire format，v4/v5 支持 `reuse: true`、10 条连接池、15 秒空闲淘汰、零帧半关闭、并发流和陈旧连接自动重拨；空 PSK 会在拨号前拒绝，v1/v2 UDP 是协议本身的明确边界。
- VLESS 支持 TCP/command-UDP、TLS/无 TLS、WebSocket、gRPC、HTTP/2、HTTP camouflage、HTTPUpgrade、自定义请求头和 ALPN。Reality 实现 X25519/HKDF/AES-GCM ClientHello 认证、short ID、时间戳、临时证书 HMAC 校验和 fingerprint profile；Vision 实现双向 padding、TLS 1.3 ServerHello 判定和独立 direct copy 切换。
- Hysteria v1 支持官方 v3 wire、auth/auth-str、上下行带宽协商、速率感知拥塞控制、TCP、QUIC datagram UDP、分片重组、单飞连接初始化、UDP 会话复用、fast-open、xplus 与 wechat-video；TCP/UDP 已与官方 hy1 服务端互通。`faketcp` 在 macOS 上属于明确的平台不适用边界。
- Hysteria2 支持严格 HTTP/3 认证、TCP、QUIC datagram UDP、分片重组、连接/会话复用、上下行带宽协商、速率感知拥塞控制，以及 Salamander/Gecko 混淆；普通、Salamander 和 Gecko 路径均有本地真实 QUIC 服务端往返验证。
- TUIC v5 支持 TLS exporter UUID/password 认证、TCP、native datagram 与 QUIC 单向流 UDP、分片重组、并发 association 隔离、心跳、Dissociate、最大包配置和 TLS 会话恢复。恢复握手确认前不发送认证或业务数据，避免 0-RTT 重放风险。
- WireGuard 使用 BoringTun 与用户态 TCP/IP 栈，支持 IPv4/IPv6、TCP/UDP、隧道内 DNS、MTU、reserved、pre-shared key、persistent keepalive、多 Peer 和 allowed IP 最长前缀路由。
- AnyTLS v2 支持 TLS 认证、官方 padding 与服务端动态更新、会话复用和空闲回收、SYNACK、心跳、TCP 与 sing-box UoT v2 UDP；独立 TLS 服务端测试覆盖 96KB 数据、多路流、UDP 与会话复用。
- ShadowTLS v3 支持 TLS 1.3 ClientHello HMAC 认证、握手 ApplicationData 校验与还原、TLS camouflage、HelloRetryRequest、证书/密码错误边界、独立 SOCKS5 backend 和 Shadowsocks `shadow-tls` 插件组合；协议原生为 TCP transport，Shadowsocks UDP 由 UoT 承载。
- Naive 支持 HTTP/2 CONNECT、显式 HTTP/3 CONNECT 和 HTTP/1.1 兼容路径，完整发送 Basic Auth、官方 16-32 字节非索引请求头 padding 与双向前 8 帧 payload padding；支持 H2/H3 连接复用、IPv6 目标和明确的 407/证书/状态错误。NaiveProxy 原生只隧道化 TCP 流，CONNECT-UDP 为协议不适用边界。
- Mieru v3 支持 TCP/UDP underlay、用户名密码认证、XChaCha20-Poly1305、标准/no-wait 握手、多路复用、随机 padding、MTU 分片、可靠 UDP 重传与拥塞控制、TCP 和 SOCKS5 UDP ASSOCIATE；支持官方简单/完整分享格式、固定端口与 `port-range`，并已与官方 `mita` 服务端完成 TCP/UDP 和丢包乱序互通。
- Juicity v0 支持 UUID/password TLS exporter 鉴权、原生 QUIC TCP、可靠 UDP stream relay、BBR/Cubic/NewReno、keepalive、连接与 UDP 会话复用、断线重建和官方证书链 SHA-256 pin；本地真实 QUIC 与官方 v0.5.0 服务端均已验证 TCP/UDP 和错误鉴权。
- MASQUE 支持 Cloudflare Access HTTP/3/HTTP/2 CONNECT-IP、HTTP/3 L4 CONNECT 和 RFC 9298 CONNECT-UDP；实现 ECDSA mTLS、服务端 SPKI pin、用户态 IPv4/IPv6 TCP/UDP、远端 DNS、标准与旧版 H3 datagram setting、capsule、flow/context ID、URI template、会话池、QUIC keepalive、BBR/Cubic/NewReno、CWND profile 和握手超时。本地真实 H2/H3 服务端覆盖 TCP/UDP、错误公钥拒绝和三种隧道模式。
- OpenVPN 使用自研 TLS control/data channel，支持 TCP、UDP、服务端 push route/DNS、重连和用户态 L3 relay，不启动外部 OpenVPN 进程。
- Sudoku 支持 KIP 握手、AEAD、纯 Sudoku/6-bit packed 下行、UoT UDP、ASCII/entropy/custom table、custom_tables 轮换，以及 legacy/stream/poll/auto/WebSocket HTTP 伪装。
- TrustTunnel 支持 TLS+HTTP/2、QUIC/HTTP3 extended CONNECT、Basic 认证、TCP relay 与
  `_udp2` UDP 帧，并有本地 H2/H3 TCP 及 H3 `_udp2` 双向拨号回环验证。
- Tailscale 使用独立 Rust userspace，支持持久化 identity/control state、auth key、hostname、tags、TCP 和 UDP，不调用系统 Tailscale 进程、不修改主机路由。
- DNS outbound 支持 raw DNS 的 UDP、TCP、DoT 和 DoH；Rematch 支持带命名上下文的规则重新匹配、循环检测和最大深度保护。外部 DoT 验证脚本支持隔离本地监听端口，不依赖默认混合端口。
- HTTP 代理支持 HTTP/HTTPS CONNECT、Basic Auth、SNI、证书校验、IPv4/IPv6 目标、非 2xx 错误分类和握手后预读数据保留；HTTP CONNECT 原生仅承载 TCP。
- SOCKS5 支持无认证与用户名密码认证、域名/IPv4/IPv6 TCP CONNECT、UDP ASSOCIATE、响应来源校验和有界会话池复用。
- SSH 支持固定主机公钥或 SHA-256 指纹、主机密钥算法约束、密码/内联或文件私钥认证、keepalive、并发 direct-tcpip 通道共享物理会话和断线自动重连；SSH 没有标准 UDP relay。
- `faketcp` 依赖平台级 packet backend，在 macOS 上由相关协议明确拒绝，不静默退化为 TCP。
- 订阅能力：支持多订阅导入、切换、更新、缓存、生命周期计量。
- 规则能力：支持主要规则目标与 RULE-SET 规则源。
- 启动行为：启动/运行 `Supercore`，支持 TUN 与本地 DNS 策略（含 Virtual/Direct/over-tcp）；已安装但未加载的 TUN 权限服务不会让普通代理启动触发管理员授权，只有启用 TUN 或复用已运行的 daemon 时才接入。
- App 只接入本地受管理的 Supercore 进程或已加载的 TUN LaunchDaemon，不会因为端口相同而接入无关核心。
- TUN 生命周期测试会记录虚拟网卡、路由、DNS 和系统代理快照，并用本次测试 Token 确认控制的是自己的核心；矩阵默认使用隔离的 mixed/control 端口，动态启停已验证，完整管理员矩阵仍需显式授权后执行，核心停止会使用有界等待并在超时后强制清理。
- Probe 接口：支持按全部节点、按组进行可配置延迟探测。
- 智能规则：支持观察数据采集、推荐写回与规则持久化。

TUN 后端当前实际支持范围见 `Supercore/docs/tun-capabilities.md`。未实现的高级 TUN 字段会明确返回错误，不会静默假装生效。真实 TUN 生命周期矩阵是单独的运维测试，只有显式执行 `Scripts/tun_macos_matrix.sh --with-tun --root` 才需要管理员授权；应用启动和普通测速不会触发该授权。

正式运行默认使用本机 9197 控制端口；隔离测试可通过 `SKYHOOK_TEST_CONTROL_PORT` 指定测试端口，不会改变正式 App 的默认配置。

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
- 稳定性脚本和 TUN 矩阵在正常退出或中断时都会清理自己启动的 Supercore 子进程；稳定性脚本默认使用隔离的 mixed/control 端口，避免误连其他核心，不会修改用户订阅数据。
