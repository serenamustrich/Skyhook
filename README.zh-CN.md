# 玥球电梯 Supercore 客户端（中文说明）

这是一个面向 `YueqiuElevatorSupercore` 的 macOS 桌面客户端与 Rust-native 核心组合，客户端不再调用外部核心，所有代理运行由仓库内的 `Supercore` 提供。

## 已确认能力

- 节点配置：支持常见 Clash 风格的订阅与本地 YAML 配置。
- 协议支持按能力等级声明（full / partial / parse-only / unsupported）：
  - 协议能力基线来源：`Supercore/docs/protocol-matrix.md`
  - 仅当 matrix 标注为 `full` 时，才对外宣称“完整可用”。
  - `partial` / `parse-only` / `unsupported` 仅作功能边界说明，不作为“完整支持”承诺。
- full：SOCKS5。其他协议按具体路径提供能力，但尚未满足整个协议标记为 full 的证据标准。
- partial：Shadowsocks、ShadowsocksR、Trojan、VMess、VLESS、Hysteria2、TUIC、Snell、WireGuard（用户态）、AnyTLS、ShadowTLS、Naive、HTTP、SSH。
- Trojan 已完成 TLS+TCP、UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、自定义请求头、显式 ALPN、UDP over WS/gRPC 真实拨号；VMess 已完成 alterId=0 的 TCP、UDP、WebSocket、gRPC、HTTP/2 真实拨号。两者仍因更广泛的服务端兼容边界保守标记为 partial。
- Shadowsocks 已完成旧 AEAD 与 Shadowsocks 2022 三种方法的 TCP/UDP 双向真实拨号，支持 SIP023 多用户 EIH、simple-obfs HTTP/TLS 和 v2ray-plugin WebSocket；plugin UDP 仍明确不支持。
- ShadowsocksR 已完成 origin、verify_simple、auth_simple、auth_sha1、auth_sha1_v2、auth_sha1_v4、auth_aes128_md5/sha1 和 auth_chain_a-f，覆盖 6 种 stream cipher、TCP/UDP、多用户 `uid:key`、HTTP simple/post 与 tls1.2_ticket_auth 混淆；auth_sha1_v4 按协议边界仅支持 TCP。
- Snell 已完成 v1-v5 TCP、独立响应 salt、HTTP/TLS 混淆和 v3-v5 UDP-over-TCP；v5 使用公开的 v4 兼容 wire format，v1/v2 UDP 和 v4/v5 connection reuse 仍是明确边界。
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

客户端与核心以 HTTP 控制接口协作（`/supercore/*`）：

- `GET /supercore/status`
- `GET /supercore/outbounds`
- `POST /supercore/outbounds/use`
- `GET /supercore/groups`
- `GET /supercore/countries`
- `POST /supercore/probe/outbounds`
- `POST /supercore/probe/group`
- `GET /supercore/proxies`
- `GET /supercore/rules`
- `GET /supercore/providers/proxies`
- `GET /supercore/providers/rules`
- `GET /supercore/subscriptions`
- `POST /supercore/subscriptions/use`
- `POST /supercore/subscriptions/import`
- `POST /supercore/subscriptions/reload-active`
- `POST /supercore/subscriptions/update-all`
- `POST /supercore/subscriptions/active-config`
- `GET /supercore/traffic/subscriptions`
- `GET /supercore/smart-rules`
- `POST /supercore/smart-rules`

`POST /supercore/probe/group` 使用 JSON body 传递 `group`，避免路径二次编码问题，支持包含 `/`、中文、emoji 的组名。

## 运行提示

- 源码构建后使用仓库内的启动脚本和脚本目录进行启动。
- 当前以现网可观测与可回归能力为优先，协议功能与文档中的状态保持同步更新。
