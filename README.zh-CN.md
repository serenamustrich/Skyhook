# Skyhook

[English](README.md)

**Skyhook** 是一个 Rust 原生的智能代理核心。  
中文名：**玥球核心**。

Skyhook 的目标不是做另一个静态规则代理核心，而是做一个更懂网络状态的核心。它会把协议拨号、TUN 捕获、实时遥测、节点测速、订阅管理、智能规则和后台学习放在同一个原生引擎里，让代理软件不再只依赖用户手写复杂规则。

Skyhook 是独立实现。仓库不包含其他代理核心的源码。协议兼容的目的只是为了互通。

## 为什么做 Skyhook

传统代理核心更像是高性能的数据搬运器。Skyhook 想进一步成为网络决策引擎。

它的方向是：

1. 导入真实订阅，并保留节点、代理组、规则、规则提供者、国家分组和节点元数据。
2. 同时支持 mixed inbound 和 TUN 模式，通过本地控制 API 暴露运行状态。
3. 观察流量，判断目标域名、IP、App 是否可以直连，并给出直连或代理建议。
4. 后台测试节点延迟，记录健康状态，选择更好的路径，同时不冻结当前代理流量。
5. 使用 Rust、Tokio 和 async I/O 构建，所有后台任务都有超时、并发上限和明确错误。
6. 明确告诉客户端哪些协议可用、哪些协议部分可用、哪些协议只是解析了配置。

Skyhook 不是克隆项目。它参考现有代理生态的能力，但产品方向是更自动、更透明、更智能的独立核心。

## 当前状态

Skyhook 仍在快速开发中。当前已经具备核心架构、配置模型、控制 API、订阅系统、智能规则框架、流量统计框架，以及多种协议的真实拨号路径。

但是它还不是一个完全稳定的成品核心。尤其是 NativeL3 的 L4 TCP/UDP 数据面仍在完成和加固中。当前重点任务见：

[docs/MIMO_FINAL_COMPLETION_AND_OPTIMIZATION_PLAN.md](docs/MIMO_FINAL_COMPLETION_AND_OPTIMIZATION_PLAN.md)

当前主要开发方向：

1. 打通 NativeL3 L4 TCP 完整双向数据流。
2. 补齐 NativeL3 UDP relay。
3. 提升真实协议拨号覆盖。
4. 强化智能规则、直连探测、后台学习。
5. 完善订阅后台更新、多订阅切换和订阅流量累计。
6. 完善实时速率、总流量、连接列表和日志分类。
7. 做性能优化和最终端到端验收。

## 核心亮点

1. **Rust 原生核心**：基于 Tokio、rustls、Quinn、HTTP/2、HTTP/3 和 async stream。
2. **Mixed inbound**：支持 SOCKS5、SOCKS5 UDP ASSOCIATE、HTTP CONNECT 和普通 HTTP 代理。
3. **TUN 模式**：支持设备级流量捕获、DNS hijack、虚拟 DNS、路由配置和 macOS 集成脚本。
4. **Native DNS**：支持 UDP/TCP DNS、DoH/DoT 上游、fake-IP、超时控制和 TUN 虚拟 DNS。
5. **订阅引擎**：支持 Clash YAML 和 URI list 订阅。
6. **多订阅存储**：支持导入、列表、切换、update-all、导出 active config、启动刷新和后台刷新。
7. **代理组**：支持 select、url-test、fallback、auto、latency、load-balance 等行为。
8. **规则转换**：支持 domain、IP、CIDR、App、process、RULE-SET、geosite、geoip、match、final。
9. **规则提供者**：支持下载、缓存、编译和原生 RULE-SET 匹配。
10. **国家智能分组**：识别节点国家，支持国家组和国家低延迟择优。
11. **智能规则**：记录访问观察，推荐直连或代理，并允许一键提升为高优先级规则。
12. **流量遥测**：连接表、节点统计、实时速率、事件日志、健康状态和订阅维度累计流量。
13. **后台测速**：有并发上限和短超时默认值，不阻塞正在使用的代理连接。
14. **控制 API**：方便桌面客户端、菜单栏 App 和自动化工具接入。

## 协议拨号能力

Skyhook 对每个 outbound 都会报告 TCP/UDP 能力和已知限制。当前能力矩阵如下：

| 协议 | TCP | UDP | 说明 |
| --- | --- | --- | --- |
| Direct | yes | yes | 原生直连出口。 |
| HTTP proxy | yes | no | HTTP CONNECT 和 absolute-form 代理。 |
| SOCKS5 | yes | yes | TCP connect 和 UDP ASSOCIATE。 |
| Shadowsocks AEAD | yes | yes | AES-GCM、ChaCha20-Poly1305 和 UDP。 |
| Shadowsocks simple-obfs | yes | partial | TCP 支持 HTTP/TLS obfs，插件 UDP 暂不启用。 |
| Trojan | yes | yes | TLS TCP 和 UDP relay。 |
| VMess AEAD | yes | yes | TCP、WebSocket、gRPC、HTTP/2、command UDP。 |
| VLESS | yes | yes | TCP、TLS、Reality、WebSocket、gRPC、HTTP/2、command UDP。 |
| Hysteria2 | yes | yes | QUIC TCP stream、datagram UDP、Salamander/Gecko。 |
| TUIC | yes | yes | QUIC TCP、原生 datagram UDP、stream UDP。 |
| Naive | yes | no | TLS HTTP CONNECT。 |
| SSH | yes | no | direct-tcpip，支持密码和私钥认证。 |
| SSR | partial | no | 已有 origin AES-CFB TCP 路径，变体覆盖仍在扩展。 |
| Snell | yes | no | AEAD TCP、Argon2id session key、HTTP obfs 首包。 |
| AnyTLS | yes | no | TLS auth、settings、stream open、SOCKS address handoff。 |
| ShadowTLS v3 | yes | no | v3 ClientHello HMAC 和 application-data framing。 |
| WireGuard | L3 | L3 | Native L3 manager，Noise packet engine，handshake、keepalive、encap/decap。 |
| OpenVPN | manager | manager | 支持 .ovpn 解析和 profile 注册，TLS/control/data channel 尚未完成。 |
| Hysteria v1 | planned | planned | 独立 QUIC v1 协议实现仍在计划中。 |

状态解释：

| 状态 | 含义 |
| --- | --- |
| production | 有真实拨号路径，基础能力已测试。 |
| partial | 有真实拨号路径，但变体覆盖不完整。 |
| experimental | 功能存在，但还未完全加固。 |
| parser only | 只能解析配置或注册 profile，不能真实拨号。 |
| planned | 尚未实现。 |

## L3 隧道引擎

Skyhook 把 L3 隧道协议当作独立运行面，而不是伪装成普通 TCP stream outbound。

当前 L3 manager 支持：

1. 从 outbounds 自动发现 WireGuard 和 OpenVPN profile。
2. 通过 `l3.enabled` 和 `l3.auto_start` 自动启动。
3. `GET /skyhook/l3` 查询状态快照。
4. `POST /skyhook/l3/start` 启动一个或全部 L3 profile。
5. `POST /skyhook/l3/stop` 停止一个或全部 L3 profile。
6. WireGuard key、endpoint、interface IP、allowed IP、MTU、PSK 校验。
7. 基于 BoringTun protocol engine 的 WireGuard Noise 状态机。
8. WireGuard handshake、keepalive、timer、加密封包、解密封包。
9. OpenVPN profile 注册和诚实状态返回，直到原生 TLS/control/data channel 完成。

WireGuard 状态会暴露 packet count、byte count、handshake age、RTT、估算 loss 和解封装后的 IP packet 转发。

L3 packet channel 使用 `send_ip_packet` / `subscribe_ip_packets` 在 Native TUN backend 和 WireGuard Noise engine 之间传递原始 IP packet。macOS 上会自动处理 utun 的 4 字节 address-family header。Linux 的 `IFF_NO_PI` 模式下直接传递 packet。

## NativeL3 TUN Backend

`native-l3` TUN backend 绕过 SOCKS5/HTTP proxy 层，直接读取 TUN 原始 IP packet，然后送入 L3 tunnel engine 或 L4 session engine。

当前实验状态：

1. macOS 通过 `PF_SYSTEM` / `SYSPROTO_CONTROL` 创建 utun。
2. Linux 通过 `/dev/net/tun` 和 `IFF_TUN | IFF_NO_PI` 创建 TUN。
3. macOS 4 字节 address-family header 自动 encode/decode。
4. `tun.backend=native-l3` 时可自动启动 L3 profile。
5. Read loop 已接入路由决策：L3Profile、Direct、Outbound、Group、Country、Reject。
6. WireGuard decapsulate 后可通过 `subscribe_l3_ip_packets()` 写回 TUN。
7. route/address setup plan 已有。
8. bypass route 可通过原 gateway 安装。
9. IP literal L3 endpoint bypass 已有。
10. setup 失败 rollback 和对称 cleanup 已有。
11. DNS hijack 可拦截 UDP/53。
12. DNS cache 可辅助 IP 到域名反查。
13. macOS/Linux process metadata resolution 已有。
14. smoltcp-based L4 TCP session engine 仍在打通和加固。
15. Direct/Outbound/Group/Country/Reject 决策层已接上。
16. SNI/HTTP Host sniffing 已有。
17. 智能规则可接入 App/domain/IP 匹配。
18. TUN metrics 和 status API 已有。

尚未完成：

1. NativeL3 L4 TCP 端到端回包写回和生产级加固。
2. NativeL3 UDP relay。
3. 域名形式 L3 endpoint bypass 的动态解析和刷新。

## TUN 和 DNS

`tun.backend` 当前有两个选项：

1. **`tun2-proxy`**：默认后端。把 TUN 流量转到本地 SOCKS5/HTTP inbound。这个路径更成熟，支持 DNS hijack、虚拟 DNS、路由配置和 session 管理。
2. **`native-l3`**：实验后端。直接读取原始 IP packet，并桥接到 L3 tunnel engine 或 L4 session engine。WireGuard L3 packet bridge、route setup、bypass route、DNS cache、process metadata 已有；L4 TCP/UDP 转发仍在完成中，暂时不要当作生产替代。

DNS 支持：

1. UDP DNS listener
2. TCP DNS listener
3. regular nameserver
4. default nameserver
5. fallback nameserver
6. DoH/DoT upstream
7. fake-IP range
8. fake-IP TTL
9. fake-IP filter
10. direct/proxy-server nameserver 区分
11. timeout 和 blocking controls

## 智能规则

Skyhook 的智能规则方向是：用户不需要长期维护复杂规则，核心自己观察、探测、推荐，用户只需要确认。

工作流：

1. 观察每个新域名、IP、进程、App bundle。
2. 后台探测目标是否可以直连。
3. 直连健康时推荐 `direct`。
4. 直连失败或表现差时推荐代理节点。
5. 用户可以把推荐提升为持久规则。
6. 智能规则优先级高于订阅规则。

当前 smart-rule engine 支持：

1. direct-reachability observation
2. recommendation list
3. proxy/direct recommendation bucket
4. apply-all
5. 单条 recommendation 启用
6. high-priority smart override
7. 持久化状态和节流写入
8. 带 App identity 的 route decision
9. direct-probe timeout 和 concurrency 配置
10. auto-apply 的成功/失败置信度阈值

## 控制 API

Skyhook 通过本地 HTTP API 暴露 `/skyhook/*`。

常用端点：

| API | 说明 |
| --- | --- |
| `GET /health` | 健康检查。 |
| `GET /skyhook/version` | 版本信息。 |
| `GET /skyhook/status` | 核心状态。 |
| `GET /skyhook/connections` | 连接和流量。 |
| `GET /skyhook/outbounds` | 节点、健康状态和 capability。 |
| `POST /skyhook/outbounds/use` | 切换默认节点。 |
| `GET /skyhook/groups` | 代理组。 |
| `GET /skyhook/countries` | 国家组。 |
| `POST /skyhook/countries/use` | 选择国家组。 |
| `GET /skyhook/tun/profile` | TUN 启动画像。 |
| `GET /skyhook/tun/status` | NativeL3 TUN 状态。 |
| `GET /skyhook/tun/metrics` | NativeL3 TUN 指标。 |
| `GET /skyhook/l3` | L3 profile 状态。 |
| `POST /skyhook/l3/start` | 启动 L3 profile。 |
| `POST /skyhook/l3/stop` | 停止 L3 profile。 |
| `POST /skyhook/probe/outbounds` | 测速节点。 |
| `POST /skyhook/route/decision` | 查询路由决策。 |
| `GET /skyhook/subscriptions` | 订阅列表。 |
| `POST /skyhook/subscriptions/import` | 导入订阅。 |
| `POST /skyhook/subscriptions/use` | 切换订阅。 |
| `POST /skyhook/subscriptions/update-all` | 更新全部订阅。 |
| `GET /skyhook/traffic/subscriptions` | 订阅维度流量。 |
| `GET /skyhook/smart-rules` | 智能规则快照。 |
| `GET /skyhook/smart-rules/stats` | 智能规则统计。 |
| `GET /skyhook/smart-rules/recommendations` | 智能推荐。 |
| `POST /skyhook/smart-rules` | 新增或更新智能规则。 |
| `POST /skyhook/smart-rules/enabled` | 启用或禁用智能规则。 |
| `POST /skyhook/smart-rules/delete` | 删除智能规则。 |
| `GET /skyhook/logs` | 日志。 |
| `GET /skyhook/config` | 当前配置。 |
| `POST /skyhook/config/reload` | 重载配置。 |

测速请求示例：

```json
{ "timeout_ms": 500, "url": "http://cp.cloudflare.com/generate_204" }
```

路由决策示例：

```json
{
  "host": "example.com",
  "port": 443,
  "network": "tcp",
  "app_bundle": "com.apple.Safari"
}
```

智能规则示例：

```json
{
  "target": "domain-suffix",
  "value": "example.com",
  "outbound": "direct",
  "enabled": true
}
```

## 快速开始

生成配置：

```bash
cargo run -- example-config > skyhook.yaml
```

检查配置：

```bash
cargo run -- check -c skyhook.example.yaml
```

运行核心：

```bash
cargo run -- run -c skyhook.example.yaml
```

测试节点：

```bash
cargo run -- probe -c skyhook.example.yaml --timeout-ms 500
```

导入订阅：

```bash
cargo run -- subscriptions import --url https://example.com/sub --id profile-id --name MySub
```

更新所有订阅：

```bash
cargo run -- subscriptions update-all --timeout-secs 10 --retries 1 --concurrency 4
```

导出 active subscription 为可运行配置：

```bash
cargo run -- subscriptions export-active-config \
  --base skyhook.example.yaml \
  --output active.yaml \
  --use-first-node
```

## 示例配置

见 [skyhook.example.yaml](skyhook.example.yaml)。

默认端口：

1. mixed proxy：`127.0.0.1:7897`
2. control API：`127.0.0.1:9197`
3. probe timeout：`500ms`
4. probe concurrency：`256`
5. subscription update timeout：`10s`

## macOS

macOS 集成说明见：

[docs/macos-system-integration.md](docs/macos-system-integration.md)

手动诊断 TUN：

```bash
./scripts/run_macos_tun.sh skyhook.example.yaml
```

安装登录时运行的 LaunchAgent：

```bash
./scripts/install_macos_launch_agent.sh
```

安装 root 权限 TUN setup 的 LaunchDaemon：

```bash
./scripts/install_macos_launch_daemon.sh
```

## 规则优先级

规则从上到下匹配，第一条命中生效。整体优先级：

1. **智能规则**：用户确认后的高优先级 override。
2. **订阅规则**：从 Clash 风格订阅导入的规则。
3. **内联规则**：配置文件 `rules:` 中定义的规则。
4. **默认出口**：`core.default_outbound`，通常是 `direct`。

同一个层级内，按出现顺序匹配。

## 设计原则

1. **原生优先**：核心行为直接用 Rust 实现，不依赖外部核心包装。
2. **测量后再切换**：路由决策应基于健康、延迟、流量和可达性信号。
3. **所有后台任务都有边界**：测速、刷新、session、DNS、UDP relay 都必须有超时和并发上限。
4. **暴露真实状态**：客户端必须知道节点为什么健康、慢、不支持或失败。
5. **偏向持久状态**：订阅、总流量、智能规则、观察记录都应该重启后保留。
6. **让高级路由更人性化**：用户不应该为了正常上网手写复杂规则树。

## 后续路线

1. 完成 NativeL3 L4 TCP 端到端数据流。
2. 增加 NativeL3 UDP relay。
3. 完成 Hysteria v1 拨号。
4. WireGuard L3 packet engine 到 Native TUN bridge：已完成 packet channel 和 macOS utun header。
5. 完成 OpenVPN TLS/control/data channel。
6. 加固 NativeL3 route/address auto-configuration 和 hot reload。
7. 扩展 SSR protocol/obfs/method 变体。
8. 增加 Snell UDP 和 TLS obfs。
9. 增加 chain outbound 和嵌套 transport composition。
10. 增加更丰富的 DNS 规则意识。
11. 增加拨号延迟、DNS 延迟、TUN 吞吐 benchmark。
12. 增加订阅解析和规则转换 fuzz。
13. 发布稳定配置 schema 和 API 文档。

## Clean-Room 声明

Skyhook 是独立 Rust 实现。仓库只应包含 Skyhook 源码、示例、测试、脚本和构建所需依赖。仓库不包含私人订阅、用户配置，也不包含其他代理核心的源码。

## License

双协议授权：

1. Apache License, Version 2.0
2. MIT License

用户可任选其一。
