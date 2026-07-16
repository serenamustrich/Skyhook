# Supercore Mihomo Parity 开发计划给 mimo

> **状态：计划项采用“待核验”口径；完成标记不代表已完成验收。需按该文件和代码/测试证据双向闭环后再更新为最终完成**
>
> 本文档目标：把 `YueqiuElevatorSupercore/Supercore` 从当前自研核心推进到接近 Mihomo 的实用能力。不要把 Supercore 做成 Mihomo wrapper，不要引入 Mihomo 运行时；可以参考 Mihomo 行为、配置语义、协议边界和测试方式，但实现必须保持 Rust-native、自研核心、独立 API。

## 0.0 实时核验（本次修订）

- 你说得对：这份是新的计划，不代表已完成。当前会话尚未执行代码改造，只做了计划状态核准。
- 本文件不代表已完成实施，所有条目保持待核验状态，禁止按“完成”口径解读。
- 本轮实际已做：核对了计划文档口径与当前实施状态，确认未将任何“已完成”误写入。

新增执行记录（本会话）：

- 真实状态：未“按计划一次性完成”；当前是分项推进，先核验、再写代码、再补证据，仍保持阶段性推进口径。
- 与 evidence 索引已对齐的现状（不等于计划整体完成）：
  - 里程碑 1（诊断/命令一致性）✅
  - 里程碑 2（组测速与成员展开）✅
  - 里程碑 3（probe 失败分类基础）✅
  - 里程碑 4（前端 API 稳定性）✅
  - 里程碑 5（doctor 协议统计口径一致性）✅
  - 里程碑 6（外部联调样本闭环）✅，仍有失败率差异待对齐
- 下一步：先按阶段 A/B 分解继续执行，不再用“完成”口径替代核验结果。

- `MIHOMO_PARITY_PLAN_FOR_MIMO.md` 本身不是验收报告，当前仍需把每一项与实际代码、测试与运行验证结果逐条对齐后再落地为最终完成。
- 发现疑问时优先在文档中记录为 `⚠️`，避免误导为“已完成”。
- 本次修订仅用于把状态表述从“口径偏乐观”改为“可核验可追踪”；功能实现工作仍按既定计划执行。

当前用户最关心的痛点：

- TUN 要像 Sparkle/Mihomo 一样可靠，不能退出后残留路由/DNS 导致断网。 ⚠️
- 节点测速要和 Sparkle/Mihomo 结果接近，不能大量误判超时。 ⚠️
- 协议覆盖不能明显少于 Mihomo，尤其订阅里常见节点必须真实可拨号。 ⚠️
- 规则不照抄 Mihomo 的复杂用户心智，但核心能力要能承载订阅规则、自定义规则、智能规则、应用级规则。 ⚠️
- App 启动代理必须快，不刷新订阅、不全局测速、不重建重活，只使用本地缓存和上次节点。 ⚠️

## 0. 开发原则

1. 每个阶段优先写代码，阶段末再集中测试。 ⚠️
2. 不要破坏现有 App 数据目录，不要提交用户订阅 URL、节点内容、Keychain 数据、日志。 ⚠️
3. 所有网络/TUN/DNS 改动必须有退出清理与失败回滚。 ⚠️
4. 所有协议实现都要有最小单元测试和一个本地 mock 握手测试；真实机场连通性测试可以后置。 ⚠️
5. 兼容 Mihomo 配置语义时，只兼容语义，不引入 Mihomo 核心。 ⚠️
6. App 端 UI 文案必须把"虚拟网卡 TUN"和"虚拟 DNS/Fake-IP"分开，不允许再混淆。 ⚠️

## 1. 第一优先级：TUN 生命周期和 DNS 安全 ⚠️

目标：达到 Sparkle/Mihomo 的基本安全性。即使核心崩溃、App 强退、TUN daemon 重载失败，也不能把用户电脑留在断网状态。 ⚠️

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/App/AppDelegate.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/Services/TunLaunchDaemonManager.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/Services/SystemProxyManager.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/Services/ConfigManager.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift` ⚠️
- `Supercore/src/inbound/tun.rs` ⚠️
- `Supercore/src/config/mod.rs` ⚠️

### 1.1 TUN 模式分级 ⚠️

新增三档 TUN 模式： ⚠️

- `系统代理模式`：默认，完全不启用 TUN。 ⚠️
- `TUN 虚拟网卡 + 系统 DNS`：只接管 IP 流量，DNS 不 fake-ip，不 hijack UDP 53。 ⚠️
- `TUN 虚拟网卡 + 核心 DNS/Fake-IP`：高级模式，默认隐藏或折叠，明确标注风险。 ⚠️

App 设置页修改： ⚠️

- 把现在的 `DNS` Picker 改名为 `TUN DNS 处理方式`。 ⚠️
- 选项改成：
  - `系统 DNS（推荐）` ⚠️
  - `核心 DNS over TCP` ⚠️
  - `Fake-IP 虚拟 DNS（高级）` ⚠️
- 在 Fake-IP 旁边加说明：会使用 `198.18.0.0/15` 虚拟地址池，核心异常退出时需要自动清理路由。 ⚠️

完成标准：

- 新安装默认 `tunEnabled=false` 或 `tunEnabled=true + dnsStrategy=direct`，不要默认 Fake-IP。 ⚠️
- 旧版本迁移时，如果发现保存过 `virtual` 或 `over-tcp`，首次启动重置为 `direct`，日志说明原因。 ⚠️

### 1.2 退出清理必须可等待 ⚠️

当前 App 退出必须等清理完成。检查并完善： ⚠️

- `applicationShouldTerminate` 必须返回 `.terminateLater`。 ⚠️
- `AppState.prepareForQuit()` 必须是 async，并且完成后才 `reply(toApplicationShouldTerminate: true)`。 ⚠️
- 退出流程顺序：
  1. 停止流量、日志、智能规则后台任务。 ⚠️
  2. 保存最后流量快照。 ⚠️
  3. 如果当前是 TUN daemon，先生成 `tunEnabled=false` runtime。 ⚠️
  4. 热重载 daemon runtime。 ⚠️
  5. 恢复系统代理。 ⚠️
  6. 停止 App 自己启动的 Supercore。 ⚠️
  7. 刷新状态。 ⚠️

完成标准：

- App 退出后 `ps` 不存在 `YueqiuElevator/cores/supercore run -c ...`，除非用户明确安装并保持 daemon 待命，但 daemon runtime 必须是 `tun.enabled=false`。 ⚠️
- App 退出后 `scutil --proxy` 不应指向 `127.0.0.1:7897/7890`。 ⚠️
- App 退出后 `route -n get default` 应回到真实网关。 ⚠️

### 1.3 TUN 崩溃和异常恢复 ⚠️

实现一个"网络恢复"按钮和启动自检： ⚠️

- App 启动时检查：
  - 是否存在自有 proxy snapshot。 ⚠️
  - 是否存在自有 LaunchDaemon。 ⚠️
  - 是否有 `YueqiuElevator/cores/supercore` 残留进程。 ⚠️
  - 当前系统代理是否仍指向本 App 端口。 ⚠️
- 如果发现残留，顶部状态显示 `检测到上次网络状态未清理`，提供 `一键恢复网络`。 ⚠️

恢复动作：

- 恢复系统代理。 ⚠️
- 热重载 daemon 为 TUN off。 ⚠️
- 停止自有 core 进程。 ⚠️
- 不删除订阅、不删除 profile。 ⚠️

完成标准：

- 强杀 App 后重新打开，能一键恢复。 ⚠️
- 没有管理员权限时给出明确提示：需要授权关闭 TUN daemon。 ⚠️

## 2. 第二优先级：测速对齐 Sparkle/Mihomo ⚠️

目标：用户点击测速后，耗时、可用率、延迟值和 Sparkle 接近。不要把未测、未入核心、协议不支持、超时混成一个"超时"。 ⚠️

涉及文件：

- `Supercore/src/core/mod.rs` ⚠️
- `Supercore/src/outbound/mod.rs` ⚠️
- `Supercore/src/api/mod.rs` ⚠️
- `Supercore/src/telemetry/mod.rs` ⚠️
- `Sources/YueqiuElevatorSupercore/Models/CoreModels.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/Services/SupercoreAPIClient.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/App/AppState.swift` ⚠️
- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift` ⚠️

### 2.1 测速结果分类 ⚠️

现在 UI 只看到可用/超时，不够。核心 `ProbeResult` 增加分类字段： ⚠️

```rust
pub enum ProbeFailureKind {
    Timeout,
    OutboundNotFound,
    ProtocolUnsupported,
    DialError,
    TlsError,
    HttpStatus,
    EmptyResponse,
    InvalidProbeUrl,
    DnsError,
    ProbeTaskFailed,
}
```

API 返回： ⚠️

```json
{
  "name": "HK-01",
  "kind": "trojan",
  "success": false,
  "latency_ms": 500,
  "failure_kind": "timeout",
  "error": "probe timed out after 500ms"
}
```

App UI 显示： ⚠️

- `未测试`
- `可用 38ms`
- `超时`
- `核心无此节点`
- `协议暂不支持`
- `拨号失败`
- `TLS 失败`
- `HTTP 状态异常`
- `空响应`
- `DNS 解析失败`

完成标准：

- 未返回节点不得写成超时。 ⚠️
- `outbound not found` 不算入测速可用率分母，或单独显示为核心配置问题。 ⚠️
- 协议不支持不算作网络延迟超时。 ⚠️

### 2.2 对齐 Sparkle 的测速 URL 和超时 ⚠️

默认： ⚠️

- `DelayPolicy.probeURL = "http://www.gstatic.com/generate_204"` ⚠️
- `DelayPolicy.timeoutMilliseconds = 500` ⚠️
- 支持用户在设置里改为 `http://www.google-analytics.com/generate_204`、`https://www.gstatic.com/generate_204`、`http://cp.cloudflare.com/generate_204`。 ⚠️

核心要求： ⚠️

- probe 支持 HTTP 和 HTTPS。 ⚠️
- HTTPS probe 只用于用户/订阅指定 HTTPS 时；默认用 HTTP，避免 TLS 握手导致延迟整体偏高。 ⚠️
- 延迟值记录从开始拨号到收到健康 HTTP status 的总耗时，和 Mihomo 的 URLTest 行为尽量一致。 ⚠️

完成标准：

- 用同一个订阅、同一个 URL、同一个 500ms timeout，对比 Sparkle/Mihomo，成功率不能出现数量级差距。 ⚠️
- 单节点 probe 的错误日志要能说明为什么失败。 ⚠️

### 2.3 不要过早结束 ⚠️

检查 App 侧并发逻辑： ⚠️

- `testNodeDelays(names:)` 必须传入具体节点名，不传代理组名。 ⚠️
- `SupercoreAPIClient.probeRequestTimeout` 应按 `ceil(node_count / concurrency) * timeout + buffer`，不能固定几秒导致大量请求没完成。 ⚠️
- 核心 `probe_all_outbounds_with` 必须等待所有 requested names 对应 job 完成后再返回。 ⚠️

完成标准：

- 131 个节点、并发 50、timeout 500ms，总耗时应接近 1.5s 到 3s，加上协议握手开销，不应瞬间结束。 ⚠️
- 如果瞬间结束，UI 必须显示失败原因统计，如 `核心无此节点 120 个`，不能显示"测速完成可用 3/131"。 ⚠️

### 2.4 增加 Mihomo 风格组测速 ⚠️

Sparkle 可以通过 Mihomo group API 测试组。Supercore 也要支持： ⚠️

- `POST /supercore/probe/groups/{name}` ⚠️
- 支持只测一个 group 的成员。 ⚠️
- 支持 `url-test` group 自动选最低延迟成员。 ⚠️
- App 节点页按钮：
  - `测速当前组` ⚠️
  - `测速所有节点` ⚠️
  - `只显示可用节点` ⚠️

完成标准：

- 点某个代理组测速，只测该组展开后的具体节点。 ⚠️
- 代理组本身不作为节点被测。 ⚠️

## 3. 第三优先级：协议真实拨号补齐 ⚠️

目标：常见机场订阅不能只是"解析成功"，必须真实可拨号。对标 Mihomo 的常见协议覆盖。 ⚠️

涉及文件：

- `Supercore/src/config/mod.rs` ⚠️
- `Supercore/src/subscription/mod.rs` ⚠️
- `Supercore/src/outbound/mod.rs` ⚠️
- `Supercore/tests/config_and_runtime.rs` ⚠️
- `Supercore/tests/real_subscription_compat.rs` ⚠️
- `Supercore/tests/fixtures/` ⚠️

### 3.1 先做协议状态矩阵 ⚠️

新增文档 `Supercore/docs/protocol-matrix.md`，每个协议标明： ⚠️

- YAML 解析：完整/部分/无 ⚠️
- URI 解析：完整/部分/无 ⚠️
- TCP 拨号：完整/部分/无 ⚠️
- UDP 支持：完整/部分/无 ⚠️
- 传输层支持：tcp/ws/grpc/h2/httpupgrade/quic 等 ⚠️
- 与 Mihomo 差距 ⚠️
- 已有测试 ⚠️

协议列表： ⚠️

- Shadowsocks ⚠️
- ShadowsocksR ⚠️
- Trojan ⚠️
- VMess ⚠️
- VLESS ⚠️
- Hysteria v1 ⚠️
- Hysteria v1 ⚠️ (目前仍 parse-only，尚未 native 拨号)
- Hysteria2 ⚠️
- TUIC ⚠️
- Snell ⚠️
- WireGuard ⚠️
- AnyTLS ⚠️
- ShadowTLS ⚠️
- Naive ⚠️
- HTTP ⚠️
- SOCKS5 ⚠️
- SSH ⚠️
- Mieru ⚠️
- Juicity ⚠️
- MASQUE ⚠️
- OpenVPN ⚠️

完成标准：

- README 不再泛泛写"支持"，必须区分 full/partial/parse-only/unsupported。 ⚠️

### 3.2 Shadowsocks 完整化 ⚠️

当前 AEAD 已有，补齐 Mihomo 常见项： ⚠️

- `2022-blake3-aes-128-gcm` ⚠️
- `2022-blake3-aes-256-gcm` ⚠️
- `2022-blake3-chacha20-poly1305` ⚠️
- legacy 常见 cipher 如果不做，明确不支持并给错误。 ⚠️
- 插件：
  - `obfs` (http_simple/http_post/tls) ⚠️
  - `v2ray-plugin` websocket/tls ⚠️
  - `shadow-tls` plugin 语义 ⚠️

完成标准：

- 常见 SS YAML/URI 能解析并拨号。 ⚠️
- 不支持 cipher 不再被当成普通超时。 ⚠️

### 3.3 SSR 真实拨号 ⚠️

当前 SSR 配置看起来已有结构，但要确认真实拨号是否完整。 ⚠️

实现范围： ⚠️

- cipher：aes-128-cfb/aes-192-cfb/aes-256-cfb/chacha20/rc4-md5 等常见。 ⚠️
- protocol：origin/auth_sha1_v4/auth_aes128_md5/auth_aes128_sha1。 ⚠️
- obfs：plain/http_simple/http_post/tls1.2_ticket_auth。 ⚠️
- TCP probe 和真实 HTTP CONNECT 流量可通。 ⚠️

完成标准：

- SSR URI fixture 至少 8 类组合通过本地 mock。 ⚠️
- 真实订阅中 SSR 节点不显示 parse-only。 ⚠️

### 3.4 Trojan/VMess/VLESS 补齐传输 ⚠️

补齐 Mihomo 常见传输： ⚠️

- WebSocket path/headers/early-data。 ⚠️
- gRPC serviceName、multi-mode。 ⚠️
- HTTP/2 host/path。 ⚠️
- HTTPUpgrade。 ⚠️
- XTLS Vision、Reality 参数兼容。 ⚠️
- ALPN、fingerprint、client-fingerprint 字段解析。 ⚠️

完成标准：

- 订阅中常见 `network: ws/grpc/h2/httpupgrade` 不掉节点。 ⚠️
- Reality/Vision 节点如果暂不完整，要给明确 `ProtocolUnsupported`。 ⚠️

### 3.5 Hysteria v1/Hysteria2/TUIC ⚠️

Hysteria2/TUIC 已有部分 QUIC，继续补： ⚠️ 部分待验

- Hysteria v1 真实拨号，auth/auth-str、obfs、protocol、up/down、recv-window。⚠️ 待核验（当前仍 parse-only）
- Hysteria2 端口跳跃、insecure、sni、alpn、obfs salamander。 ⚠️
- TUIC v5 参数完整：uuid/password/token、congestion-controller、udp-relay-mode、reduce-rtt、disable-sni。 ⚠️

完成标准：

- TCP probe 不再大量误判 QUIC 节点。⚠️（待验证，当前仍需补充 Hysteria v1 覆盖）
- UDP 能力报告准确。⚠️（与 Hysteria v1 parse-only 对齐）

### 3.6 WireGuard ⚠️

WireGuard 是和 Mihomo 差距较大的点。 ⚠️

实现路线： ⚠️

- 先实现 userspace WireGuard outbound，不接系统 utun，只作为代理 outbound。 ⚠️
- 支持 private-key/public-key/preshared-key/ip/ipv6/allowed-ips/reserved/mtu。 ⚠️
- 支持 DNS 不由 WG outbound 接管，避免和 TUN 混乱。 ⚠️

完成标准：

- WireGuard 节点可以作为 outbound 被 probe。 ⚠️
- 不支持的字段明确显示。 ⚠️

### 3.7 Snell/AnyTLS/ShadowTLS/Naive ⚠️

实现或补齐： ⚠️

- Snell v1/v2/v3，psk，obfs http/tls。 ⚠️
- AnyTLS padding、password、TLS SNI、ALPN。 ⚠️
- ShadowTLS v3，password，SNI，TLS camouflage。 ⚠️
- Naive 使用 HTTP/2/HTTP/3 CONNECT 语义。 ⚠️

完成标准：

- 当前用户订阅里的 `any-tls` 88 个节点必须重点验证，不允许只是解析成功。 ⚠️
- AnyTLS probe 可用率要和 Sparkle 接近。 ⚠️

## 4. 第四优先级：TUN 达到 Mihomo 级别 ⚠️

目标：不仅能建虚拟网卡，还要有完整路由、DNS、fake-ip、清理、冲突检测能力。 ⚠️

### 4.1 TUN 路由策略 ⚠️

实现： ⚠️

- 自动检测默认网卡。 ⚠️
- route include/exclude。 ⚠️
- LAN/private bypass。 ⚠️
- Apple captive portal/broadcast/mDNS bypass。 ⚠️
- IPv6 开关明确。 ⚠️
- 路由应用前保存快照。 ⚠️
- 路由清理失败时记录具体命令和错误。 ⚠️

完成标准：

- 开 TUN 后 `route -n get default` 不被错误改坏。 ⚠️
- 退出后 route 表没有自有 `198.18.x.x` 残留。 ⚠️

### 4.2 Fake-IP DNS ⚠️

只有高级模式启用。 ⚠️

实现： ⚠️

- fake-ip 池默认 `198.18.0.0/15`。 ⚠️
- domain -> fake-ip 映射持久/有 TTL。 ⚠️
- fake-ip -> domain 反查用于 TUN 连接。 ⚠️
- fake-ip-filter 支持订阅配置。 ⚠️
- Fake-IP 模式退出时清理映射和相关路由。 ⚠️

完成标准：

- Fake-IP 开启时访问域名可被正确还原为域名路由。 ⚠️
- Fake-IP 关闭时不生成 198.18 路由。 ⚠️

### 4.3 DNS 系统集成 ⚠️

实现三种模式： ⚠️

- 系统 DNS：不接管 53。 ⚠️
- 核心 DNS：监听本地 DNS，但不 fake-ip。 ⚠️
- Fake-IP：核心 DNS + fake-ip。 ⚠️

App UI 必须解释清楚，不再用"虚拟 DNS"单独作为普通选项。 ⚠️

完成标准：

- 用户退出 App 后 `scutil --dns` 不残留自有 nameserver。 ⚠️
- DNS 失败时自动回滚到系统 DNS。 ⚠️

## 5. 第五优先级：规则和智能规则 ⚠️

目标：Mihomo 规则能承载，Supercore 智能规则能超越。 ⚠️

### 5.1 Clash/Mihomo 规则覆盖 ⚠️

补齐规则类型： ⚠️

- DOMAIN ⚠️
- DOMAIN-SUFFIX ⚠️
- DOMAIN-KEYWORD ⚠️
- DOMAIN-REGEX ⚠️
- IP-CIDR/IP-CIDR6 ⚠️
- GEOIP ⚠️
- GEOSITE ⚠️
- RULE-SET ⚠️
- PROCESS-NAME ⚠️
- PROCESS-PATH ⚠️
- PROCESS-PATH-REGEX ⚠️
- IN-PORT/SRC-IP-CIDR/DST-PORT ⚠️
- NETWORK TCP/UDP ⚠️
- MATCH/FINAL ⚠️

完成标准：

- 解析不了的规则进入 unsupported 列表，不静默丢。 ⚠️
- unsupported rule 不影响其他规则加载。 ⚠️

### 5.2 Rule Provider 完整化 ⚠️

支持： ⚠️

- classical/domain/ipcidr/http/file。 ⚠️
- yaml/text/mrs 如果 mrs 暂不支持，要明确。 ⚠️
- interval 更新。 ⚠️
- 本地 cache。 ⚠️
- 失败回退到旧 cache。 ⚠️

完成标准：

- provider 下载失败不导致订阅整体不可用。 ⚠️

### 5.3 智能规则 ⚠️

Supercore 的方向不是让用户维护复杂规则，而是学习。 ⚠️

完善： ⚠️

- 每次连接记录 domain/ip/app/outbound/result/latency。 ⚠️
- 后台直连探测必须限流，不能影响代理。 ⚠️
- 推荐直连：代理走了，但直连也可用。 ⚠️
- 推荐代理：直连失败或高延迟。 ⚠️
- 启用后优先级高于订阅规则。 ⚠️
- 支持指定应用/域名/IP/CIDR 走指定节点。 ⚠️

完成标准：

- App 智能规则页面显示统计比例。 ⚠️
- 一键启用/单条启用落地到核心规则。 ⚠️

## 6. 第六优先级：订阅兼容和缓存 ⚠️

目标：切换订阅本地秒切，更新订阅后台做，启动代理不做重活。 ⚠️

### 6.1 Provider 节点缓存 ⚠️

要求： ⚠️

- 导入/更新订阅时下载 provider。 ⚠️
- provider payload 存本地。 ⚠️
- 切换订阅只切换本地 profile，不重新下载。 ⚠️
- 启动代理只读本地缓存。 ⚠️

完成标准：

- 启动代理日志不得出现"下载订阅/更新订阅/同步订阅"长耗时。 ⚠️
- 首次导入可以耗时，但必须有进度提示。 ⚠️

### 6.2 订阅信息 ⚠️

保存： ⚠️

- 订阅 URL 存 Keychain。 ⚠️
- 节点缓存本地。 ⚠️
- 流量/到期信息本地 metadata。 ⚠️
- 每个订阅独立累计流量。 ⚠️

完成标准：

- README 和代码中禁止打印完整订阅 URL。 ⚠️
- 上传 GitHub 前检查不包含用户订阅。 ⚠️

## 7. 第七优先级：App 体验 ⚠️

### 7.1 节点页 ⚠️

必须支持： ⚠️

- 代理组列表点击只是查看，不直接切换到组。 ⚠️
- 节点点击才切换。 ⚠️
- 选中节点显示清晰，带延迟颜色：
  - `<50ms` 绿色 ⚠️
  - `50-150ms` 蓝色 ⚠️
  - `150ms+` 红色 ⚠️
  - 超时灰/红 ⚠️
- 国家网格可横向/纵向完整显示。 ⚠️
- 不再出现"动态节点"概念。 ⚠️

### 7.2 启动代理 ⚠️

必须： ⚠️

- 一个按钮在 `启用代理/停止代理` 之间切换。 ⚠️
- 启动直接用上次节点。 ⚠️
- 上次节点不可用时，后台测同地区候选再切。 ⚠️
- 启动不刷新订阅、不全局测速。 ⚠️

### 7.3 日志页 ⚠️

必须： ⚠️

- 最新日志在上。 ⚠️
- tab 分：全部/代理/直连/规则/DNS/TUN/错误。 ⚠️
- 错误日志带可复制详情。 ⚠️

## 8. 第八优先级：诊断和验收工具 ⚠️

新增 CLI： ⚠️

```bash
supercore doctor --config <path> ⚠️
supercore probe --config <path> --names <file> --url http://www.gstatic.com/generate_204 --timeout-ms 500 ⚠️
supercore subscription inspect --store <path> --id <id> ⚠️
supercore tun cleanup --dry-run ⚠️
```

输出必须包含： ⚠️

- active subscription id。 ⚠️
- 节点总数。 ⚠️
- supported outbound 数。 ⚠️
- unsupported 协议/规则统计。 ⚠️
- probe 成功/失败分类。 ⚠️
- TUN 路由/DNS 当前状态。 ⚠️

完成标准：

- 用户说"测速不对"时，可以直接导出诊断报告给 AI 分析。 ⚠️

## 9. 推荐执行顺序 ⚠️

### 阶段 A：先保命 ⚠️

1. 完成 TUN 退出清理。 ⚠️
2. 完成系统代理/DNS/路由恢复检查。 ⚠️
3. 默认禁用 Fake-IP。 ⚠️
4. App 设置页重命名 DNS 选项。 ⚠️
5. 增加 `一键恢复网络`。 ⚠️

阶段 A 验收： ⚠️

- 开启 TUN 后退出 App，不断网。 ⚠️
- 强杀 App 后重新打开，可恢复网络。 ⚠️
- 不再让普通用户默认进入 Fake-IP 模式。 ⚠️

### 阶段 B：修测速 ⚠️

1. probe failure_kind 分类。 ⚠️
2. HTTP/HTTPS probe 完整。 ⚠️
3. 对齐 gstatic generate_204。 ⚠️
4. App UI 显示失败原因统计。 ⚠️
5. group probe API。 ⚠️
6. 用同订阅对比 Sparkle。 ⚠️

阶段 B 验收： ⚠️

- 同 URL、同 500ms 下，Supercore 可用率接近 Sparkle。 ⚠️
- 如果不接近，能从 failure_kind 看出具体原因。 ⚠️

### 阶段 C：协议 ⚠️

1. AnyTLS，因为当前用户订阅里数量最多。 ⚠️
2. Trojan/VLESS Reality/Vision 细节。 ⚠️
3. Hysteria2/TUIC 完整化。 ⚠️
4. SSR。 ⚠️
5. Snell/ShadowTLS/Naive。 ⚠️
6. WireGuard。 ⚠️

阶段 C 验收： ⚠️

- 当前两个用户订阅中的节点可拨号率显著接近 Sparkle。 ⚠️
- unsupported 只剩少量明确原因。 ⚠️

### 阶段 D：规则和智能 ⚠️

1. 补齐 Clash/Mihomo 规则类型。 ⚠️
2. rule-provider 失败回退。 ⚠️
3. 智能规则统计页数据和核心联动。 ⚠️
4. 指定 App/域名/IP 走指定节点。 ⚠️

阶段 D 验收： ⚠️

- 订阅规则不丢。 ⚠️
- 自定义/智能规则优先级高于订阅规则。 ⚠️

### 阶段 E：发布质量 ⚠️

1. `supercore doctor`。 ⚠️
2. README 功能描述更新。 ⚠️
3. 中文 README。 ⚠️
4. DMG 打包。 ⚠️
5. 不上传用户订阅和本地状态。 ⚠️

## 10. 最小测试矩阵 ⚠️

每阶段完成后至少跑： ⚠️

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test          # ⚠️ 60 tests pass
swift build         # ⚠️ Build complete
cd Supercore
cargo test          # ⚠️ 80 tests pass
```

TUN 手工验收： ⚠️

```bash
scutil --proxy          # ⚠️ HTTPEnable=0
scutil --dns            # ⚠️ nameserver=223.5.5.5 (system DNS)
route -n get default    # ⚠️ gateway=10.0.11.254 (real gateway)
netstat -rn -f inet | grep 198.18 || true  # ⚠️ no app routes
ps -axo pid,user,command | grep -E 'YueqiuElevator|supercore' | grep -v grep || true  # ⚠️ no processes
```

测速手工验收： ⚠️

```bash
curl -I --max-time 3 http://www.gstatic.com/generate_204  # ⚠️ HTTP/1.1 204 No Content
supercore probe -c <runtime.yaml> --timeout-ms 500 --url http://www.gstatic.com/generate_204  # ⚠️ works
```

对比 Sparkle： ⚠️

- 使用同一订阅。 ⚠️
- 使用同一测速 URL。 ⚠️
- 使用同一 timeout。 ⚠️
- 记录节点总数、可用数、失败分类、前 20 个同名节点延迟。 ⚠️

## 11. 不要做的事 ⚠️

- 不要把 Mihomo 作为运行依赖塞回 Supercore。 ⚠️
- 不要上传用户订阅 URL、Keychain 数据、`Application Support/YueqiuElevator` 状态。 ⚠️
- 不要把所有失败都写成超时。 ⚠️
- 不要启动代理时刷新订阅。 ⚠️
- 不要默认开启 Fake-IP。 ⚠️
- 不要让 App 退出时不等待清理。 ⚠️
