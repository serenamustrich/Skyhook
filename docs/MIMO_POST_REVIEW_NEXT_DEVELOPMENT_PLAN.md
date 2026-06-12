# MiMo Post-Review Next Development Plan for Skyhook

生成时间：2026-06-12

目标读者：MiMo

工程目录：

```text
/Users/chency/Downloads/clash/Skyhook
```

本文是基于最近一次代码复查后的下一步开发指引。当前代码已经能通过
`cargo test --all-targets` 和 `cargo run -- check -c skyhook.example.yaml`，
但这只代表测试层面不阻塞，不代表 Skyhook 核心能力已经完成。

接下来不要再做泛泛的“兼容 Mihomo”或“双核心”设计。Skyhook 是独立 Rust 核心，
中文名“玥球核心”。可以参考之前玥球电梯需要的能力，但不要为了兼容旧 app 牺牲核心架构。

---

## 0. 最重要的结论

MiMo 上一轮确实修掉了一些明显问题：

1. `cargo test --all-targets` 已通过。
2. `cargo run -- check -c skyhook.example.yaml` 已通过。
3. Native TUN 已经使用真实 utun interface name。
4. `NativeTunMetrics` 已经挂进 runtime，不再是全 0 假数据。
5. 代理组 auto-select 测试已修。
6. DNS 测试已修。

但还有几个不能忽略的问题：

1. NativeL3 的智能分流还不是真正可用。
2. TUN bypass/status 仍有误导。
3. `/skyhook/tun/status.running` 不是实际运行态。
4. OpenVPN 仍然只是 parser/profile/status，不是真拨号。
5. Hysteria v1 有代码雏形，但没有真实协议互通证明，README 也仍然写 planned/not implemented。
6. 编译 warning 还没清理。

下一步优先级必须是：

```text
P0: 修掉状态和 warning，保证 API 不骗人
P1: 修正 NativeL3 route/bypass 生命周期
P2: 实现 NativeL3 智能分流的真实执行路径
P3: 把智能规则、指定 app/domain/ip -> 指定节点/组/国家/direct/reject 原生落进核心
P4: Hysteria v1/OpenVPN/协议能力按真实可拨号标准推进
P5: 最后统一测试、文档对齐、不能夸大
```

---

## 1. 开发约束

### 1.1 不允许做的事

1. 不要修改旧的玥球电梯 app。
2. 不要做双核心。
3. 不要做 Mihomo wrapper。
4. 不要为了“看起来支持”把 placeholder 改名成 supported。
5. 不要把 parser、profile、config round-trip 称为真实拨号。
6. 不要删掉现有 dirty worktree 里的文件。
7. 不要回滚用户或其他 agent 已经改过的文件。
8. 不要把 NativeL3 的 packet path 和 stream outbound path 混在一起随便打通。
9. 不要在没有实际 traffic flow 的情况下更新 README 说完成。
10. 不要把测试写成只验证假状态，必须验证 runtime path。

### 1.2 允许做的事

1. 可以重构 Skyhook 内部模块。
2. 可以新增模块和 API。
3. 可以新增 crate dependency，但必须说明用途。
4. 可以保留不完整能力，但必须在 capability/status/README 里诚实标注。
5. 可以分阶段提交实现，但每个阶段要能编译。

### 1.3 测试策略

用户明确要求“先把代码写完，最后统一测试”，所以开发中不要反复跑全量测试。

建议节奏：

```text
每完成一个小模块：
  cargo check --tests

完成 P0-P3 后：
  cargo test config_and_runtime
  cargo test native_tun
  cargo run -- check -c skyhook.example.yaml

完成全部开发后：
  cargo fmt --all
  cargo test --all-targets
  cargo run -- check -c skyhook.example.yaml
```

如果某个功能必须 sudo 或真实服务端才能验证，写 ignored integration test，并在输出里明确：

```text
manual test not run: requires sudo / real server
```

---

## 2. 当前必须先读的文件

MiMo 开工前必须按顺序读这些文件：

```text
src/inbound/native_tun.rs
src/inbound/native_tun_system.rs
src/inbound/native_tun_metrics.rs
src/inbound/native_tun_flow.rs
src/inbound/native_tun_packet.rs
src/core/mod.rs
src/api/mod.rs
src/smart/mod.rs
src/routing/mod.rs
src/l3/mod.rs
src/l3/openvpn/mod.rs
src/l3/openvpn/config.rs
src/l3/openvpn/parser.rs
src/l3/openvpn/packet.rs
src/outbound/mod.rs
src/config/mod.rs
src/subscription/mod.rs
src/subscription_store.rs
skyhook.example.yaml
README.md
docs/检查结果.md
docs/MIMO_SKYHOOK_DEVELOPMENT_GUIDE.md
```

读的时候重点看这些代码点：

```text
src/inbound/native_tun.rs:
  create_tun_interface()
  execute_setup_plan()
  runtime.tun_metrics()
  parse_ip_packet()
  extract_transport_ports()
  extract_tls_sni()
  runtime.decide()
  runtime.send_l3_ip_packet()

src/inbound/native_tun_system.rs:
  NativeTunSetupPlan::from_config()
  build_macos_commands()
  build_linux_commands()
  SetupCommand::RouteExclude
  SetupCommand::to_shell_command()
  SetupCommand::to_cleanup_command()

src/api/mod.rs:
  tun_status()
  tun_metrics()
  tun_reload()
  l3 endpoints
  smart-rule endpoints

src/core/mod.rs:
  Runtime::connect()
  Runtime::decide()
  Runtime::send_l3_ip_packet()
  Runtime::probe_all_outbounds_with()
  outbound_capability()
  l3_tunnel_capability()

src/l3/mod.rs:
  L3Manager
  WireGuardProfile
  OpenVpnProfile::unsupported_status()
  L3PacketSubmitResult

src/outbound/mod.rs:
  build_outbound()
  UnsupportedProtocolOutbound
  HysteriaOutbound
  Hysteria2Outbound
  SsrOutbound
  SnellOutbound
```

---

## 3. P0：状态、warning、文档一致性修复

### 3.1 目标

先把“会骗人”的状态修掉。UI 或 API 展示的东西必须是 runtime 真实状态。

### 3.2 要修的文件

```text
src/api/mod.rs
src/inbound/native_tun.rs
src/inbound/native_tun_flow.rs
src/inbound/native_tun_system.rs
src/inbound/native_tun_metrics.rs
README.md
```

### 3.3 具体任务

#### P0-1：修 `/skyhook/tun/status.running`

当前问题：

```text
src/api/mod.rs
tun_status() 里 running = profile.enabled && config.l3.enabled
```

这不是实际运行态，只是配置推断。

必须改成：

1. `runtime.native_tun_metrics()` 里 snapshot 的 `running` 字段作为真实运行态。
2. 如果 backend 不是 native-l3，继续返回当前错误。
3. 如果 native-l3 enabled 但还没启动，`running=false`。
4. 如果 native-l3 启动失败，`running=false`，并暴露 last_error。
5. 如果 native-l3 正在运行，`running=true`，并带 interface name / mtu / routes / bytes。

建议数据结构：

```rust
{
  "ok": true,
  "status": {
    "backend": "native-l3",
    "configured": true,
    "running": metrics.running,
    "interface_name": metrics.interface_name,
    "l3_profile": metrics.l3_profile,
    "mtu": metrics.mtu,
    "setup": {
      "enabled": profile.setup_enabled,
      "auto_route": profile.auto_route,
      "routes": metrics.routes_installed,
      "bypass": metrics.bypass_routes_installed
    },
    "metrics": metrics
  }
}
```

#### P0-2：NativeTun shutdown 时必须设置 running=false

当前 `native_tun::serve()` 启动时设置 `metrics.set_running(true)`。

必须保证这些路径都会设置 false：

1. read loop 退出。
2. write loop 退出。
3. setup 失败。
4. inbound packet subscription 失败。
5. task 被 abort/drop。
6. 正常 stop。

建议：

1. 增加 `NativeTunRuntimeGuard`。
2. guard drop 时：
   - `metrics.set_running(false)`
   - `metrics.set_interface_name(None)` 或保留 last interface，二选一但要文档一致
   - `metrics.set_last_error(...)` 如果异常退出
3. `NativeTunSetupGuard` 只负责系统路由清理，不负责 metrics lifecycle。

#### P0-3：清理 warning

当前 warning：

```text
unused import FlowProtocol in src/inbound/native_tun.rs
unused import Instant in src/inbound/native_tun_flow.rs
unused variable ipv4 in src/inbound/native_tun.rs
CleanupAction::RemoveAddress never constructed in src/inbound/native_tun_system.rs
```

处理方式：

1. 删除未使用 import。
2. 把 `TunIpPacket::Ipv4(ipv4)` 如果未使用改成 `TunIpPacket::Ipv4(_)`。
3. `CleanupAction::RemoveAddress` 如果确实不用，删除；如果应该用于 Linux/macOS address cleanup，就补全实际使用。
4. 最终 `cargo check --tests` 不应出现这些 warning。

#### P0-4：README 状态对齐

README 里不能出现和代码相反的描述。

当前重点：

1. 如果 Hysteria v1 仍没有真实互通验证，不要写 complete。
2. 如果 OpenVPN 仍是 parser/profile/status，不要写 real dialing。
3. 如果 NativeL3 route/bypass 没完全修，不要写 fully supported。
4. 如果 metrics 真实接入了，可以写 metrics enabled，但要说明覆盖范围。

### 3.4 P0 验收标准

```bash
cargo check --tests
cargo run -- check -c skyhook.example.yaml
```

人工检查：

```text
/skyhook/tun/status.running 来自真实 metrics
NativeTun 停止后 running=false
无新增 warning
README 不夸大
```

---

## 4. P1：NativeL3 route/bypass 生命周期修正

### 4.1 目标

NativeL3 的系统路由必须真实、可解释、可清理。bypass 不能只是写进 metrics，更不能错误地 route 到 TUN。

### 4.2 当前问题

当前代码里：

```text
src/inbound/native_tun.rs
metrics.set_bypass_routes(plan.bypass.clone())
```

但是：

```text
src/inbound/native_tun_system.rs
build_macos_commands() 只生成 route_add，不生成真正的 bypass route。
```

另外：

```text
SetupCommand::RouteExclude 的 shell command 仍然是:
route -n add -net <cidr> -interface <tun>
```

这不是 bypass，反而会把排除网段送进 TUN。虽然目前 macOS builder 没有发出 `RouteExclude`，
但这个 enum 保留着很危险，后续一旦使用就会出错。

### 4.3 要修的文件

```text
src/inbound/native_tun_system.rs
src/inbound/native_tun.rs
src/inbound/native_tun_metrics.rs
src/config/mod.rs
skyhook.example.yaml
README.md
tests/config_and_runtime.rs
```

### 4.4 设计要求

#### P1-1：明确 route 类型

不要再用模糊的 `RouteExclude`。

建议改成：

```rust
enum SetupCommand {
    Ifconfig { interface: String, args: String },
    RouteAddTun { cidr: String, interface: String },
    RouteAddGateway { cidr: String, gateway: IpAddr },
    RouteAddInterface { cidr: String, interface: String },
    IpAddrAdd { addr: String, interface: String },
    IpLinkSet { interface: String, mtu: u16 },
    IpRouteAddTun { cidr: String, interface: String },
    IpRouteAddGateway { cidr: String, gateway: IpAddr },
}
```

命名必须表达真实行为：

1. `RouteAddTun` 表示进 TUN。
2. `RouteAddGateway` 表示走原网关。
3. `RouteAddInterface` 表示走指定物理 interface。
4. 不要再出现名字叫 exclude 但命令还是指向 TUN 的情况。

#### P1-2：bypass 要么真实安装，要么明确不安装

规则：

1. 如果 `tun.auto_route=false`，通常不需要 bypass route。
2. 如果 `tun.auto_route=true` 且 route_add 里包含默认路由或大网段，bypass 才有意义。
3. bypass 的真实含义是：这些 CIDR 不走 TUN，而走原始网络出口。
4. macOS 上需要先解析原始 default gateway 和 default interface。
5. 如果拿不到原始 gateway/interface，不要假装安装 bypass。
6. metrics 只能记录实际执行成功的 bypass，不记录 plan 里的理论值。

macOS 可选实现：

```text
route -n get default
```

解析：

```text
gateway: 192.168.x.1
interface: en0
```

对 IPv4 bypass：

```text
route -n add -net <cidr> <gateway>
```

或者当 gateway 不存在但 interface 可用时：

```text
route -n add -net <cidr> -interface <physical-interface>
```

不要用 TUN interface 安装 bypass。

Linux 可选实现：

```text
ip route show default
ip route add <cidr> via <gateway>
```

如果不实现 Linux bypass：

1. 返回清晰的 unsupported reason。
2. 不要记录为 installed。
3. README 诚实写 macOS-only 或 pending。

#### P1-3：execute_setup_plan 返回实际安装结果

当前 `execute_setup_plan(&plan)` 只返回 guard。

建议改成：

```rust
pub struct NativeTunSetupResult {
    pub guard: NativeTunSetupGuard,
    pub installed_routes: Vec<String>,
    pub installed_bypass_routes: Vec<String>,
    pub skipped_bypass_routes: Vec<String>,
    pub warnings: Vec<String>,
}
```

然后：

```rust
let result = execute_setup_plan(&plan).await?;
metrics.set_routes(result.installed_routes);
metrics.set_bypass_routes(result.installed_bypass_routes);
metrics.set_setup_warnings(result.warnings);
```

不要再用：

```rust
metrics.set_bypass_routes(plan.bypass.clone());
```

#### P1-4：cleanup 必须对称

每个成功执行的 route add，都要有对应 cleanup command。

要求：

1. 如果 route add 第 3 条失败，前 2 条必须 cleanup。
2. `NativeTunSetupGuard` drop 时执行 cleanup。
3. cleanup 失败不能 panic，但要记录 warning。
4. metrics 里要记录 cleanup status 或 last cleanup error。

#### P1-5：避免代理服务器回环

如果正在使用某个 L3 profile 或 outbound server，例如 WireGuard endpoint：

```text
server = 1.2.3.4
port = 51820
```

那么这个 endpoint IP 必须自动加入 bypass，否则 full-tunnel 很容易把“连接代理服务器的流量”也送进 TUN，造成回环。

实现：

1. Runtime 启动 NativeL3 前收集 active profile endpoint IP。
2. `NativeTunSetupPlan` 增加 `endpoint_bypass`。
3. endpoint bypass 优先级高于用户 bypass。
4. metrics 区分：

```json
{
  "bypass_routes_installed": ["192.168.0.0/16"],
  "endpoint_bypass_routes_installed": ["1.2.3.4/32"]
}
```

如果域名 endpoint 没解析出 IP：

1. 不阻塞启动。
2. telemetry warning。
3. DNS 解析成功后可以异步补装 endpoint route。

### 4.5 P1 测试建议

单元测试不需要真实改系统路由，用 command builder 验证。

新增测试：

```text
native_tun_macos_route_add_uses_tun_interface
native_tun_macos_bypass_uses_original_gateway_not_tun
native_tun_metrics_only_records_installed_bypass
native_tun_cleanup_is_symmetric
native_tun_endpoint_bypass_added_for_l3_endpoint
native_tun_route_exclude_removed_or_not_tun
```

### 4.6 P1 验收标准

```text
1. 没有任何 bypass command 指向 TUN interface。
2. metrics 只展示实际安装成功的路由。
3. route setup 失败会清理已安装路由。
4. stop 后路由被清理。
5. README 写清支持范围。
```

---

## 5. P2：NativeL3 智能分流真实执行路径

### 5.1 目标

当前 NativeL3 做了 packet parse 和 decision，但没有真正把普通 stream 节点、代理组、国家组、direct/reject 执行起来。

要实现用户真正要的能力：

```text
不同 domain / IP / app 可以走指定节点
可以走指定代理组
可以走指定国家自动择优
可以 direct
可以 reject
可以继续走 L3 tunnel profile
```

### 5.2 当前问题

当前逻辑大致是：

```rust
let decision = runtime.decide(&destination);
let target_profile = decision.outbound;
runtime.send_l3_ip_packet(&target_profile, packet).await;
```

问题：

1. `send_l3_ip_packet()` 只接受 L3 profile。
2. 普通 outbound 不是 L3 profile。
3. group/country/direct/reject 也不是 L3 profile。
4. 所以 decision 算出来了，但实际执行路径不对。

不能再继续让它“看起来做了智能分流”，但所有包最后还是塞给一个 L3 profile。

### 5.3 核心设计

需要把 NativeL3 的 packet ingress 分成两类：

```text
Raw IP packet path:
  适合 WireGuard/OpenVPN 这种 L3 tunnel profile。

L4 session path:
  适合普通 TCP/UDP proxy outbound、direct、group、country。
```

也就是说：

```text
TUN packet
  -> packet classifier
  -> route decision
  -> if target is L3 profile:
       send original IP packet to L3 manager
     else if target is stream-capable TCP outbound:
       terminate TCP session locally, open outbound stream, pump bytes
     else if target is direct TCP:
       terminate TCP session locally, connect target directly, pump bytes
     else if target is UDP outbound:
       terminate UDP flow locally, relay datagrams
     else if reject:
       drop / send RST or ICMP unreachable where possible
```

### 5.4 推荐实现方案：引入 smoltcp session engine

Rust 里自己手写 TCP state machine 不现实。建议引入 `smoltcp` 做 TUN packet -> TCP/UDP socket session。

新增模块建议：

```text
src/inbound/native_tun_stack.rs
src/inbound/native_tun_session.rs
src/inbound/native_tun_router.rs
src/inbound/native_tun_process.rs
```

职责：

```text
native_tun_stack.rs
  smoltcp interface/device/socketset
  把 TUN IP packets 喂给 smoltcp
  从 smoltcp 取出需要写回 TUN 的 IP packets

native_tun_session.rs
  TCP/UDP session lifecycle
  session -> runtime outbound/direct connection
  bidirectional pump
  backpressure / timeout / cleanup

native_tun_router.rs
  将 Runtime::decide() 的结果规范化成可执行 RouteTarget

native_tun_process.rs
  macOS/Linux flow -> PID/app/bundle 解析
```

### 5.5 RouteTarget 必须明确

新增类似结构：

```rust
pub enum NativeRouteTarget {
    Direct,
    Reject { reason: String },
    Outbound { name: String },
    Group { name: String },
    Country { code: String },
    L3Profile { name: String },
}
```

不要继续只用 `String outbound` 表示所有目标。一个字符串无法区分：

```text
direct
reject
节点名
代理组名
国家组
L3 profile
```

### 5.6 Runtime 需要暴露可执行 resolver

新增 Runtime 方法：

```rust
pub fn resolve_route_target(&self, decision: RoutingDecision) -> NativeRouteTarget
```

或者：

```rust
pub async fn resolve_native_route(
    &self,
    flow: &NativeFlowMetadata,
) -> NativeRouteDecision
```

要求：

1. 用户自定义规则优先级最高。
2. 智能学习启用规则优先级高于订阅规则。
3. 订阅规则作为 fallback。
4. 手动指定节点高于自动择优。
5. 国家组自动择优要基于后台健康度，不要阻塞当前连接测速。
6. 如果目标节点不可用，根据 policy fallback：
   - strict: reject
   - fallback: selected group best
   - direct-fallback: direct

### 5.7 TCP session 执行

TCP 必须这样做：

1. smoltcp 接收来自 TUN 的 SYN。
2. 为该 flow 创建 session。
3. 提取目标：
   - dst IP/port
   - DNS cache 反查 domain
   - TLS SNI
   - HTTP Host
   - process/app metadata
4. 调用 routing decision。
5. 根据 `NativeRouteTarget`：
   - Direct: `tokio::net::TcpStream::connect(dst)`
   - Outbound: 使用指定 outbound 的 connect 方法
   - Group: resolve 到当前 selected/best outbound 后 connect
   - Country: resolve 到该国家低延迟可用 outbound 后 connect
   - L3Profile: 不进入 TCP termination，走 raw packet path
   - Reject: drop/RST
6. 建立两个 pump：
   - smoltcp socket -> remote stream
   - remote stream -> smoltcp socket
7. 记录 metrics：
   - tx/rx bytes
   - target name
   - decision source
   - latency first byte
   - close reason

注意：

1. 对 HTTPS，SNI 通常在 TCP 建立后的 ClientHello 才有，可能需要先接受 socket 并 buffer 前几个 KB。
2. 如果先根据 IP 选路，后续发现 SNI 命中更高优先级规则，可以：
   - 对新 flow 生效，不中途迁移。
   - 或在未真正 dial 前短暂等待 first payload。
3. 建议实现短等待策略：

```text
wait_first_payload_max_ms = 100
max_sniff_bytes = 4096
```

### 5.8 UDP session 执行

UDP 必须这样做：

1. 按 5-tuple 建 session。
2. DNS UDP/53 优先被 DNS hijack 处理。
3. 非 DNS UDP 根据规则：
   - Direct: UDP socket direct
   - Outbound: 调 outbound UDP relay，如果该 outbound 支持 UDP
   - Group/Country: resolve 到支持 UDP 的节点
   - L3Profile: raw packet path
   - Reject: drop
4. 如果目标 outbound 不支持 UDP：
   - 记录 `udp_unsupported`
   - 根据 fallback policy 尝试下一个节点
   - 不能静默成功

### 5.9 L3Profile raw packet path

只有目标是 L3 profile 时才能调用：

```rust
runtime.send_l3_ip_packet(&profile, packet).await
```

必须先判断：

```rust
runtime.is_l3_profile(name)
```

如果不是 L3 profile，禁止调用 `send_l3_ip_packet()`。

新增测试：

```text
native_route_target_outbound_does_not_call_send_l3_ip_packet
native_route_target_l3_profile_calls_send_l3_ip_packet
native_route_target_direct_uses_l4_session
native_route_target_reject_drops_flow
```

### 5.10 app 识别

TUN packet 本身没有 app 名，需要通过 OS flow -> PID/app 解析。

macOS 方案：

1. 先实现缓存和接口。
2. 后端可以用：
   - `lsof -nP -iTCP`
   - `netstat`
   - `sysctl net.inet.tcp.pcblist`
   - 后续可替换成 NetworkExtension 更准确来源
3. 用 flow 5-tuple 查询 PID。
4. PID -> process path -> bundle id。
5. 缓存 TTL 2-5 秒。
6. 查不到 app 不阻塞连接，只是不匹配 app rule。

接口建议：

```rust
pub struct ProcessMetadata {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub executable_path: Option<String>,
}
```

### 5.11 P2 验收标准

必须满足：

```text
1. 普通节点/代理组/direct/reject 不再误走 send_l3_ip_packet。
2. L3 profile 仍然可以走 raw packet path。
3. TCP flow 能通过 selected outbound 建立连接。
4. UDP flow 能按 capability 选择支持 UDP 的目标。
5. app/domain/ip 元数据进入 flow decision。
6. metrics 能看到每个 flow 的 route target 和 bytes。
7. 不支持的路径必须明示 rejected/unsupported，不能假成功。
```

---

## 6. P3：智能规则原生能力落地

### 6.1 目标

Skyhook 的方向不是让用户维护复杂规则，而是核心自动学习：

```text
访问了什么 domain/ip/app
直连能不能通
代理能不能通
哪个节点/国家延迟低
下次应该 direct 还是 proxy
用户启用后变成高优先级规则
```

### 6.2 要修的文件

```text
src/smart/mod.rs
src/core/mod.rs
src/routing/mod.rs
src/api/mod.rs
src/inbound/native_tun_flow.rs
src/inbound/native_tun_router.rs
src/telemetry/mod.rs
src/config/mod.rs
skyhook.example.yaml
README.md
tests/config_and_runtime.rs
```

### 6.3 数据模型

新增或补强：

```rust
pub enum SmartSubject {
    Domain(String),
    Ip(IpAddr),
    Cidr(IpNet),
    AppBundle(String),
    ProcessName(String),
}

pub enum SmartAction {
    Direct,
    Proxy,
    Reject,
    Outbound(String),
    Group(String),
    Country(String),
    L3Profile(String),
}

pub enum SmartRuleSource {
    User,
    LearnedEnabled,
    LearnedRecommendation,
    Subscription,
    Default,
}

pub struct SmartRule {
    pub id: String,
    pub subject: SmartSubject,
    pub action: SmartAction,
    pub enabled: bool,
    pub priority: i32,
    pub source: SmartRuleSource,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub hit_count: u64,
    pub last_hit_at: Option<DateTime<Utc>>,
    pub evidence: SmartRuleEvidence,
}
```

### 6.4 规则优先级

必须固定下来：

```text
1. User enabled app/domain/ip/cidr rule
2. Learned enabled rule
3. Temporary session override
4. Subscription rule
5. Smart recommendation not enabled
6. Default route policy
```

注意：

推荐列表里的东西如果用户没有启用，不应该直接改变路由。

### 6.5 统计能力

用户要的智能规则页顶部统计，本质需要核心 API 支撑。

必须统计：

```text
1. 规则中走代理，但 direct 也可以连接的比例
2. 推荐 direct 数量
3. 推荐 proxy 数量
4. 已启用 learned direct 数量
5. 已启用 learned proxy 数量
6. 用户规则数量
7. 最近 24 小时观察 domain/ip/app 数量
8. direct probe 成功率
9. proxy probe 成功率
10. 因超时标记不可用的数量
```

建议 API：

```text
GET  /skyhook/smart/stats
GET  /skyhook/smart/recommendations?kind=direct
GET  /skyhook/smart/recommendations?kind=proxy
POST /skyhook/smart/recommendations/enable
POST /skyhook/smart/recommendations/enable-all
GET  /skyhook/smart/rules
POST /skyhook/smart/rules
PUT  /skyhook/smart/rules/:id
DELETE /skyhook/smart/rules/:id
```

### 6.6 后台 direct/proxy probe

不要在用户请求链路上同步 probe，避免拖慢代理。

后台 worker：

```text
smart_probe_worker
  interval: configurable
  concurrency: configurable
  timeout_ms: configurable
  max_pending: configurable
```

配置建议：

```yaml
smart:
  enabled: true
  learning:
    enabled: true
    store_path: ~/.skyhook/smart-rules.json
  probe:
    enabled: true
    interval_secs: 600
    timeout_ms: 500
    concurrency: 32
    direct_probe_timeout_ms: 500
    proxy_probe_timeout_ms: 800
```

注意用户之前明确说过：

```text
节点超过 500ms 的就直接当超时不用测试
```

所以节点延迟 probe timeout 默认要支持配置，默认可以是 500ms。

### 6.7 推荐规则生成逻辑

规则：

```text
如果某 domain/ip 当前走代理，但 direct probe 成功：
  推荐 direct

如果某 domain/ip direct probe 失败，但 proxy 成功：
  推荐 proxy

如果 direct/proxy 都失败：
  不推荐，标记 unreachable

如果 direct 成功但质量明显差于 proxy：
  可以推荐 proxy，但 reason 必须写 latency/timeout evidence
```

推荐必须带 evidence：

```json
{
  "subject": "youtube.com",
  "recommendation": "proxy",
  "reason": "direct timeout, proxy 83ms",
  "direct": {
    "ok": false,
    "latency_ms": null,
    "error": "timeout"
  },
  "proxy": {
    "ok": true,
    "latency_ms": 83,
    "outbound": "JP-01"
  },
  "last_observed_at": "...",
  "hit_count": 12
}
```

### 6.8 启用推荐

单条启用：

```text
POST /skyhook/smart/recommendations/enable
body:
{
  "id": "...",
  "action": "direct" | "proxy" | "outbound" | "group" | "country",
  "target": "..."
}
```

全部启用：

```text
POST /skyhook/smart/recommendations/enable-all
body:
{
  "kind": "direct",
  "max_age_secs": 604800,
  "min_confidence": 0.7
}
```

启用后：

1. 写入 durable store。
2. source = LearnedEnabled。
3. priority 高于 subscription。
4. API 返回 enabled count 和 skipped count。

### 6.9 P3 验收标准

```text
1. smart stats API 能返回代理但 direct 可连比例。
2. recommendation API 能列出 recommended direct/proxy。
3. enable single 和 enable all 都会写入规则 store。
4. enabled learned rule 优先级高于 subscription rule。
5. NativeL3 和 stream inbound 都使用同一套 smart decision。
6. direct/proxy probe 后台运行，不阻塞实时连接。
7. timeout_ms 可配置，默认尊重 500ms 快速失败策略。
```

---

## 7. P4：协议真实可拨号能力

### 7.1 总原则

“真实可拨号”定义：

```text
给一个真实节点配置，Skyhook 可以完成协议握手，建立真实连接，真实收发数据。
```

不是：

```text
能 parse
能保存配置
能 round-trip
能显示在列表
能返回 status
能创建 placeholder outbound
```

### 7.2 Hysteria v1

当前状态：

1. `OutboundConfig::Hysteria` 存在。
2. `HysteriaOutbound` 存在。
3. capability 仍写 `hysteria udp is not supported`。
4. `obfs` 仍写 not implemented。
5. README 仍有 planned/not implemented 文案。
6. 没有真实服务端互通测试证据。

任务：

1. 确认 Hysteria v1 协议细节，不要照搬 Hysteria2。
2. 梳理 auth/auth_str、ALPN、QUIC stream、UDP relay、obfs 的真实语义。
3. TCP connect 必须能和真实 Hysteria v1 server 建立 stream。
4. UDP 如果暂时不做，capability 必须明确 `udp_supported=false`。
5. 如果 obfs 不做，配置中出现 obfs 必须明确 fail，不要静默忽略。
6. 增加 ignored integration test：

```text
HYSTERIA_V1_TEST_SERVER
HYSTERIA_V1_TEST_PORT
HYSTERIA_V1_TEST_AUTH
```

7. README 只有在真实互通后才能改成 supported。

验收：

```text
1. hysteria:// URI parse 到 OutboundConfig::Hysteria。
2. Clash YAML hysteria parse 到 OutboundConfig::Hysteria。
3. capability 不再误报 unsupported。
4. 真实 server ignored integration test 可运行。
5. probe_outbounds 能测 Hysteria v1 TCP。
```

### 7.3 OpenVPN

当前状态：

1. `.ovpn` parser/profile 已有。
2. L3 manager 能发现 profile。
3. `start_l3(openvpn)` 仍返回 Unsupported。
4. 控制通道、TLS、data channel 都没实现。

OpenVPN 是大任务，不要一口吃成假的。

建议分三层：

```text
Layer 1: parser/profile 完整性
Layer 2: control channel + TLS handshake
Layer 3: data channel encrypt/decrypt + TUN packet bridge
```

#### Layer 1：parser/profile

补齐：

```text
remote
proto udp/tcp
dev tun
cipher
auth
tls-auth / tls-crypt
ca/cert/key inline block
auth-user-pass
reneg-sec
remote-cert-tls
verify-x509-name
compress/comp-lzo
```

明确不支持：

```text
tap mode
compression
static key legacy mode
```

不支持时必须 status/limitations 清楚。

#### Layer 2：control channel

要做：

1. OpenVPN packet opcode parse/serialize。
2. Session id。
3. reliable ack。
4. TLS over OpenVPN control packets。
5. server pushed options parse。
6. key material extraction。

#### Layer 3：data channel

要做：

1. data packet encrypt/decrypt。
2. replay window。
3. keepalive/ping。
4. TUN packet -> OpenVPN data packet -> network。
5. network -> OpenVPN decrypt -> TUN packet channel。
6. metrics tx/rx。

验收：

```text
1. start_l3(openvpn) 不再返回 Unsupported，仅当配置真的不支持时才返回 Unsupported。
2. 真实 OpenVPN server ignored integration test 能通过。
3. TUN packet 能经 OpenVPN 出去，回包能回到 TUN。
4. README 不再说 parser only。
```

### 7.4 SSR/Snell/ShadowTLS/AnyTLS/Naive/Mieru/Juicity/MASQUE

当前优先级低于 NativeL3 智能分流，但不能隐藏差距。

建议顺序：

```text
1. SSR 完整 method/protocol/obfs 覆盖
2. Snell UDP/TLS obfs 补齐
3. ShadowTLS v1/v2/v3 行为确认
4. AnyTLS UDP/edge case
5. Naive 如果配置里已有，确认是否真实 connect
6. Mieru/Juicity/MASQUE 继续 unsupported，但 capability/README 诚实
```

每个协议完成标准：

```text
parse config
build outbound
capability 正确
probe 可运行
真实 server ignored integration test
README 更新
```

---

## 8. P5：节点测速、国家择优、超时配置

### 8.1 目标

用户要求：

```text
原生支持节点测试 timeout ms 设置
节点超过 500ms 直接当超时
后台定时测速不影响代理使用
国家组自动选择低延迟节点
启动代理时优先使用上次节点，失败才全局测速
节点页面能测试所有节点，包括之前因超时不可用的
```

### 8.2 要修的文件

```text
src/core/mod.rs
src/telemetry/mod.rs
src/api/mod.rs
src/config/mod.rs
src/subscription_store.rs
src/smart/mod.rs
skyhook.example.yaml
README.md
```

### 8.3 配置

建议：

```yaml
probe:
  timeout_ms: 500
  concurrency: 64
  interval_secs: 600
  include_unavailable_on_manual_all: true
  background:
    enabled: true
    max_parallel_per_subscription: 16
    low_priority: true
  startup:
    use_last_selected_first: true
    global_probe_if_last_failed: true
```

### 8.4 API

建议：

```text
POST /skyhook/probes/all
POST /skyhook/probes/subscription/:id
POST /skyhook/probes/country/:code
GET  /skyhook/probes/status
GET  /skyhook/probes/results
PUT  /skyhook/probes/config
```

### 8.5 后台测速要求

1. 使用单独 tokio task。
2. 使用 semaphore 限并发。
3. 不抢占实时连接线程。
4. 不因为一个节点慢拖住全部。
5. timeout 到立即标记 timeout。
6. 手动“测速所有节点”必须包含不可用节点。
7. 自动测速可以跳过近期连续失败节点，但要有冷却时间。
8. 结果持久化。

### 8.6 国家择优

国家识别来源优先级：

```text
1. subscription node metadata / name parse
2. server IP geo
3. provider supplied country
4. unknown
```

国家组选择：

```text
eligible nodes = 当前订阅中该国家节点
filter = alive && latency_ms <= timeout_ms
sort = latency_ms asc, recent failure count asc
select = first
fallback = previous selected if still alive, else group policy fallback
```

### 8.7 验收标准

```text
1. timeout_ms 可配置，默认 500。
2. 手动测速所有节点包含 unavailable。
3. 后台测速不会阻塞 connect。
4. 国家组能基于最新健康度择优。
5. 启动代理优先使用上次节点。
6. 上次节点失败才触发更大范围测速。
```

---

## 9. API 和数据持久化收口

### 9.1 目标

Skyhook 需要把核心状态保存清楚。不能只在内存里“看起来能用”。

### 9.2 必须持久化

```text
subscriptions
selected subscription
selected group/node per subscription
traffic counters per subscription
probe results per node
country grouping cache
smart observations
smart recommendations
enabled smart rules
last used node
last successful node
native tun metrics snapshot summary
```

### 9.3 文件建议

```text
~/.skyhook/subscriptions.json
~/.skyhook/probe-results.json
~/.skyhook/smart-rules.json
~/.skyhook/traffic-counters.json
~/.skyhook/runtime-state.json
```

测试里不要写真实 home，必须支持临时目录。

### 9.4 API 必须返回 subscription scope

所有和订阅有关的指标都要带：

```text
subscription_id
subscription_name
provider_url_hash
updated_at
```

用户之前明确要求：

```text
总流量按订阅累计，不同订阅显示该订阅从添加开始使用的所有流量。
```

Skyhook core API 要支撑这一点。

---

## 10. 文档更新要求

最后统一改：

```text
README.md
skyhook.example.yaml
docs/MIMO_SKYHOOK_DEVELOPMENT_GUIDE.md
docs/检查结果.md 或新增 docs/POST_REVIEW_FIX_RESULT.md
```

文档必须遵守：

1. 已完成才写 supported。
2. 未完成写 planned/unsupported，并说明原因。
3. parser only 不能写 real dialing。
4. L3 profile manager 不能写 stream outbound。
5. NativeL3 如果只支持 macOS，要写 macOS。
6. 需要 sudo/root 的地方要写清楚。
7. API 示例要和真实返回一致。

---

## 11. 最终统一验证

MiMo 完成开发后，统一跑：

```bash
cargo fmt --all
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

如果有真实环境：

```bash
sudo target/debug/skyhook run -c skyhook.example.yaml
```

手动验证 checklist：

```text
[ ] NativeL3 creates real utun
[ ] address assigned
[ ] route_add installed
[ ] bypass route does not point to tun
[ ] endpoint bypass exists for active L3 endpoint
[ ] /skyhook/tun/status running=true while running
[ ] /skyhook/tun/status running=false after stop
[ ] /skyhook/tun/metrics bytes increase when traffic flows
[ ] direct route works
[ ] selected outbound route works
[ ] group route works
[ ] country route works
[ ] reject route works
[ ] L3 profile raw packet route works
[ ] smart recommendations generated
[ ] enable one smart rule works
[ ] enable all smart direct rules works
[ ] enabled smart rules override subscription rules
[ ] background probe runs without blocking traffic
[ ] manual probe all includes unavailable nodes
[ ] Hysteria v1 status is honest
[ ] OpenVPN status is honest or truly dials
```

---

## 12. MiMo 最终输出格式

完成后请按下面格式输出，不要只说“已全部修复”：

```text
## Completed

1. ...
2. ...

## Files Changed

- path: summary

## Runtime Behavior Changed

1. ...
2. ...

## Validation

- cargo fmt --all: pass/fail
- cargo check --tests: pass/fail
- cargo test --all-targets: pass/fail
- cargo run -- check -c skyhook.example.yaml: pass/fail
- manual NativeL3 macOS run: pass/fail/not run, reason
- real Hysteria v1 integration: pass/fail/not run, reason
- real OpenVPN integration: pass/fail/not run, reason

## Still Not Complete

1. ...
2. ...

## Risks

1. ...
2. ...
```

---

## 13. 绝对完成定义

只有同时满足下面条件，才能说这轮完成：

```text
1. TUN status 不再用配置假装运行态。
2. metrics 是真实 runtime packet/byte/error 数据。
3. bypass 不再错误指向 TUN。
4. installed routes 和 metrics 展示一致。
5. NativeL3 decision 结果能执行 direct/outbound/group/country/reject/L3Profile。
6. app/domain/ip 指定路由可以进入核心决策。
7. 智能推荐可以统计、展示、单条启用、全部启用。
8. 启用后的智能规则高于订阅规则。
9. 节点 probe timeout 可配置，默认 500ms。
10. 后台 probe 不影响实时代理。
11. 国家择优使用健康度结果，不同步阻塞测速。
12. Hysteria v1/OpenVPN 要么真实可拨号，要么诚实标注未完成。
13. README 和 example config 与真实代码一致。
14. 全量测试最后通过。
```

如果其中任何一条不满足，就不要说“全部修复”。
