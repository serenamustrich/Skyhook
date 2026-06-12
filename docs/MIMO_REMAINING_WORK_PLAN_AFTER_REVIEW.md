# MiMo Remaining Work Plan After Review

生成时间：2026-06-12

工程目录：

```text
/Users/chency/Downloads/clash/Skyhook
```

目标读者：MiMo

本文是基于最新一次复查后的“剩余开发任务计划”。不要再按旧文档里的历史状态执行，
也不要只跑测试后说“全部修复”。当前代码已经能通过大部分测试，但还有几个核心问题
没有真正完成。

---

## 0. 当前真实状态

### 0.1 已经做得不错的部分

下面这些可以视为已有基础，不要推倒重来：

1. `cargo test --all-targets` 当前通过。
2. `cargo run -- check -c skyhook.example.yaml` 当前通过。
3. `/skyhook/tun/status.running` 已经改为读取 `NativeTunMetricsSnapshot.running`。
4. `NativeTunRuntimeGuard` 已经会在 drop 时把 running 置为 false。
5. `NativeTunMetrics` 已经接入 read/write/error/drop 计数。
6. `NativeRouteTarget` 已经有基础枚举：

```rust
Direct
Reject
Outbound
Group
Country
L3Profile
```

7. `resolve_native_route()` 已经能把 `RouteDecision` 转成 `NativeRouteTarget`。
8. 智能规则已有 snapshot/stats/recommendations/apply-one/apply-all API。
9. smart rules 已经在 stream/mixed connect path 里优先于普通 router。
10. OpenVPN 仍诚实标记为 unsupported/parser only，没有乱说完成。
11. README 对部分未完成能力已经有诚实说明。

### 0.2 不能说完成的部分

以下仍然没完成，必须继续修：

1. NativeL3 对 `Direct/Outbound/Group/Country` 的真实执行路径没有实现。
2. NativeL3 当前除了 `L3Profile` 和 `Reject`，其他 route target 仍 fallback 到默认 L3 profile。
3. `route_exclude_address` 在 NativeL3 里仍被加进 `route_add`，方向是错的。
4. bypass route 的 cleanup 会用 TUN interface 删除，和安装时的 gateway route 不对称。
5. endpoint bypass 只是把 L3 endpoint 字符串塞进去，`host:port` 或域名不会变成真实 CIDR。
6. `cargo fmt --all -- --check` 当前失败。
7. Hysteria v1 没有真实互通证明。
8. OpenVPN 仍不是真实拨号。
9. NativeL3 没有用户态 TCP/IP stack，所以 TUN 里的普通代理节点分流还不能真正工作。

---

## 1. 本轮必须遵守的规则

### 1.1 不要做这些事

1. 不要改旧的玥球电梯 app。
2. 不要做双核心。
3. 不要做 Mihomo wrapper。
4. 不要把 parse/profile/status 说成真实拨号。
5. 不要把 `Direct/Outbound/Group/Country` fallback 到 L3 profile 后说分流完成。
6. 不要用测试假数据证明真实网络能力。
7. 不要隐藏 unsupported protocol。
8. 不要删除其他 agent 或用户留下的未提交改动。
9. 不要把 `route_exclude_address` 当作 route_add。
10. 不要在 README 里夸大能力。

### 1.2 本轮优先级

严格按下面顺序做：

```text
P0: 格式和当前明显失败项收口
P1: NativeL3 route_exclude / bypass / cleanup / endpoint bypass 修正确
P2: NativeL3 非 L3 目标不要再假 fallback，先做到行为诚实
P3: NativeL3 普通代理目标真实执行路径，引入用户态 TCP/IP stack
P4: 智能规则和 NativeL3 flow metadata 对齐
P5: 节点测速、国家组、后台 probe 收口
P6: 协议真实拨号差距继续推进或诚实保留
P7: 文档和最终验证
```

如果时间有限，必须先完成 P0-P2。P3 是大任务，但不能继续假装完成。

---

## 2. P0：格式和当前明显失败项收口

### 2.1 当前问题

`cargo fmt --all -- --check` 失败，涉及至少：

```text
src/inbound/native_tun.rs
src/inbound/native_tun_packet.rs
src/inbound/native_tun_system.rs
```

### 2.2 要做什么

1. 运行：

```bash
cargo fmt --all
```

2. 不要手工大范围改格式。
3. 格式化后跑：

```bash
cargo fmt --all -- --check
cargo check --tests
```

4. 如果 `cargo fmt` 改了大量文件，检查是否只是格式变化。

### 2.3 验收标准

```text
cargo fmt --all -- --check 通过
cargo check --tests 通过
没有新增 warning
```

---

## 3. P1：NativeL3 route/bypass/cleanup 逻辑修正确

这是当前最重要的“系统路由安全”问题。没修好之前，NativeL3 可能破坏本机路由。

### 3.1 当前问题 A：route_exclude_address 方向错了

当前普通 TUN backend 里：

```text
src/inbound/tun.rs
effective_bypass() 会把 config.tun.route_exclude_address 合并进 bypass
```

但是 NativeL3 里：

```text
src/inbound/native_tun_system.rs
NativeTunSetupPlan::from_config()
route_add.extend(config.route_exclude_address.clone())
```

这会把“排除路由”变成“进入 TUN 的路由”。

### 3.2 修复要求 A

修改：

```text
src/inbound/native_tun_system.rs
```

把：

```rust
route_add.extend(config.route_exclude_address.clone());
```

改成：

```rust
bypass.extend(config.route_exclude_address.clone());
```

但不要只改这一行，还必须做测试。

新增测试：

```text
native_l3_route_exclude_goes_to_bypass_not_route_add
```

测试必须断言：

```rust
assert!(!plan.route_add.contains(&"10.0.0.0/8".to_string()));
assert!(plan.bypass.contains(&"10.0.0.0/8".to_string()));
```

### 3.3 当前问题 B：bypass cleanup 和安装命令不对称

当前 `SetupCommand::RouteAddGateway` 的 `to_cleanup_command()` 是对的：

```text
route -n delete -net <cidr> <gateway>
```

但是 `execute_setup_plan()` 成功后只调用：

```rust
guard.record_route_added(route.clone());
```

`NativeTunSetupGuard::cleanup()` 里对所有 route 都用：

```text
route -n delete -net <cidr> -interface <tun>
```

所以 gateway bypass 安装时是：

```text
route -n add -net 192.168.0.0/16 192.168.1.1
```

清理时却变成：

```text
route -n delete -net 192.168.0.0/16 -interface utunX
```

这很可能删不掉。

### 3.4 修复要求 B

重构 cleanup，不要只存 cidr。

推荐方案：

```rust
#[derive(Debug, Clone)]
enum CleanupAction {
    Command(String),
}
```

或者：

```rust
#[derive(Debug, Clone)]
enum CleanupAction {
    DeleteRoute { cleanup_command: String },
    RemoveAddress { cleanup_command: String },
}
```

执行 setup command 成功后：

```rust
if let Some(cleanup) = cmd.to_cleanup_command() {
    guard.record_cleanup_command(cleanup);
}
```

不要在 cleanup 阶段重新猜命令。

### 3.5 修复要求 C：setup 失败时 rollback

当前 `execute_setup_plan()` 对某些失败只是记录 warning 然后继续。需要区分：

```text
fatal commands:
  ifconfig / ip addr add
  route add tun / ip route add tun

non-fatal commands:
  bypass route add gateway
  endpoint bypass route add gateway
```

规则：

1. 地址配置失败：fatal，清理已经执行的命令并返回 Err。
2. 主路由进入 TUN 失败：fatal，清理已经执行的命令并返回 Err。
3. bypass route 失败：non-fatal，记录 skipped/warning，继续启动。
4. endpoint bypass 失败：non-fatal 但必须 warning，因为可能产生回环风险。
5. fatal error 发生后，必须执行 rollback。

建议新增：

```rust
impl SetupCommand {
    fn is_fatal(&self) -> bool { ... }
    fn is_bypass(&self) -> bool { ... }
}
```

### 3.6 修复要求 D：metrics 只展示真实安装成功的路由

`NativeTunMetrics` 当前只有：

```rust
routes_installed
bypass_routes_installed
```

建议新增：

```rust
skipped_bypass_routes
setup_warnings
endpoint_bypass_routes_installed
endpoint_bypass_routes_skipped
```

如果不想扩字段，也至少不要把未安装的 endpoint/bypass 放进 installed。

### 3.7 测试要求

新增或改造测试：

```text
native_l3_route_exclude_goes_to_bypass_not_route_add
gateway_bypass_cleanup_uses_gateway_not_tun_interface
tun_route_cleanup_uses_tun_interface
execute_setup_plan_rolls_back_on_fatal_route_failure
execute_setup_plan_skips_bypass_failure_without_claiming_installed
metrics_records_only_installed_routes
```

如果 `execute_setup_plan` 现在直接跑系统命令，不方便测，需要抽象 command runner：

```rust
trait SystemCommandRunner {
    async fn run(&self, command: &str) -> anyhow::Result<()>;
}
```

测试用 fake runner。

### 3.8 P1 验收标准

```text
route_exclude_address 不进入 route_add
bypass command 不指向 tun interface
gateway bypass cleanup 使用 gateway
fatal setup 失败会 rollback
metrics 不展示未安装成功的 bypass
cargo test native_tun_system 通过
```

---

## 4. P2：endpoint bypass 真正可用

### 4.1 当前问题

当前流程：

```rust
let endpoints = runtime.collect_l3_endpoints();
plan.add_endpoint_bypass(endpoints);
```

但是 `collect_l3_endpoints()` 返回的是 L3 snapshot 里的 endpoint 字符串，常见形式是：

```text
1.2.3.4:51820
wg.example.com:51820
```

而 setup 里只接受：

```rust
cidr.parse::<IpNet>().is_ok()
```

所以 `1.2.3.4:51820` 和域名都不会被安装成 bypass route。

### 4.2 修复目标

endpoint bypass 必须能把 active L3 server endpoint 转成真实 route：

```text
IPv4 endpoint -> x.x.x.x/32
IPv6 endpoint -> xxxx::xxxx/128
domain endpoint -> resolve IP -> /32 or /128
```

### 4.3 推荐实现

新增 helper：

```rust
pub async fn collect_l3_endpoint_bypass_cidrs(&self) -> Vec<String>
```

或者在 `native_tun_system.rs` 里做：

```rust
pub async fn normalize_endpoint_bypass(endpoint: &str) -> Vec<String>
```

处理规则：

1. 如果 endpoint 是 `SocketAddr` 字符串：

```text
1.2.3.4:51820 -> 1.2.3.4/32
[2606:4700::1111]:51820 -> 2606:4700::1111/128
```

2. 如果 endpoint 是纯 IP：

```text
1.2.3.4 -> 1.2.3.4/32
2606:4700::1111 -> 2606:4700::1111/128
```

3. 如果 endpoint 是 domain:port：

```text
wg.example.com:51820 -> lookup_host -> all resolved IPs
```

4. 解析失败：

```text
不要阻塞启动
记录 setup warning
记录 skipped endpoint
```

5. 去重。

6. 不要把 port 带进 bypass。

### 4.4 endpoint bypass 安装顺序

必须先解析原始 default gateway，再安装 endpoint bypass，再安装默认路由进 TUN。

顺序建议：

```text
1. resolve default gateway/interface
2. configure TUN address
3. install endpoint bypass via original gateway
4. install user/private bypass via original gateway
5. install TUN route_add
```

这样可以减少代理服务器连接被默认路由抢进 TUN 的风险。

### 4.5 测试要求

新增测试：

```text
endpoint_ip_port_becomes_32_cidr
endpoint_ipv6_port_becomes_128_cidr
endpoint_domain_resolution_failure_is_skipped_not_installed
endpoint_bypass_commands_are_before_default_tun_routes
endpoint_bypass_cleanup_uses_gateway
```

如果 DNS 解析不想在单测里联网，抽象 resolver：

```rust
trait EndpointResolver {
    async fn resolve(&self, host: &str, port: u16) -> anyhow::Result<Vec<IpAddr>>;
}
```

### 4.6 P2 验收标准

```text
active WireGuard endpoint 能变成 /32 或 /128 bypass
domain endpoint 能通过 resolver 转成 IP cidr
endpoint bypass 安装在默认 TUN 路由之前
metrics 能区分 endpoint bypass installed/skipped
```

---

## 5. P3：NativeL3 非 L3 目标不能再假 fallback

这个阶段先做到“不骗人”。即使还没实现 smoltcp，也不能把普通节点目标错误送进 L3 profile。

### 5.1 当前问题

当前 NativeTUN read loop 中：

```rust
match route.target {
    L3Profile { name } => send_l3_ip_packet(name, packet)
    Reject { reason } => record_dropped(reason)
    _ => send_l3_ip_packet(&l3_profile_clone, packet)
}
```

这意味着：

```text
Direct  -> 实际走默认 L3 profile
Outbound -> 实际走默认 L3 profile
Group -> 实际走默认 L3 profile
Country -> 实际走默认 L3 profile
```

这不是分流。

### 5.2 短期必须修正

在真正实现 smoltcp 之前，必须改成：

```rust
match route.target {
    L3Profile { name } => send_l3_ip_packet(name, packet),
    Reject { reason } => drop,
    Direct | Outbound | Group | Country => {
        record_dropped("native-l3 l4 route target not implemented")
        telemetry warn
        do not call send_l3_ip_packet(default_l3_profile)
    }
}
```

这样至少不会把“走 direct/节点/国家”的流量偷偷走 L3。

### 5.3 增加 metrics

`NativeTunMetrics` 增加：

```rust
l4_targets_unsupported: AtomicU64
last_unsupported_route_target: Option<String>
```

或者用现有 dropped + reason，但 reason 必须包含 target：

```text
native-l3 cannot execute Outbound(JP-01) without l4 session engine
```

### 5.4 测试要求

新增测试，不需要真实 TUN：

```text
native_route_target_direct_is_not_sent_to_l3_profile
native_route_target_outbound_is_not_sent_to_l3_profile
native_route_target_group_is_not_sent_to_l3_profile
native_route_target_country_is_not_sent_to_l3_profile
native_route_target_l3_profile_is_sent_to_l3_profile
native_route_target_reject_is_dropped
```

如果当前 read loop 不容易测，提取纯函数：

```rust
async fn execute_native_route_target(
    runtime: &Runtime,
    target: NativeRouteTarget,
    packet: Vec<u8>,
    default_l3_profile: &str,
    metrics: &NativeTunMetrics,
) -> NativePacketActionResult
```

先对这个函数做单元测试。

### 5.5 P3 验收标准

```text
Direct/Outbound/Group/Country 不再 fallback 到默认 L3 profile
metrics 能看到 unsupported l4 target drop
README 说明 native-l3 当前只真实执行 L3Profile/Reject
```

---

## 6. P4：NativeL3 普通代理目标真实执行路径

这是核心功能大任务。用户最终要的是：

```text
TUN 模式下，也能按 domain/ip/app 走 direct / 指定节点 / 指定组 / 指定国家 / reject
```

当前没有用户态 TCP/IP stack，所以还不能做到。

### 6.1 目标架构

```text
TUN IP packet
  -> native_tun_packet parser
  -> flow classifier
  -> smart/static routing decision
  -> NativeRouteTarget
  -> if L3Profile: raw packet -> L3Manager
  -> if Reject: drop/RST
  -> if Direct/Outbound/Group/Country: userland L4 session engine
  -> Runtime::connect_outbound / Runtime::exchange_udp
  -> write response packets back to TUN
```

### 6.2 必须引入用户态 TCP/IP stack

不要手写 TCP state machine。推荐引入：

```toml
smoltcp = "0.11"
```

如果版本不合适，选择当前稳定版本，但要说明原因。

新增模块建议：

```text
src/inbound/native_tun_stack.rs
src/inbound/native_tun_session.rs
src/inbound/native_tun_udp.rs
src/inbound/native_tun_tcp.rs
```

### 6.3 native_tun_stack.rs

职责：

1. 把 TUN 读到的 IP packet 喂给 smoltcp interface。
2. 从 smoltcp socketset 取出应用层 TCP/UDP payload。
3. 把远端返回数据写回 smoltcp socket。
4. 从 smoltcp 取出待发 IP packet 写回 TUN。
5. 管理 socket 生命周期。

核心结构建议：

```rust
pub struct NativeTunStack {
    iface: smoltcp::iface::Interface,
    sockets: smoltcp::iface::SocketSet<'static>,
    flows: HashMap<FlowKey, NativeL4Session>,
}
```

### 6.4 native_tun_session.rs

职责：

1. 为 TCP SYN 创建 session。
2. 等待 first payload，尽量 sniff SNI/HTTP Host。
3. 生成 `NativeFlowMetadata`。
4. 调 runtime route resolver。
5. 对 Direct/Outbound/Group/Country 建立真实 remote stream。
6. 双向 pump。
7. 关闭时更新 telemetry/metrics。

建议结构：

```rust
pub struct NativeFlowMetadata {
    pub protocol: FlowProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub hostname: Option<String>,
    pub sni: Option<String>,
    pub http_host: Option<String>,
    pub app: Option<ProcessMetadata>,
}
```

### 6.5 RouteTarget 执行规则

#### Direct

```rust
tokio::net::TcpStream::connect(dst).await
```

UDP:

```rust
tokio::net::UdpSocket
```

#### Outbound

使用现有：

```rust
Runtime::connect_outbound_to_named(name, destination)
```

如果没有这个方法，需要新增，不要临时改 default_outbound。

建议新增：

```rust
pub async fn connect_named_outbound(
    &self,
    outbound_name: &str,
    destination: &Destination,
) -> anyhow::Result<BoxedStream>
```

要求：

1. 不改变全局 default outbound。
2. 记录 telemetry。
3. 复用 existing outbound implementations。

#### Group

新增：

```rust
pub async fn resolve_group_member_for_connect(&self, group_name: &str) -> anyhow::Result<String>
```

规则：

1. `select` 组：使用已选成员。
2. `url-test` / auto group：使用当前 health 最低延迟可用成员。
3. 没有健康度：按成员顺序尝试。
4. 成员失败：尝试下一个。
5. 不要阻塞当前连接去测速所有节点。

#### Country

新增：

```rust
pub async fn resolve_country_best_member(&self, code: &str) -> anyhow::Result<String>
```

规则：

1. 从当前配置 outbounds 识别国家成员。
2. 过滤 alive。
3. 过滤 latency <= probe_timeout_ms。
4. 选 latency 最低。
5. 没有健康数据则按 fallback policy。

#### Reject

TCP:

1. 优先发送 RST，如果 smoltcp 支持。
2. 否则 drop。

UDP:

1. 可选 ICMP unreachable。
2. 否则 drop。

### 6.6 不要破坏 L3Profile raw path

L3Profile 仍然保持：

```rust
runtime.send_l3_ip_packet(profile, packet)
```

但只有 target 是 `L3Profile` 时能调用。

### 6.7 测试要求

新增单元/集成测试：

```text
native_l4_direct_tcp_connects_to_local_echo_server
native_l4_named_outbound_uses_selected_outbound_without_changing_default
native_l4_group_resolves_selected_member
native_l4_country_resolves_lowest_latency_member
native_l4_reject_does_not_dial_remote
native_l4_l3profile_still_uses_l3_manager
```

如果真实 TUN 测试需要 sudo，则做 ignored test：

```text
native_l3_tun_smoke_requires_sudo
```

### 6.8 P4 验收标准

```text
TUN TCP flow 可以真实走 direct
TUN TCP flow 可以真实走指定 outbound
TUN TCP flow 可以真实走 group resolved member
TUN TCP flow 可以真实走 country best member
TUN reject 不拨远端
L3Profile raw packet path 不受影响
```

---

## 7. P5：智能规则和 NativeL3 flow metadata 对齐

### 7.1 当前状态

智能规则在 stream/mixed path 里已经比较可用：

```text
Runtime::decide()
Runtime::connect_outbound()
SmartRuleEngine::decide()
SmartRuleEngine::record_connect_success()
SmartRuleEngine::record_direct_probe_result()
```

但是 NativeL3 的 flow metadata 还不够完整：

1. app/process metadata 仍没有真实查询。
2. DNS cache / SNI / HTTP Host 需要进入统一决策。
3. NativeL3 route decision 和 stream path 应该共享同一优先级。

### 7.2 要做什么

新增：

```text
src/inbound/native_tun_process.rs
src/inbound/native_tun_dns_cache.rs
```

#### Process metadata

```rust
pub struct ProcessMetadata {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bundle_id: Option<String>,
    pub executable_path: Option<String>,
}
```

macOS 初版可以用：

```text
lsof -nP -iTCP
```

或者保留抽象接口 + mock 测试。查不到 app 不阻塞连接。

#### DNS cache

当 DNS hijack 解析出：

```text
domain -> ip
```

保存短 TTL cache，NativeL3 后续只看到 IP 时可以反查 domain。

### 7.3 route decision 输入

新增统一方法：

```rust
pub async fn decide_native_flow(&self, metadata: &NativeFlowMetadata) -> NativeRouteDecision
```

优先级：

```text
1. smart enabled user/learned rules
2. app/process rules
3. domain/suffix/keyword rules
4. ip/cidr/geo rules
5. subscription rules
6. match/default
```

### 7.4 测试要求

```text
native_flow_uses_sni_for_domain_rule
native_flow_uses_dns_cache_for_domain_rule
native_flow_uses_app_bundle_rule_when_available
native_flow_smart_rule_overrides_subscription_rule
native_flow_subscription_rule_used_when_no_smart_rule
```

### 7.5 P5 验收标准

```text
NativeL3 和 mixed stream path 使用同一套智能规则优先级
SNI / DNS cache / IP / app metadata 都可以影响 decision
metadata 缺失时不崩溃，只 fallback
```

---

## 8. P6：节点测速、国家组和后台 probe 收口

### 8.1 当前状态

已有：

1. `probe_timeout_ms` 可配置。
2. `probe_all_outbounds_with()` 支持 timeout/concurrency/include_failed。
3. `background_probe_loop()` 已启动。
4. country groups 可根据 health 生成。

还要继续收口：

1. 手动“测速所有节点”必须包含 previously unavailable。
2. 自动后台测速不能影响当前连接。
3. 国家组选择必须明确使用 latency <= timeout_ms。
4. 启动代理时优先使用上次节点，失败才全局测速，这个状态要持久化。

### 8.2 要做什么

#### API

确认或新增：

```text
POST /skyhook/probe/outbounds
body:
{
  "include_failed": true,
  "include_unsupported": false,
  "timeout_ms": 500,
  "concurrency": 256
}
```

新增更明确别名也可以：

```text
POST /skyhook/probe/all
GET  /skyhook/probe/status
```

#### Last selected node

持久化：

```text
last_selected_outbound
last_successful_outbound
last_selected_by_subscription
last_selected_by_group
```

建议位置：

```text
subscription_store
runtime-state
```

启动逻辑：

```text
1. 读取上次节点
2. 如果节点仍存在，先使用
3. 后台轻量 probe 上次节点
4. 如果失败，再触发 group/country/global fallback
5. 不要启动代理时同步全量测速
```

### 8.3 测试要求

```text
manual_probe_all_includes_failed_nodes
background_probe_uses_timeout_and_concurrency
country_group_ignores_nodes_over_timeout
startup_uses_last_selected_node_without_global_probe
startup_falls_back_when_last_selected_missing
```

### 8.4 P6 验收标准

```text
500ms timeout 生效
手动测速所有节点包含失败节点
后台测速不阻塞 connect_outbound
国家组按健康度择优
上次节点优先生效
```

---

## 9. P7：协议真实拨号状态

### 9.1 Hysteria v1

当前状态：

1. `HysteriaOutbound` 有代码。
2. README 仍写 Hysteria v1 planned/not implemented。
3. 没有真实 Hysteria v1 server integration test。
4. obfs 仍 not implemented。
5. UDP 仍不支持。

本轮不要强行说完成。

如果要继续做 Hysteria v1：

```text
1. 确认协议 wire format
2. 确认 auth/auth_str 语义
3. 确认 QUIC ALPN
4. 确认 TCP request/response format
5. 增加 ignored integration test with real server env vars
6. 通过真实 server 后再改 README 状态
```

建议 env：

```text
SKYHOOK_HYSTERIA_V1_SERVER
SKYHOOK_HYSTERIA_V1_PORT
SKYHOOK_HYSTERIA_V1_AUTH
SKYHOOK_HYSTERIA_V1_SNI
```

### 9.2 OpenVPN

当前状态：

1. parser 有。
2. packet opcode 有测试。
3. L3 profile manager 有。
4. start 仍返回 Unsupported。
5. TLS/control/data channel 未实现。

如果不做完整 OpenVPN，保持 honest status。

如果继续做：

```text
Layer 1: control channel reliable packet
Layer 2: TLS handshake over OpenVPN control channel
Layer 3: server push options and key derivation
Layer 4: data channel encrypt/decrypt
Layer 5: TUN packet bridge
```

不要把 Layer 1/2 说成真拨号完成。

### 9.3 SSR/Snell/AnyTLS/ShadowTLS

当前仍有 partial 限制：

```text
SSR: variant coverage limited
Snell: no UDP / no TLS obfs
AnyTLS: early
ShadowTLS: v3 only, no UDP
```

能力矩阵必须保持诚实。

### 9.4 P7 验收标准

```text
真实拨号完成才改 supported
没有真实 server integration 的协议不能写 production
unsupported/partial 限制 API 和 README 一致
```

---

## 10. P8：文档和验收收口

### 10.1 README 当前有一处不一致

README NativeL3 current status 写：

```text
Route and address auto-configuration via setup plan
```

但 Not yet complete 又写：

```text
Bypass route installation via original gateway (currently bypass routes are recorded but not installed)
Endpoint bypass for L3 tunnel server IPs
```

如果 P1/P2 修完，要更新为：

```text
Route/address auto-configuration supports macOS/Linux basic setup.
Bypass route installation supports original gateway where gateway can be detected.
Endpoint bypass supports IP literal endpoints; domain endpoints depend on resolver.
```

如果没修完，继续标实验状态，不要说完成。

### 10.2 docs/检查结果.md

这个文件还记录旧问题。修完后不要直接删，新增：

```text
docs/MIMO_REMAINING_FIX_RESULT.md
```

写：

```text
已修复：
未修复：
验证命令：
风险：
```

### 10.3 最终验证命令

开发中不要频繁全量测试，但最后必须跑：

```bash
cargo fmt --all -- --check
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

如果没有 sudo，不要假装跑了 NativeL3 真机：

```text
manual NativeL3 macOS run: not run, requires sudo
```

如果没有真实协议服务器：

```text
real Hysteria v1 integration: not run, no server env
real OpenVPN integration: not run, no server env
```

---

## 11. 本轮 MiMo 输出格式

MiMo 完成后必须按这个格式输出：

```text
## Completed

1. ...
2. ...

## Fixed Bugs

1. route_exclude_address ...
2. bypass cleanup ...
3. endpoint bypass ...
4. native-l3 non-l3 target fallback ...

## Files Changed

- src/inbound/native_tun_system.rs: ...
- src/inbound/native_tun.rs: ...
- src/inbound/native_tun_router.rs: ...
- src/inbound/native_tun_metrics.rs: ...
- src/core/mod.rs: ...
- README.md: ...
- tests/...: ...

## Validation

- cargo fmt --all -- --check: pass/fail
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

## 12. 最终完成定义

只有满足下面条件，才能说这轮完成：

```text
1. cargo fmt --all -- --check 通过
2. route_exclude_address 在 NativeL3 中走 bypass，不走 route_add
3. bypass cleanup 和安装命令对称
4. endpoint bypass 能把 IP/host:port/domain 转为真实 /32 或 /128 CIDR
5. Direct/Outbound/Group/Country 不再偷偷 fallback 到默认 L3 profile
6. 如果 P4 未完成，README 和 metrics 必须诚实显示 NativeL3 无法执行 L4 targets
7. 如果 P4 完成，TUN TCP flow 必须能真实走 direct/outbound/group/country
8. smart rules 对 NativeL3 flow metadata 生效或诚实标注未完成
9. 节点测速 timeout、后台 probe、国家组择优状态清晰
10. Hysteria v1/OpenVPN 没有真实 integration 前不能写 production/complete
11. cargo test --all-targets 通过
12. cargo run -- check -c skyhook.example.yaml 通过
```

如果第 5 条没做，就绝对不要说 NativeL3 智能分流完成。

