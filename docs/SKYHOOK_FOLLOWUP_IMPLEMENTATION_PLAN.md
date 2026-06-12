# Skyhook 后续优化与实现交接计划

生成日期：2026-06-12  
项目路径：`/Users/chency/Downloads/clash/Skyhook`  
项目名称：Skyhook / 玥球核心  
目标读者：接手继续写代码的大模型或工程师

## 0. 先读这个

这份文档不是产品愿景稿，而是后续编码任务书。接手方应按本文顺序逐步实现，不要把未完成能力包装成“已经完成”。

当前 Skyhook 是一个独立 Rust 代理核心，不是 Mihomo wrapper，不要引入“双核心”，不要把旧 Mihomo/App 作为运行时依赖。可以参考成熟实现和协议文档，但最终能力应落在 Skyhook 自己的源码、配置、状态、API、测试里。

接手前必须先执行：

```bash
cd /Users/chency/Downloads/clash/Skyhook
git status --short
cargo check --tests
```

注意：当前工作树可能是脏的，里面有正在开发的 L3、TUN、协议、智能规则等改动。不要使用 `git reset --hard`、`git checkout -- .`、`git clean -fd` 这类命令回滚用户或前序模型的工作。

## 1. 当前已完成的核心基线

### 1.1 主要已实现能力

- Rust crate 名称为 `skyhook`，主程序在 `src/main.rs`。
- 配置模型在 `src/config/mod.rs`，示例配置在 `skyhook.example.yaml`。
- 控制 API 在 `src/api/mod.rs`，本地 HTTP API 以 `/skyhook/*` 为主。
- Runtime 在 `src/core/mod.rs`，负责路由、出站、探测、智能规则、遥测。
- Mixed inbound 在 `src/inbound/mixed.rs`，TUN 入口在 `src/inbound/tun.rs`。
- 出站协议大部分集中在 `src/outbound/mod.rs`。
- 订阅解析在 `src/subscription/mod.rs`，多订阅持久化在 `src/subscription_store.rs`。
- 智能规则在 `src/smart/mod.rs`。
- L3 manager 已新增在 `src/l3/mod.rs`，并通过 `src/lib.rs` 暴露。

### 1.2 已接入的 L3 控制面

当前已有：

- `L3Config`：`enabled`、`auto_start`、`handshake_interval_secs`、`start_timeout_ms`。
- 示例配置已有 `l3:` 块。
- Runtime 启动时会在 `l3.enabled && l3.auto_start` 时调用 `runtime.start_l3_all().await`。
- API 已有：
  - `GET /skyhook/l3`
  - `POST /skyhook/l3/start`
  - `POST /skyhook/l3/stop`
- WireGuard 和 OpenVPN 不再伪装成普通 TCP stream outbound，而是 L3 tunnel profile。

### 1.3 WireGuard 当前状态

当前 WireGuard 已经不是简单占位：

- 使用 `boringtun = "0.7.1"` 的 WireGuard Noise packet engine。
- 支持 profile 校验：
  - server
  - port
  - private_key
  - public_key
  - preshared_key
  - interface IP
  - allowed IP
  - MTU
- 支持启动 UDP socket。
- 支持 WireGuard handshake initiation。
- 支持处理 WireGuard network datagram：
  - handshake response
  - keepalive
  - encrypted data packet decapsulation
- 支持 timer tick 和 persistent keepalive。
- 状态里暴露：
  - `tx_packets`
  - `rx_packets`
  - `tx_bytes`
  - `rx_bytes`
  - `last_handshake_age_secs`
  - `last_rtt_ms`
  - `estimated_loss`
  - `data_tx_bytes`
  - `data_rx_bytes`

已经通过的验证：

```bash
cargo check --tests
cargo test l3::tests::wireguard_tunnel_engine_emits_handshake
```

### 1.4 必须诚实承认的边界

WireGuard L3 packet engine 已经存在，但还没有真正接进 OS TUN 数据面。

当前 `src/l3/mod.rs` 里解封出来的 IP packet 只是被状态描述为 ready for TUN bridge。它还没有写回 TUN 设备，也还没有从 TUN 设备读取原始 IP packet 再交给 WireGuard encapsulate。

所以不能说 WireGuard L3 已完整可用。准确说法是：

- WireGuard Noise/packet engine：已有。
- L3 manager/control API：已有。
- WireGuard 到真实 TUN 设备的双向 packet bridge：未完成。

OpenVPN 当前只是 L3 profile manager/status boundary，native OpenVPN TLS/control/data channel 未完成。

## 2. 总体优先级

按优先级继续做：

1. WireGuard L3 packet engine 接入 TUN bridge。
2. Native TUN backend 和 L3/full-tunnel 路由能力。
3. OpenVPN native TLS/control/data channel。
4. Hysteria v1 真拨号。
5. Mieru / Juicity / MASQUE 真拨号。
6. SSR / Snell 协议补全。
7. 智能规则闭环：流量观察、直连探测、自动学习、自动推荐、可控自动应用。
8. Mihomo 级规则、Rule Provider、DNS 策略兼容增强。
9. 性能基准、压力测试、fuzz、schema docs。

不要反过来先做 UI 或包装文案。这个项目的瓶颈是核心能力，不是展示。

## 3. P0：接手准备与保护现场

### 3.1 要做什么

接手方第一步不是写代码，而是确认当前代码和脏工作树。

执行：

```bash
cd /Users/chency/Downloads/clash/Skyhook
git status --short
cargo check --tests
cargo test l3::tests::wireguard_tunnel_engine_emits_handshake
```

如果 `cargo check --tests` 失败：

1. 先修编译失败。
2. 不要删除 L3 模块。
3. 不要回滚 `Cargo.toml` 中的 `boringtun`。
4. 不要把 WireGuard/OpenVPN 改回普通 stream outbound。

### 3.2 验收标准

- `cargo check --tests` 通过。
- L3 定向测试通过。
- `GET /skyhook/l3` 相关 handler 仍在 `src/api/mod.rs`。
- `src/l3/mod.rs` 仍存在并由 `src/lib.rs` 暴露。

## 4. P1：WireGuard L3 packet engine 接入 TUN bridge

这是最高优先级。完成后 Skyhook 才真正具备自研 L3 核心的第一块硬能力。

### 4.1 当前问题

当前 WireGuard task 能从网络读 WireGuard datagram，也能 decapsulate 出 IP packet，但缺两条链路：

1. OS TUN -> 原始 IP packet -> WireGuard encapsulate -> UDP network。
2. UDP network -> WireGuard decapsulate -> 原始 IP packet -> OS TUN。

现有 `src/inbound/tun.rs` 使用 `tun2proxy::general_run_async`。`tun2proxy` 负责把 TUN 流量转成 SOCKS/HTTP 代理连接，它不是给 Skyhook 暴露原始 IP packet 的双向接口。因此不要试图在 `tun2proxy` 回调里“顺手拿 packet”，当前结构做不到。

### 4.2 推荐分三阶段做

#### 阶段 1：先完成 L3 内部 packet channel

目标：不碰 OS TUN，先让 `L3Manager` 具备发送/接收原始 IP packet 的内部 API。

建议新增/调整类型：

```rust
pub struct L3Packet {
    pub profile: String,
    pub packet: Vec<u8>,
    pub direction: L3PacketDirection,
    pub timestamp: DateTime<Utc>,
}

pub enum L3PacketDirection {
    ToNetwork,
    ToTun,
}

pub struct L3PacketSubmitResult {
    pub accepted: bool,
    pub profile: String,
    pub packet_len: usize,
    pub error: Option<String>,
}
```

建议在 `L3ManagerInner` 里增加：

```rust
packet_txs: BTreeMap<String, tokio::sync::mpsc::Sender<Vec<u8>>>,
packet_rxs or broadcast sender for decapsulated packets
```

更推荐结构：

```rust
struct L3Task {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
    outbound_packets: mpsc::Sender<Vec<u8>>,
    inbound_packets: broadcast::Sender<L3Packet>,
}
```

需要新增 public 方法：

```rust
impl L3Manager {
    pub async fn send_ip_packet(&self, profile: &str, packet: Vec<u8>) -> L3PacketSubmitResult;
    pub fn subscribe_ip_packets(&self, profile: &str) -> anyhow::Result<broadcast::Receiver<L3Packet>>;
}
```

`run_wireguard_profile` 增加一个 `mpsc::Receiver<Vec<u8>>` 分支：

```rust
packet = outbound_packet_rx.recv() => {
    let action = wireguard_action(tunnel.encapsulate(&packet, &mut tunnel_buf));
    // send WireGuardAction::WriteToNetwork to UDP socket
}
```

`WireGuardAction::WriteToTunnel` 当前只保存 bytes/source，必须改成保存完整 packet：

```rust
WriteToTunnel {
    packet: Vec<u8>,
    source: IpAddr,
    notes: Vec<String>,
}
```

然后在 `send_wireguard_action` 里把 decapsulated packet 发送到 `broadcast::Sender<L3Packet>`。

#### 阶段 1 验收

新增测试，不需要 root：

- 构造两个 WireGuard tunnel engine。
- A 生成 handshake init。
- B decapsulate init 并生成 response。
- A decapsulate response 并生成 keepalive。
- A encapsulate 一个 synthetic IPv4 packet。
- B decapsulate 后得到同样的 IPv4 packet。

这个测试可以基于 `boringtun::noise::Tunn`，放在 `src/l3/mod.rs` 或 `tests/l3_wireguard.rs`。

验收命令：

```bash
cargo test l3::tests::wireguard_tunnel_engine_emits_handshake
cargo test wireguard_l3_packet_round_trip
cargo check --tests
```

#### 阶段 2：新增 native TUN full-tunnel backend

目标：先做 WireGuard full-tunnel，不要一上来做复杂混合路由。

为什么先 full-tunnel：

- 它只需要把 TUN 所有 packet 送到一个 WireGuard profile。
- 不需要立刻实现 TCP/UDP 用户态协议栈。
- 可以最快证明 L3 能真实上网。

建议新增文件：

- `src/inbound/native_tun.rs`
- 或 `src/inbound/tun_native.rs`
- 或拆目录 `src/inbound/tun/native.rs`

建议新增配置：

```rust
pub enum TunBackend {
    Tun2Proxy,
    NativeL3,
}

pub struct TunConfig {
    pub backend: TunBackend,
    pub l3_profile: Option<String>,
    ...
}
```

如果不想大改现有 `TunConfig`，也可以先加：

```rust
pub l3_bridge: bool,
pub l3_profile: Option<String>,
```

但长期更清晰的是 backend enum。

Native TUN backend 需要做：

1. 创建 TUN interface。
2. 设置 MTU。
3. 根据 macOS/Linux 差异处理 packet information header。
4. read loop：从 TUN 读原始 IP packet。
5. 根据 `l3_profile` 调用 `runtime.send_l3_ip_packet(profile, packet).await`。
6. write loop：订阅 `runtime.subscribe_l3_ip_packets(profile)`，把 decapsulated packet 写回 TUN。
7. 处理 backpressure：
   - channel 满时丢包并计数。
   - 状态/API 显示 drop 计数。
8. 处理 shutdown：
   - Runtime 退出时关闭 TUN read/write loop。
   - L3 stop 时 TUN bridge 不应 panic。

建议在 `Runtime` 增加：

```rust
pub async fn send_l3_ip_packet(&self, profile: &str, packet: Vec<u8>) -> L3PacketSubmitResult;
pub fn subscribe_l3_ip_packets(&self, profile: &str) -> anyhow::Result<broadcast::Receiver<L3Packet>>;
```

#### 阶段 2 验收

需要 root/权限的测试不要放进默认 `cargo test`。加 ignored test 或脚本。

建议新增脚本：

```bash
scripts/run_wireguard_l3_tun_smoke.sh
```

验收至少包括：

- 无 WireGuard profile 时，native L3 TUN 明确失败并给出可读错误。
- WireGuard profile 无法握手时，状态为 `Handshaking` 或 `Degraded`，不能假装 Running。
- 有可用 WireGuard server 时：
  - TUN 能读 packet。
  - WireGuard UDP 有 tx/rx。
  - decapsulated packet 能写回 TUN。
  - `/skyhook/l3` 可看到 packet counters 增长。

### 4.3 阶段 3：混合 TUN 路由

这是更难的部分，不要和阶段 2 混在一起。

问题：如果 native TUN 同时要支持普通 stream outbound 和 L3 outbound，需要用户态网络栈。

可选路线：

1. 使用 `smoltcp` 或等价用户态 TCP/IP 栈，将 TUN packet 还原为 TCP/UDP flows，再交给已有 outbound stream/udp path。
2. 保留 `tun2proxy` 作为普通代理 TUN backend，另起 native L3 TUN backend 只做 WireGuard/OpenVPN full-tunnel。
3. 长期做统一 native packet router：raw packet -> route decision -> L3 或 stream proxy。

推荐实现顺序：

1. 先做 `NativeL3` full-tunnel。
2. 再评估是否引入 `smoltcp`。
3. 最后再统一替换 `tun2proxy`。

不要在没有用户态 TCP/IP 栈的情况下声称“所有 TUN 流量都可任意选择 HTTP/SOCKS/WireGuard 出站”。那是不真实的。

## 5. P2：OpenVPN native TLS/control/data channel

### 5.1 当前状态

OpenVPN 现在只在配置和订阅里被识别，并进入 L3 manager。启动时返回 `Unsupported`，原因是 native OpenVPN data plane 未实现。

### 5.2 要实现的子模块

建议拆文件：

- `src/l3/openvpn.rs`
- `src/l3/openvpn/config.rs`
- `src/l3/openvpn/control.rs`
- `src/l3/openvpn/data.rs`
- `src/l3/openvpn/crypto.rs`

### 5.3 Profile 解析

支持 `.ovpn` 常见字段：

- `remote host port proto`
- `proto udp`
- `proto tcp-client`
- `dev tun`
- `cipher`
- `data-ciphers`
- `auth`
- `auth-user-pass`
- `ca`
- `cert`
- `key`
- inline blocks:
  - `<ca>`
  - `<cert>`
  - `<key>`
  - `<tls-auth>`
  - `<tls-crypt>`
- `remote-cert-tls server`
- `verify-x509-name`
- `comp-lzo` / compression：默认拒绝或明确 unsupported，不要静默启用。

输出结构：

```rust
pub struct OpenVpnParsedProfile {
    pub remotes: Vec<OpenVpnRemote>,
    pub proto: OpenVpnTransport,
    pub dev: OpenVpnDeviceMode,
    pub ca: Vec<Vec<u8>>,
    pub cert: Option<Vec<u8>>,
    pub key: Option<Vec<u8>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_auth: Option<Vec<u8>>,
    pub tls_crypt: Option<Vec<u8>>,
    pub ciphers: Vec<String>,
    pub auth: Option<String>,
}
```

### 5.4 Control channel

实现：

- UDP/TCP transport connect。
- OpenVPN packet opcode parse/serialize。
- TLS handshake over OpenVPN control channel。
- rustls client config。
- certificate validation 与 `skip_cert_verify` 类配置。
- key method negotiation。
- push options parse。
- keepalive/ping。
- reconnect/backoff。

### 5.5 Data channel

优先支持：

- AES-256-GCM
- AES-128-GCM
- AES-256-CBC + HMAC-SHA1/SHA256

后续再扩：

- CHACHA20-POLY1305
- tls-crypt-v2
- compression legacy handling

Data channel 需要和 L3 packet channel 复用：

- TUN packet -> OpenVPN data packet -> network。
- network data packet -> OpenVPN decrypt -> TUN packet。

### 5.6 验收

不要求默认测试依赖公网 VPN。要做三层验证：

1. profile parser unit tests。
2. packet codec tests。
3. optional ignored integration test，需要本地/测试 OpenVPN server。

命令：

```bash
cargo test openvpn_profile_parser
cargo test openvpn_packet_codec
cargo check --tests
```

## 6. P3：Hysteria v1 真拨号

### 6.1 当前状态

`OutboundConfig::Hysteria` 存在，但在 `src/outbound/mod.rs` 里仍是 unsupported outbound。

### 6.2 实现范围

新增或复用模块：

- `HysteriaOutbound`
- QUIC client transport，优先使用现有 `quinn`
- auth
- obfs
- TCP stream relay
- UDP datagram relay

需要确认 Hysteria v1 与 Hysteria2 的差异，不要直接套 Hysteria2 的实现。

### 6.3 配置字段

检查 `src/config/mod.rs` 里的 Hysteria 字段是否足够：

- server
- port
- auth/password
- sni
- skip_cert_verify
- alpn
- obfs
- up/down bandwidth
- protocol hints

不足就扩配置，并同步订阅解析。

### 6.4 验收

- capability 从 unsupported 改成真实 tcp/udp。
- `probe_outbounds` 能测 Hysteria v1 节点。
- TCP smoke test。
- UDP smoke test。
- 失败时错误信息能说明是 auth、TLS、QUIC、obfs、还是 relay 失败。

## 7. P4：Mieru / Juicity / MASQUE

### 7.1 当前状态

这三个协议在订阅和配置层有识别，但 native dialing 未实现。

### 7.2 实现建议

不要三个一起写。按优先级：

1. MASQUE
2. Juicity
3. Mieru

原因：

- MASQUE 和现有 HTTP/3/QUIC 依赖更接近，Skyhook 已有 `h3`、`h3-quinn`、`quinn`。
- Juicity 也基于 QUIC/TLS，和 Hysteria/TUIC 方向接近。
- Mieru 独立协议成本更高。

### 7.3 MASQUE 要做

- HTTP/3 CONNECT-UDP
- CONNECT-IP 如果目标协议需要
- TLS/rustls config
- UDP capsule framing
- Proxy-Authorization
- SNI / ALPN
- capability 标记 UDP mode

### 7.4 Juicity 要做

- 协议握手
- QUIC stream
- UDP datagram
- auth
- TLS verification

### 7.5 Mieru 要做

- 先写协议调研文档或注释，不要盲写。
- 明确 auth、transport、framing、multiplexing、UDP 方式。
- 先实现 TCP，再实现 UDP。

## 8. P5：SSR / Snell 补全

### 8.1 SSR 当前缺口

当前 SSR 已有 origin/plain/http 简化路径，但不完整。

要补：

- protocol:
  - `auth_sha1_v4`
  - `auth_aes128_md5`
  - `auth_aes128_sha1`
  - `auth_chain_a`
  - `auth_chain_b`
- obfs:
  - `tls1.2_ticket_auth`
  - `tls1.2_ticket_fastauth`
  - 更多 http_simple/http_post 参数兼容
- UDP relay
- method coverage
- 订阅 URI 参数完整兼容

验收：

- 每种 protocol 有 codec unit test。
- 每种 obfs 有 first-packet test。
- 真实节点 probe 不应比当前慢很多。

### 8.2 Snell 当前缺口

当前 Snell 已有 TCP AEAD 和 HTTP obfs，缺：

- UDP
- TLS obfs
- 更多版本边界测试
- keepalive/复用行为

验收：

- Snell v1/v2/v3 TCP tests。
- UDP packet codec tests。
- TLS obfs handshake smoke test。

## 9. P6：智能规则闭环

### 9.1 当前状态

已有智能规则 engine、观察、推荐、apply、阈值、并发控制。但它还不是完整自动学习系统。

### 9.2 最终目标

Skyhook 的方向不是让用户维护复杂规则，而是：

1. 记录新访问的 domain/ip/app/process。
2. 后台直连探测。
3. 判断直连是否可用、是否稳定、是否更快。
4. 推荐 direct 或 proxy。
5. 用户可一键应用，也可设置自动应用策略。
6. 智能规则优先级高于订阅规则。
7. 规则命中、直连失败、代理失败都进入反馈闭环。

### 9.3 要改的模块

- `src/smart/mod.rs`
- `src/core/mod.rs`
- `src/telemetry/*`
- `src/routing/*`
- `src/api/mod.rs`

### 9.4 数据模型建议

```rust
pub struct SmartObservation {
    pub target: RuleTarget,
    pub value: String,
    pub app_bundle: Option<String>,
    pub process_name: Option<String>,
    pub direct_successes: u64,
    pub direct_failures: u64,
    pub proxy_successes: u64,
    pub proxy_failures: u64,
    pub direct_latency_p50_ms: Option<u64>,
    pub proxy_latency_p50_ms: Option<u64>,
    pub last_seen_at: DateTime<Utc>,
    pub last_probe_at: Option<DateTime<Utc>>,
}
```

### 9.5 API 建议

新增：

- `GET /skyhook/smart/observations`
- `GET /skyhook/smart/recommendations`
- `POST /skyhook/smart/probe`
- `POST /skyhook/smart/auto-apply`
- `POST /skyhook/smart/rules/promote`

保留现有 `/skyhook/smart-rules`，不要破坏兼容。

### 9.6 探测策略

不要在请求路径同步探测，避免卡代理。

正确方式：

- 连接发生时只记录 observation。
- 后台 worker 根据 cooldown 和优先级做 direct probe。
- direct probe timeout 默认 500ms，可配置。
- 连续成功/失败达到阈值才推荐。
- 自动应用必须有开关，并且要记录 reason。

### 9.7 验收

- 新访问域名会进入 observation store。
- 后台 probe 不阻塞连接。
- 推荐列表可以区分推荐直连、推荐代理。
- 应用后的智能规则优先级高于订阅规则。
- 重启后 observation 和 promoted rules 不丢。

## 10. P7：规则、Rule Provider、DNS 增强

### 10.1 规则缺口

需要继续补齐：

- Clash/Mihomo 常见 rule 行为。
- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `IP-CIDR`
- `IP-CIDR6`
- `GEOIP`
- `GEOSITE`
- `RULE-SET`
- `PROCESS-NAME`
- `PROCESS-PATH`
- `UID`
- `IN-PORT`
- `SRC-IP-CIDR`
- `DST-PORT`
- `NETWORK`
- `MATCH`

现有已覆盖一部分，但要做兼容矩阵，不要凭感觉。

### 10.2 Rule Provider

要加强：

- 下载缓存。
- ETag/Last-Modified。
- 失败 fallback 到本地缓存。
- YAML/text/mrs 行为。
- domain/ip/classical provider。
- provider health/status API。

### 10.3 DNS

重点：

- fake-ip cache。
- fake-ip reverse mapping。
- nameserver-policy。
- fallback-filter。
- direct/proxy nameserver 分流。
- DoH/DoT 错误回退。
- DNS leak 防护。
- IPv6 策略。

### 10.4 验收

- 加规则兼容测试表。
- 加 DNS fake-ip round-trip test。
- 加 provider cache failure test。
- `cargo test config_and_runtime` 不回退。

## 11. P8：API 和状态面完善

### 11.1 L3 API 增强

当前：

- `GET /skyhook/l3`
- `POST /skyhook/l3/start`
- `POST /skyhook/l3/stop`

建议新增：

- `POST /skyhook/l3/restart`
- `GET /skyhook/l3/:name`
- `GET /skyhook/l3/:name/packets`
- `POST /skyhook/l3/:name/send-test-packet`
- `GET /skyhook/l3/metrics`

状态应包含：

- handshake state
- last endpoint
- resolved endpoint
- local UDP bind addr
- tx/rx datagram count
- tx/rx tunnel packet count
- dropped packet count
- queue depth
- last error
- last handshake age
- RTT/loss

### 11.2 Traffic metrics

区分：

- proxy stream traffic
- UDP relay traffic
- L3 encrypted network traffic
- L3 decapsulated IP traffic
- per subscription traffic
- per outbound traffic
- per smart-rule traffic

不要把所有 bytes 混成一个数字。

## 12. P9：性能与稳定性

### 12.1 Benchmark

新增：

- `benches/dial_latency.rs`
- `benches/dns_latency.rs`
- `benches/rule_match.rs`
- `benches/subscription_parse.rs`
- `benches/wireguard_packet.rs`

指标：

- 节点测速并发性能。
- 500/1000/5000 节点订阅解析时间。
- 规则匹配 p50/p95/p99。
- DNS 查询延迟。
- WireGuard encapsulate/decapsulate throughput。

### 12.2 Fuzz

优先 fuzz：

- subscription URI parser
- YAML parser
- rule parser
- SOCKS address parser
- VMess/VLESS packet parser
- WireGuard/OpenVPN packet codec

### 12.3 长稳

加长稳脚本：

```bash
scripts/soak_mixed_proxy.sh
scripts/soak_tun_l3.sh
scripts/soak_subscription_update.sh
```

要求：

- 运行 30 分钟不 panic。
- memory 不持续上涨。
- connection table 不泄漏。
- background task 能 shutdown。

## 13. 其他 AI 的具体执行顺序

建议按这个顺序开工：

### 第一批：WireGuard L3 内部 packet channel

1. 打开 `src/l3/mod.rs`。
2. 给 `L3Task` 增加 mpsc/broadcast channel。
3. 给 `L3Manager` 增加 `send_ip_packet` 和 `subscribe_ip_packets`。
4. 把 `WireGuardAction::WriteToTunnel` 改成携带完整 packet。
5. 给 `run_wireguard_profile` 增加 outbound IP packet recv branch。
6. 写 paired tunnel round-trip unit test。
7. 跑：

```bash
cargo test wireguard_l3_packet_round_trip
cargo check --tests
```

### 第二批：NativeL3 TUN backend

1. 研究 `src/inbound/tun.rs` 当前 tun2proxy backend。
2. 新增 native TUN backend，不要删除 tun2proxy。
3. 配置新增 `tun.backend` 或 `tun.l3_bridge`/`tun.l3_profile`。
4. read TUN packet -> `Runtime::send_l3_ip_packet`。
5. L3 inbound packet -> write TUN。
6. `/skyhook/tun/profile` 显示 backend 和 L3 profile。
7. 加 smoke script，不放默认 root test。

### 第三批：OpenVPN profile parser

1. 新增 `src/l3/openvpn/*`。
2. 只做 parser 和 codec，不急着网络连接。
3. 加 parser tests。
4. 然后做 control channel。

### 第四批：Hysteria v1

1. 把 `OutboundConfig::Hysteria` 从 unsupported 改成真实 outbound。
2. 先 TCP，再 UDP。
3. 同步 capability。

### 第五批：智能规则闭环

1. observation store。
2. background direct probe queue。
3. recommendation API。
4. auto-apply policy。
5. telemetry feedback。

## 14. 重要禁止事项

不要做这些：

- 不要修改旧的 MihomoTrayMac App 来冒充 Skyhook 核心进展。
- 不要重新引入 Mihomo core。
- 不要搞“双核心切换”。
- 不要把 unsupported protocol 改个名字就说支持了。
- 不要把 OpenVPN profile parser 当成 OpenVPN 真拨号。
- 不要把 WireGuard handshake 当成完整 WireGuard TUN。
- 不要把所有流量统计混在一起。
- 不要让后台测速、订阅更新、智能探测阻塞正在使用的代理连接。
- 不要把私人订阅链接、节点、token、证书写入仓库。
- 不要用长超时拖慢节点测试，默认超时应保持短，例如 500ms。

## 15. Definition of Done

一个任务只有同时满足这些条件才算完成：

1. 代码真实实现，不只是状态文案。
2. API 能显示真实状态。
3. capability 不说谎。
4. 错误信息可读。
5. 默认 `cargo check --tests` 通过。
6. 至少有一个针对性测试或 smoke script。
7. README 或 docs 更新到真实状态。
8. 不破坏已有订阅解析、节点测速、智能规则、TUN 配置。

对 L3 来说，特别强调：

- 只有当 OS TUN packet 能进入 WireGuard/OpenVPN，并且远端回包能写回 OS TUN，才能称为 L3 full tunnel 可用。
- 只有 handshake 或 profile 识别不算完成。

## 16. 当前最应该马上做的任务

最推荐下一位模型立即做：

```text
实现 L3Manager 的原始 IP packet channel：
1. send_ip_packet(profile, packet)
2. subscribe_ip_packets(profile)
3. WireGuard outbound IP packet encapsulate
4. WireGuard decapsulated packet broadcast
5. paired tunnel round-trip test
```

原因：

- 它不需要 root。
- 它不需要先改 OS TUN。
- 它能把 L3 从“网络握手引擎”推进到“可收发原始 IP packet 的核心数据面”。
- 它是后续 NativeL3 TUN backend 的前置条件。

