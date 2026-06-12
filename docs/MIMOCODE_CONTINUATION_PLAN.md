# mimocode 后续开发计划

生成日期：2026-06-12  
项目路径：`/Users/chency/Downloads/clash/Skyhook`  
目标：基于 mimocode 已经完成的 L3 packet channel、NativeL3 TUN 雏形、OpenVPN parser，继续把 Skyhook 的 L3 能力推进到真实可运行。

## 0. 接手前先确认

先执行：

```bash
cd /Users/chency/Downloads/clash/Skyhook
git status --short
cargo check --tests
cargo test --all-targets
```

当前工作树是脏的，里面包含前序模型和 mimocode 的开发成果。不要回滚、不要重置、不要删除 `src/l3/`、`src/inbound/native_tun.rs`、`docs/SKYHOOK_FOLLOWUP_IMPLEMENTATION_PLAN.md`。

## 1. mimocode 已经完成的内容

### 1.1 L3 packet channel

已在 `src/l3/mod.rs` 增加：

- `L3Packet`
- `L3PacketDirection`
- `L3PacketSubmitResult`
- `L3Manager::send_ip_packet`
- `L3Manager::subscribe_ip_packets`
- `Runtime::send_l3_ip_packet`
- `Runtime::subscribe_l3_ip_packets`

WireGuard task 已经有：

- outbound packet channel：TUN -> L3 -> WireGuard encapsulate -> UDP network
- inbound broadcast channel：UDP network -> WireGuard decapsulate -> L3 packet -> TUN bridge

已有测试：

```bash
cargo test l3::tests
```

当前能通过：

- `wireguard_tunnel_engine_emits_handshake`
- `wireguard_l3_packet_round_trip`

### 1.2 NativeL3 TUN 雏形

已新增：

- `src/inbound/native_tun.rs`
- `src/inbound/mod.rs` 暴露 `native_tun`
- `TunBackend::NativeL3`
- `TunConfig.backend`
- `TunConfig.l3_profile`
- `/skyhook/tun/profile` 可根据 backend 返回 `native_tun::profile` 或 `tun::profile`

### 1.3 OpenVPN parser

已新增：

- `src/l3/openvpn/mod.rs`
- `src/l3/openvpn/config.rs`
- `src/l3/openvpn/parser.rs`

parser 已支持：

- `remote`
- `proto udp`
- `proto tcp-client`
- `dev tun/tap`
- `cipher`
- `data-ciphers`
- `auth`
- inline `<ca>` / `<cert>` / `<key>` / `<tls-auth>` / `<tls-crypt>`
- 拒绝 compression

已有测试：

```bash
cargo test openvpn
```

## 2. 当前必须先修的阻塞问题

### P0-1：NativeL3 TUN 没有被启动

问题位置：

- `src/main.rs`
- `src/inbound/tun.rs`
- `src/inbound/native_tun.rs`

当前 `main.rs` 只启动：

```rust
tasks.spawn(inbound::tun::serve(runtime.clone()));
```

但 `tun::serve` 在 `backend != TunBackend::Tun2Proxy` 时会直接返回 `Ok(())`。这意味着：

- `tun.backend = native-l3` 时，`native_tun::serve` 根本没启动。
- `tun::serve` 立即返回后，`JoinSet` 可能认为一个核心任务结束，导致整个 `run` 流程提前退出。

必须改成：

```rust
if runtime.config().tun.enabled {
    match runtime.config().tun.backend {
        TunBackend::Tun2Proxy => {
            tasks.spawn(inbound::tun::serve(runtime.clone()));
        }
        TunBackend::NativeL3 => {
            tasks.spawn(inbound::native_tun::serve(runtime.clone()));
        }
    }
}
```

同时要确认 import：

```rust
use skyhook::config::TunBackend;
```

或者使用完整路径。

验收：

```bash
cargo check --tests
cargo test --all-targets
```

再新增一个不需要 root 的测试或最小配置检查，确认 `TunBackend::NativeL3` 配置可以解析。

### P0-2：macOS TUN 创建方式错误

问题位置：

- `src/inbound/native_tun.rs`

当前 macOS 分支尝试：

```rust
libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
libc::open(b"/dev/tun\0", libc::O_RDWR)
```

这不是 macOS 正常 utun 创建方式。macOS 上应使用 utun control socket：

1. `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
2. `ioctl(fd, CTLIOCGINFO, ctl_info { ctl_name = "com.apple.net.utun_control" })`
3. `connect(fd, sockaddr_ctl { sc_id, sc_unit, ... })`
4. `getsockopt(..., UTUN_OPT_IFNAME, ...)` 获取真实 interface name
5. 用这个 fd 构造 `tokio::fs::File`

注意：

- `utun` 读写 packet 通常带 4 字节 address family header。
- IPv4 header 一般是 `AF_INET`，IPv6 是 `AF_INET6`。
- read 时要剥掉 4 字节 header，再交给 `send_l3_ip_packet`。
- write 时要根据 packet 第一 nibble 判断 IPv4/IPv6，然后补 4 字节 header。

需要新增 helper：

```rust
fn strip_macos_utun_header(packet: &[u8]) -> anyhow::Result<Vec<u8>>;
fn add_macos_utun_header(packet: &[u8]) -> anyhow::Result<Vec<u8>>;
```

Linux 分支可继续使用 `/dev/net/tun` + `IFF_TUN | IFF_NO_PI`，但要修掉不安全的 `transmute` 写法。

Linux name 写入建议：

```rust
for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes.iter()) {
    *dst = *src as libc::c_char;
}
```

验收：

```bash
cargo check --tests
cargo test native_tun
```

新增单测：

- macOS utun header add/strip IPv4
- macOS utun header add/strip IPv6
- unknown packet version 报错

### P0-3：L3 inbound broadcast 失败被吞掉

问题位置：

- `src/l3/mod.rs`

当前：

```rust
let _ = inbound_packets.send(l3_packet);
```

这会导致没有 TUN 订阅者时仍然把状态写成 `wireguard packet sent to TUN bridge`。

必须改成：

```rust
match inbound_packets.send(l3_packet) {
    Ok(receiver_count) => {
        // details 里记录 receiver_count
    }
    Err(error) => {
        // 状态写 Degraded 或 details 里写 dropped_to_tun_packet
        // 不要谎称 sent to TUN bridge
    }
}
```

建议扩展 `L3TunnelStatus.details`：

- `tun_receivers=N`
- `tun_packet_broadcasted=true/false`
- `tun_packet_drop_reason=no_receiver`

验收：

新增测试：

- 没有 subscriber 时，`WriteToTunnel` 不应显示成功 sent。
- 有 subscriber 时，能收到 packet。

## 3. P1：把 NativeL3 从“能编译”推进到“能启动”

### P1-1：NativeL3 配置校验

在 `Runtime::new_with_base` 或 TUN 启动前新增校验：

当：

```yaml
tun:
  enabled: true
  backend: native-l3
```

必须要求：

- `tun.l3_profile` 不为空。
- `l3.enabled = true`。
- 对应 profile 存在于 L3 profiles。
- 对应 profile 已能 start，或由 startup auto-start 启动。

如果缺失，错误要清楚：

```text
native-l3 tun backend requires tun.l3_profile to reference a WireGuard/OpenVPN L3 profile
```

### P1-2：启动顺序

NativeL3 依赖 L3 profile channel，所以启动顺序必须是：

1. Runtime 创建。
2. `runtime.start_l3_all()` 或 `runtime.start_l3(profile)`。
3. API server。
4. NativeL3 TUN backend。
5. mixed inbound。

如果 `tun.backend = native-l3` 且 `l3.auto_start = false`，那么 main 应该主动启动 `tun.l3_profile`，否则 `native_tun::serve` 调用 `subscribe_l3_ip_packets` 会失败。

建议逻辑：

```rust
if config.tun.enabled && config.tun.backend == TunBackend::NativeL3 {
    if let Some(profile) = config.tun.l3_profile.clone() {
        runtime.start_l3(&profile).await;
    }
}
```

但要避免和 `l3.auto_start` 重复冲突。重复 start 当前会返回已有状态，可以接受。

### P1-3：不要让立即返回的 task 杀掉主进程

当前 `JoinSet` 的模式是：

```rust
if let Some(result) = tasks.join_next().await {
    result??;
}
```

这意味着任何一个 task 正常结束，程序就结束。

对于长期服务，应该区分：

- API/mixed/tun/dns 意外退出：应该返回错误或 shutdown。
- 某些 backend 因 disabled 立即返回：不要 spawn。

所以主程序只应该 spawn 确定要长期运行的 task。

验收：

- `tun.enabled=false` 时不会 spawn tun task。
- `tun.enabled=true backend=tun2proxy` 时只 spawn tun2proxy。
- `tun.enabled=true backend=native-l3` 时只 spawn native_tun。

## 4. P2：NativeL3 packet correctness

### P2-1：packet version 校验

TUN read 后不要 blindly 发送到 L3。

新增：

```rust
fn validate_ip_packet(packet: &[u8]) -> anyhow::Result<IpVersion>;
```

规则：

- 空包拒绝。
- first byte >> 4 == 4：IPv4。
- first byte >> 4 == 6：IPv6。
- 其他拒绝并记 telemetry warning。

### P2-2：MTU 和 buffer

当前 read buffer 固定 65535，可以接受但不精细。

建议：

- read buffer = `mtu + platform_header_len + safety_margin`
- write 时如果 packet 大于 MTU，记录 warning。
- 不要 panic。

### P2-3：drop counters

NativeTunProfile 应该加入：

```rust
pub dropped_to_l3: u64
pub dropped_to_tun: u64
pub last_error: Option<String>
```

如果暂时不做全局共享 counters，至少在 telemetry log 里输出。

## 5. P3：OpenVPN parser 接入 L3 状态，但不要说成真拨号

### P3-1：OpenVPN profile parse on discovery

当前 parser 存在，但 L3 profile discovery 没使用它。

在 `profile_from_outbound` 处理 `OutboundConfig::OpenVpn` 时：

- 如果有 `inline_profile`，调用 `parse_openvpn_profile`。
- 如果有 `profile` path，读取文件并 parse。
- parse 成功后，snapshot notes 显示：
  - remote count
  - proto
  - dev
  - cipher list
- parse 失败时，profile status 应该是 `Failed`，错误可见。

不要启动 OpenVPN 网络连接；仍然返回 Unsupported，但 status/details 要更准。

### P3-2：OpenVPN parser 增强

补充：

- `remote-random`
- `nobind`
- `persist-key`
- `persist-tun`
- `reneg-sec`
- `auth-nocache`
- `tls-client`
- `client`
- `resolv-retry`
- `explicit-exit-notify`

这些暂时可以 parse/ignore，但不能误报 unsupported，除非确实影响后续拨号。

## 6. P4：文档同步

需要更新：

- `README.md`
- `docs/SKYHOOK_FOLLOWUP_IMPLEMENTATION_PLAN.md`
- 本文件

重点文案：

- `NativeL3` 是 experimental。
- WireGuard packet channel 已有。
- macOS utun backend 完成前，不能说 macOS NativeL3 可用。
- OpenVPN parser 不等于 OpenVPN 真拨号。

## 7. P5：验收命令

每轮提交前跑：

```bash
cargo fmt --all
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

NativeL3 相关新增测试后，至少要能跑：

```bash
cargo test native_tun
cargo test l3::tests
cargo test openvpn
```

如果新增需要 root 的真实 TUN smoke，不要放进默认测试。写成脚本：

```bash
scripts/run_native_l3_tun_smoke.sh
```

脚本必须提示需要 sudo，并且不应修改用户现有网络设置后不恢复。

## 8. 当前最推荐 mimocode 立即做的 5 个 patch

按顺序做，不要跳：

1. **修 `main.rs` backend 分流启动**
   - `Tun2Proxy` -> `inbound::tun::serve`
   - `NativeL3` -> `inbound::native_tun::serve`

2. **修 macOS utun 创建**
   - 不再使用 `/dev/tun`
   - 使用 `com.apple.net.utun_control`
   - read strip 4 字节 header
   - write add 4 字节 header

3. **修 L3 broadcast send 错误处理**
   - 不吞错误
   - 无 subscriber 时不要显示 sent to TUN bridge

4. **给 native_tun 加无 root 单测**
   - IPv4/IPv6 header add/strip
   - packet version validation
   - profile warning

5. **OpenVPN parser 接入 profile discovery**
   - inline profile parse
   - file profile parse
   - snapshot/status 显示 parse 结果
   - 仍标记 native data plane 未完成

## 9. 完成标准

这些都满足，才算 mimocode 下一阶段完成：

- `tun.backend=native-l3` 时主程序确实启动 `native_tun::serve`。
- macOS 不再 open `/dev/tun`。
- L3 解封 packet 没有 TUN subscriber 时会明确报/记 drop，不会假装成功。
- `cargo test --all-targets` 通过。
- `cargo run -- check -c skyhook.example.yaml` 通过。
- README/docs 不夸大 NativeL3 和 OpenVPN 状态。

