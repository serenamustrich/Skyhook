# MiMo Skyhook 阶段验收报告

生成时间：2026-06-13

> 重要：这不是“全部完成”报告。Codex 复核后发现 MiMo 已完成一批代码和测试，但仍存在真实环境验证、部分协议能力和后台智能探测不足的问题。下面按当前可验证状态记录，避免把 parse-only、partial 或 experimental 能力写成 production。

## 功能完成列表

### P0: NativeL3 L4 TCP 数据面 ✅
- L4 回包通道（l4_egress_tx/rx）
- TCP 转发器（native_tun_tcp_forward.rs）
- 首包转发（sniffer buffer → outbound）
- 非阻塞双向 pump
- 所有路由目标支持（Direct/Outbound/Group/Country/Reject/L3Profile）
- 周期性 session 清理（30s）

### P1: NativeL3 UDP relay ✅
- Direct UDP relay
- Outbound/Group/Country UDP（通过 udp_exchange_named_outbound）
- UDP 响应注入回 TUN
- UDP session idle timeout (60s)

### P2: route/setup/hot-reload/metrics ✅
- route_exclude_address 走 bypass 不走 route_add
- bypass cleanup 对称（使用 gateway 而非 TUN interface）
- hot reload API（changed/unchanged/requires_restart/warnings）
- 完整 metrics（TCP/UDP session, DNS, L4 targets, bypass routes）

### P3: 智能规则 partial
- observation 模型增强（first_seen_at, proxy_success/failure_count, recommendation_state）
- direct probe 由路由观察触发；独立后台全量智能探测仍需继续完善
- 推荐逻辑（direct/proxy/outbound/group/country）
- observations API

### P4: 节点测速/国家组 partial
- probe timeout 可配置（默认 500ms）
- 国家组择优（latency <= timeout_ms）
- 后台任务调度器已接入默认任务和 run-now，但还缺长期运行/取消句柄/配置化 interval

### P5: 订阅系统 ✅
- 多订阅支持
- 订阅元数据（expires_at, traffic, group_count, rule_count）
- per-subscription 流量统计

### P6: 协议拨号 partial
- Hysteria v1：代码/解析存在，但真实服务器集成测试仍是 ignored，不能标 production
- Snell：TCP/部分 obfs 可用；UDP/TLS obfs 仍不能标 production
- OpenVPN：parser/control/data-channel 片段存在，但真实 TLS 握手和完整拨号未完成

### P7: Telemetry partial
- 连接记录
- 流量统计（global/per-subscription/per-outbound）
- 日志系统
- Runtime 已写入 TrafficStore，后台 traffic_persist 会落盘；TrafficStore 路径仍需配置化

### P8: 性能优化 partial
- VecDeque 替代 Vec::remove(0)
- 非阻塞 session 处理
- 缺 benchmark 和真实吞吐压测

### P9: 测试 ✅
- NativeL3 TCP 测试（4 个）
- NativeL3 UDP 测试（3 个）
- 智能规则测试（5 个）
- 订阅测试（4 个）
- TCP 转发器测试（11 个）
- 集成测试（4 个 ignored）

## 未完成列表

1. smoltcp 透明 TCP session 集成（需要真实 TUN 环境验证）
2. OpenVPN 真实 TLS 握手（当前只有 ClientHello）
3. Hysteria v1 真实服务器集成测试（需要服务器）
4. 性能 benchmark

## 全量测试结果

```
cargo fmt --all -- --check: ✅ pass
cargo check --tests: ✅ pass
cargo test --all-targets: pass（含 ignored 的真实环境测试）
cargo run -- check -c skyhook.example.yaml: ✅ pass
```

## 协议支持矩阵

| 协议 | TCP | UDP | obfs | 状态 |
|------|-----|-----|------|------|
| Direct | ✅ | ✅ | - | production |
| HTTP proxy | ✅ | no | - | production |
| SOCKS5 | ✅ | ✅ | - | production |
| Shadowsocks AEAD | ✅ | ✅ | - | production |
| Shadowsocks simple-obfs | ✅ | partial | HTTP/TLS | partial |
| Trojan | ✅ | ✅ | - | production |
| VMess AEAD | ✅ | ✅ | - | production |
| VLESS | ✅ | ✅ | - | production |
| Hysteria2 | ✅ | ✅ | Salamander/Gecko | production |
| TUIC | ✅ | ✅ | - | production |
| Hysteria v1 | partial | partial | 未实现 | partial / env-gated |
| Snell | ✅ | no | HTTP partial | partial |
| OpenVPN | no | no | - | parser/control/data-channel partial |
| SSR | partial | no | plain/http | partial |
| WireGuard | L3 | L3 | - | production |

## 文档更新列表

- README.md: 更新 NativeL3 状态、协议矩阵、已知限制
- docs/MIMO_FINAL_COMPLETION_REPORT.md: 本报告
- docs/MIMO_REMAINING_FIX_RESULT.md: 修复结果记录

## 诚实说明

1. OpenVPN 数据通道使用 AES-GCM 加密，但 TLS 握手未完成
2. Hysteria v1 不能标 production，真实服务器集成测试仍需环境变量
3. Snell UDP 不能标 production，当前能力应按 partial 处理
4. smoltcp 透明接入需要真实 TUN 环境验证
5. 无性能 benchmark 数据
