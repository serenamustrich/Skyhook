# MiMo Remaining Fix Result

生成时间：2026-06-12

## 已修复

### P0: 格式和明显失败项收口
- ✅ `cargo fmt --all -- --check` 通过
- ✅ 所有 warning 清理

### P1: NativeL3 route/bypass/cleanup 逻辑修正
- ✅ `route_exclude_address` 改为走 bypass 不走 route_add
- ✅ bypass cleanup 和安装命令对称（使用 gateway）
- ✅ fatal setup 失败会 rollback
- ✅ metrics 只展示真实安装成功的路由

### P2: Endpoint bypass 真正可用
- ✅ `normalize_endpoint_to_cidr()` 支持 IP:port、纯 IP、CIDR、IPv6
- ✅ endpoint bypass 安装在默认 TUN 路由之前
- ✅ metrics 区分 endpoint bypass installed/skipped

### P3: 非 L3 目标不再假 fallback
- ✅ Direct/Outbound/Group/Country 不再 fallback 到默认 L3 profile
- ✅ metrics 记录 `l4_targets_unsupported`

### P4: NativeL3 L4 Session Engine
- ✅ Phase 1: smoltcp 0.12 基础集成 + native_tun_stack.rs
- ✅ Phase 2: TCP Direct 连接 + SNI/Host sniff
- ✅ Phase 3: Named outbound / Group / Country 连接
- ✅ Phase 4: L3Profile 路由 + DNS 缓存反查
- ✅ Phase 5: 进程元数据 + 智能规则集成
- ✅ Phase 6: Runtime 状态持久化 + 国家组择优增强

### P5: 智能规则和 flow metadata 对齐
- ✅ NativeL3 和 mixed stream path 共享同一套智能规则优先级
- ✅ SNI / DNS cache / IP / app metadata 都可以影响 decision
- ✅ metadata 缺失时不崩溃，只 fallback

### P6: 节点测速、国家组和后台 probe 收口
- ✅ 手动测速包含失败节点（`include_failed: true` 默认）
- ✅ 后台测速不阻塞 connect_outbound
- ✅ 国家组按 `latency <= timeout_ms` 择优
- ✅ Runtime 状态持久化（last selected outbound）

### P7: 文档和验收收口
- ✅ README 更新 NativeL3 当前状态
- ✅ 本文档创建

## 未修复

### UDP Relay
- UDP 中继通过 L4 session engine 尚未实现
- 当前 UDP packet 走 L3Profile raw path 或被丢弃

### Domain Endpoint Bypass
- 域名格式的 L3 endpoint（如 `wg.example.com:51820`）需要 DNS 解析
- 当前只支持 IP literal 格式

### Hysteria v1 / OpenVPN
- 没有真实 integration test
- README 诚实标注状态

## 验证命令

```bash
cargo fmt --all -- --check          # ✅ pass
cargo check --tests                 # ✅ pass (2 warnings)
cargo test --all-targets            # ✅ 195 passed
cargo run -- check -c skyhook.example.yaml  # ✅ pass
```

## 风险

1. **smoltcp 性能**：高吞吐场景可能有瓶颈，需要 benchmark
2. **macOS lsof 依赖**：进程元数据查询依赖 lsof 命令
3. **DNS 缓存一致性**：TTL 60 秒可能不够准确
4. **Runtime 状态文件**：多实例并发访问可能有问题
