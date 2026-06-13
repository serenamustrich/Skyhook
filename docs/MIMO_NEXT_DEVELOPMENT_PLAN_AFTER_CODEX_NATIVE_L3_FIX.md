# MiMo 下一轮开发指引：Skyhook Native L3 修复后的收尾计划

日期：2026-06-13  
范围：`/Users/chency/Downloads/clash/Skyhook`  
目标：在保留 Skyhook 独立自研方向的前提下，把 MiMo 已写功能从“看起来有”推进到“真实可用、可验证、文档诚实”。

## 0. 当前状态先读清楚

Codex 已在本轮修复并验证以下关键问题，MiMo 继续开发时不要回滚：

1. `src/inbound/native_tun.rs`
   - Native L4 主循环现在在收到 TCP ACK 后会调用 `NativeTcpForwarder::pending_connect_sessions()` 和 `connect_and_pump()`。
   - 之前的 bug 是：测试手工调用了 `connect_and_pump()`，但真实 `serve()` 路径没有调用，所以实际 TUN TCP 不会真正拨出。
   - UDP 非 TCP 包现在通过 `NativeSessionManager::handle_udp_packet()` 走真实 direct/outbound/group/country 回包路径，并把响应写回 `l4_egress_tx`。

2. `src/inbound/native_tun_tcp_forward.rs`
   - TCP SYN-ACK / ACK / DATA 包现在会生成 IPv4 header checksum 和 TCP checksum。
   - 远端回包现在使用真实推进的 server seq 和 client ack，不再使用 `seq=0/ack=0` 的无效 TCP 数据包。
   - `tests/tcp_forwarder_e2e.rs` 已增加强断言：echo 回包必须回来、payload 必须一致、IP/TCP checksum 必须可验证。

3. `src/inbound/native_tun_session.rs`
   - 新增 `handle_udp_packet()`，用于 Native L4 实际 UDP 包的 direct/outbound/group/country/reject 分流。
   - direct UDP 会向真实 UDP server 发送 payload，等待 500ms 内的响应，并封装成返回虚拟客户端的 IPv4/IPv6 UDP 包。
   - `tests/native_l3_udp_tests.rs` 已增加强断言：本地 IPv4/IPv6 UDP echo server 必须收到请求并返回，响应包 source/destination/port/payload/checksum 都必须正确。

4. 已通过验证命令：
   - `cargo fmt --all`
   - `cargo test --test tcp_forwarder_e2e -- --nocapture`
   - `cargo test --test native_l3_udp_tests -- --nocapture`
   - `cargo test --all-targets`
   - `cargo run -- check -c skyhook.example.yaml`

注意：当前仍有 warnings，主要来自 MiMo 之前新增但未彻底接入的 `background_tasks.rs`、旧 NativeSessionManager 路径和部分测试。下一轮要处理，但不要为了消 warning 把真实链路改坏。

## 1. 开发原则

1. 不要做双核心，不要兼容 Mihomo API 作为目标。
   - Skyhook 是独立核心。
   - 可以参考旧玥球电梯功能体验，但不能把设计目标写成“兼容 Mihomo”。

2. 不要写假能力。
   - 能解析订阅但不能真实连接的协议，文档和 API 都必须标为 `parse-only` 或 `unsupported-runtime`。
   - 能跑单元测试不代表能真实拨号，必须有真实拨号路径或 mock server 级别的协议交互测试。

3. 先收敛架构，再补功能。
   - Native L3/TUN 现在同时有 `NativeTcpForwarder` 实际主路径和 `NativeSessionManager.process_events()` 旧 smoltcp 路径。
   - 下一轮必须明确单一主路径，避免两个半成品互相遮挡问题。

4. 每个任务完成后至少跑对应局部测试。
   - 不要求每个小修改都全量测试。
   - 一个大阶段结束后必须跑全量 `cargo test --all-targets`。

## 2. P0：把 Native L3/TUN 主路径收敛成一个真实可维护架构

### P0-1. 明确 TCP 主路径

目标：`NativeTcpForwarder` 成为 Native L4 TCP 的唯一主路径，旧 smoltcp TCP 逻辑不要继续参与真实 TUN TCP 转发。

涉及文件：

- `src/inbound/native_tun.rs`
- `src/inbound/native_tun_tcp_forward.rs`
- `src/inbound/native_tun_session.rs`
- `src/inbound/native_tun_stack.rs`
- `tests/native_l3_tcp_tests.rs`
- `tests/tcp_forwarder_e2e.rs`

要做：

1. 在 `native_tun.rs` 中保留当前 L4 loop 的 TCP 判断和 `connect_and_pump()` 调用。
2. 检查 `session_mgr.process_events(&runtime).await` 是否仍会重复处理同一个 TCP packet。
   - 如果会重复处理，必须改成只处理 DNS/UDP/旧测试需要的内容。
   - 不允许同一个 TCP flow 同时被 `NativeTcpForwarder` 和 smoltcp socket 接管。
3. 给 `NativeTcpForwarder` 增加清晰状态机注释：
   - `SynReceived`
   - `Connecting`
   - `Established`
   - `FinWait`
   - `Closed`
4. 完善 TCP 行为：
   - 收到重复 SYN：不要创建第二个 session；可以重发 SYN-ACK。
   - 收到乱序 payload：至少不要污染 seq/ack；后续可实现重排。
   - 收到 FIN：回 FIN-ACK，并标记关闭。
   - 收到 RST：立即删除 session，更新 metrics。
   - outbound connect 失败：回 RST 给客户端，不要沉默。
5. 补测试：
   - duplicate SYN 只保留一个 session，并有明确断言。
   - connect 失败时 egress 里能拿到 RST。
   - FIN 后再发 data 不应继续写 outbound。
   - echo 回包 checksum、seq、ack 必须正确。

验收：

- `cargo test --test tcp_forwarder_e2e -- --nocapture` 通过。
- `cargo test --test native_l3_tcp_tests -- --nocapture` 通过。
- 不新增 TCP 相关 warning。

### P0-2. 收敛 UDP 主路径

目标：Native L4 UDP 走真实、可回包、可统计的路径，而不是只 inject 到栈里后没有响应。

涉及文件：

- `src/inbound/native_tun.rs`
- `src/inbound/native_tun_session.rs`
- `src/inbound/native_tun_packet.rs`
- `tests/native_l3_udp_tests.rs`
- `tests/native_l3_real_e2e.rs`

要做：

1. 保留并完善 `handle_udp_packet()`，这是当前真实 L4 UDP 主路径。
2. 检查 `drain_udp_inbound()`：
   - 当前旧路径只读取 socket response 并更新计数，没有把 response inject/write 回 TUN。
   - 如果旧路径仍保留，必须调用 `inject_udp_response()` 或返回 response packet。
   - 如果旧路径不再是主路径，降低其职责，避免误导。
3. IPv4/IPv6 UDP 已有 checksum builder，但下一轮仍要继续压测。
   - IPv6 当前已有 loopback echo 测试，但还缺真实 TUN/公网 IPv6 场景。
   - 如果真实环境没有 IPv6 路由，要在 API/telemetry 中给出明确 drop/reject 原因。
4. direct UDP 的 timeout 需要从配置读取，不能写死 500ms。
   - 建议配置项：`native_tun.udp_response_timeout_ms`，默认 500。
   - 后续 UI 可以暴露。
5. outbound/group/country UDP：
   - `runtime.udp_exchange_named_outbound()` 成功后必须封装回客户端。
   - group/country resolve 失败必须有 telemetry。
   - reject 必须计入 metrics。

验收：

- `cargo test --test native_l3_udp_tests -- --nocapture` 通过。
- 保持 IPv6 loopback 行为测试通过；再补真实 TUN/公网 IPv6 场景或明确 reject/drop 测试。
- `cargo test --test native_l3_real_e2e -- --nocapture` 通过。

### P0-3. 增加 serve 级别的可测试 harness

目标：不要只测 `NativeTcpForwarder` 和 `NativeSessionManager`，还要测 `native_tun::serve()` 的主循环分发。

建议设计：

1. 抽出一个纯逻辑结构：
   - `NativeL4Dispatcher`
   - 输入：`(packet, FlowKey)`
   - 输出：`Vec<Vec<u8>>` 或 async egress channel
   - 内部持有 `NativeTcpForwarder`、UDP handler、metrics。
2. `serve()` 只负责：
   - TUN read/write
   - route setup/cleanup
   - DNS hijack
   - 调用 dispatcher
3. 测试直接构造 dispatcher，不需要 root、不需要真实 TUN。

涉及文件：

- 新建 `src/inbound/native_tun_dispatcher.rs`
- 修改 `src/inbound/mod.rs`
- 修改 `src/inbound/native_tun.rs`
- 新建 `tests/native_l4_dispatcher_tests.rs`

验收测试：

1. TCP SYN -> dispatcher 返回 SYN-ACK。
2. TCP ACK -> dispatcher 自动触发 connect_and_pump，不需要测试手工调用。
3. TCP data -> local echo server -> dispatcher egress 返回 echo payload。
4. UDP packet -> local UDP echo server -> dispatcher egress 返回 UDP payload。

这一步很重要，它能防止再次出现“单元测试通过但真实 serve 路径没调用”的问题。

## 3. P1：把后台任务从假 API 改成真实可控的 Runtime 服务

当前问题：

- `src/background_tasks.rs` 中很多函数只是静态模拟。
- API 可能返回“任务在跑”的状态，但实际没有长期 scheduler。
- 订阅更新、节点测速、智能学习 probe、流量持久化不能只靠外部手工触发。

涉及文件：

- `src/background_tasks.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `src/subscription_store.rs`
- `src/smart/mod.rs`
- `src/traffic_store.rs`
- `tests/config_and_runtime.rs`
- 新建 `tests/background_tasks_tests.rs`

要做：

1. 在 `Runtime` 内持有 `Arc<BackgroundScheduler>`。
2. `BackgroundScheduler` 必须真实管理任务：
   - `subscription_update`
   - `probe_all_nodes`
   - `smart_probe`
   - `traffic_persist`
   - `session_cleanup`
3. 每个任务要有：
   - `task_id`
   - `name`
   - `enabled`
   - `interval_ms`
   - `last_started_at`
   - `last_finished_at`
   - `last_error`
   - `running`
   - `success_count`
   - `failure_count`
   - `cancel_handle`
4. API：
   - `GET /background/tasks` 返回真实状态。
   - `POST /background/tasks/{id}/run-now` 立即执行一次。
   - `POST /background/tasks/{id}/pause` 暂停。
   - `POST /background/tasks/{id}/resume` 恢复。
   - `PATCH /background/tasks/{id}` 修改 interval/enabled。
5. 任务行为：
   - 订阅更新：更新所有订阅，不只当前 active。
   - 节点测速：后台跑，不阻塞代理连接。
   - 智能 probe：对观察到的域名/IP 做 direct 可达性测试，生成推荐规则。
   - 流量持久化：定期把内存 traffic snapshot 落盘。
6. 失败处理：
   - 单个订阅失败不影响其他订阅。
   - 单个节点测速失败不影响其他节点。
   - 每次失败写 telemetry 和 task.last_error。

验收：

- `cargo test --test background_tasks_tests -- --nocapture` 通过。
- API 测试确认 pause/resume/run-now 改变真实状态。
- 手工运行 Skyhook 后，`GET /background/tasks` 不再是静态假数据。

## 4. P1：把 TrafficStore 真正接入 Runtime 和 Subscription

当前问题：

- `src/traffic_store.rs` 已有持久化结构，但接入不完整。
- 需要支持按订阅累计总流量、按节点/规则/app 统计，并且重启不丢。

涉及文件：

- `src/traffic_store.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `src/subscription_store.rs`
- `src/outbound/mod.rs`
- `src/inbound/native_tun_metrics.rs`
- `tests/config_and_runtime.rs`
- `tests/subscription_store.rs`
- 新建 `tests/traffic_store_tests.rs`

要做：

1. Runtime 启动时加载 traffic store。
2. Runtime 关闭或后台 `traffic_persist` 时保存 traffic store。
3. 每次 TCP/UDP 代理流量都要记录：
   - active subscription id
   - outbound name
   - route decision
   - domain/ip
   - app identity（如果有）
   - bytes_tx
   - bytes_rx
4. direct 流量也要记录，但可和 proxy 分类展示。
5. 订阅更新不能清空该订阅历史流量。
6. 删除订阅时：
   - 默认保留历史流量。
   - 如果未来 API 支持 purge，再显式删除。
7. API：
   - `GET /traffic/summary`
   - `GET /traffic/subscriptions`
   - `GET /traffic/outbounds`
   - `GET /traffic/rules`
   - `GET /traffic/apps`
8. 单位：
   - API 返回原始 bytes。
   - UI 自己格式化 MB/GB。

验收：

- `subscription_traffic_accumulates_and_survives_replace` 保持通过。
- 新增重启加载测试：写入 -> drop runtime -> 新 runtime load -> bytes 不丢。
- 新增 active subscription 切换测试：A/B 两个订阅流量分别累计。

## 5. P1：协议能力必须诚实分级，继续补真实拨号

当前要求：

- 用户要求“协议覆盖不能比 Mihomo 差”，但 Skyhook 不能靠 parser 冒充真实拨号。
- README 和 API 必须把协议状态分清楚。

协议状态标准：

1. `runtime-ready`
   - 能解析配置。
   - 能建立真实 TCP 或 UDP 连接。
   - 有本地 mock server 或真实集成测试证明握手/收发。

2. `parse-only`
   - 能从订阅读取和保存。
   - 不能真实连接。
   - 不能在 UI/API 中显示为可用节点。

3. `experimental`
   - 有连接路径，但缺少重要特性或真实环境验证。
   - 可以手动启用，但默认不作为“稳定支持”宣传。

需要逐项检查：

- Shadowsocks：确认 TCP/UDP/插件/simple-obfs 状态。
- SSR：现在不能只 parse，必须实现真实 TCP connect 或标 parse-only。
- Trojan：确认 TCP/TLS 真实握手和 UDP 状态。
- VLESS：确认 TCP/WS/gRPC/H2/Reality/Vision 状态。
- VMess：确认 AEAD/TCP/WS/gRPC/H2 状态。
- Hysteria2：确认 TCP/UDP 状态。
- Hysteria v1：不要写成完成，除非有真实 server 测试。
- TUIC：确认 TCP/UDP 状态。
- Snell：实现真实拨号或标 parse-only；确认 obfs/UDP。
- ShadowTLS：实现真实拨号或标 parse-only。
- AnyTLS：实现真实拨号或标 parse-only。
- Naive：如果还没有实现，标 parse-only/unsupported-runtime。
- WireGuard：L3 engine 有测试，但要确认真实 peer/config path。
- OpenVPN：当前有 parser/control/data channel 片段，不等于 production-ready。
- SSH：确认 direct TCP tunnel 是否真实可用。
- Mieru/Juicity/Masque：如果只是保存，必须标 parse-only。

涉及文件：

- `src/outbound/mod.rs`
- `src/subscription.rs`
- `src/config.rs`
- `README.md`
- 新增或完善 `docs/PROTOCOL_SUPPORT_MATRIX.md`
- `tests/protocol_integration.rs`
- `tests/real_subscription_compat.rs`

验收：

- README 英文版和中文版都必须同步。
- `docs/PROTOCOL_SUPPORT_MATRIX.md` 每个协议必须写：
  - parse
  - tcp runtime
  - udp runtime
  - tls/obfs/transport
  - test coverage
  - known gaps
- `cargo test --test protocol_integration -- --nocapture` 通过。
- 需要真实 server 的测试必须 `#[ignore]` 并写清楚环境变量。

## 6. P1：智能规则页背后的核心能力补完整

用户的方向不是 Mihomo 复杂规则，而是 Skyhook 原生智能：

- 观察每次访问的域名/IP/app。
- 直连可达就推荐直连。
- 直连不可达就推荐代理。
- 用户可以一键启用或单条启用。
- 启用后优先级高于订阅规则。
- 支持指定域名/app/IP 走指定节点。

涉及文件：

- `src/smart/mod.rs`
- `src/routing.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `src/background_tasks.rs`
- `tests/smart_rules_tests.rs`

要做：

1. Observation 数据模型补齐：
   - key type：domain/ip/app/process_path/bundle_id。
   - first_seen/last_seen。
   - proxy_success/direct_success/direct_failure。
   - last_direct_probe_ms。
   - recommendation：direct/proxy/specific_outbound/ignore。
   - confidence。
2. Probe 策略：
   - 后台低优先级执行。
   - 同一 domain/IP 有冷却时间，避免频繁测试。
   - direct probe timeout 从配置读取。
   - 不阻塞真实代理流量。
3. Rule 应用：
   - `apply_one(id)`
   - `apply_all_recommended_direct()`
   - `apply_all_recommended_proxy()`
   - `ignore(id)`
   - `undo_applied(id)`
4. Rule 优先级：
   - 用户手动指定节点最高。
   - 用户启用智能规则高于订阅规则。
   - 订阅规则高于默认策略。
5. API：
   - `GET /smart/stats`
   - `GET /smart/recommendations?kind=direct|proxy|all`
   - `POST /smart/recommendations/{id}/apply`
   - `POST /smart/recommendations/apply-all`
   - `POST /smart/recommendations/{id}/ignore`
   - `GET /smart/rules`
   - `DELETE /smart/rules/{id}`
6. 指定节点：
   - domain -> outbound/group/country/direct/reject。
   - ip/cidr -> outbound/group/country/direct/reject。
   - app name/path/bundle id -> outbound/group/country/direct/reject。

验收：

- `cargo test --test smart_rules_tests -- --nocapture` 通过。
- 新增测试：智能规则优先级高于订阅规则。
- 新增测试：app 指定节点高于 domain 智能推荐。
- 新增测试：apply-all 不会启用 ignored 项。

## 7. P2：订阅和代理组继续补真实产品能力

涉及文件：

- `src/subscription_store.rs`
- `src/subscription.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `tests/subscription_store.rs`
- `tests/subscription_tests.rs`

要做：

1. 更新所有订阅：
   - API 必须真的遍历全部订阅。
   - 每个订阅独立记录 `last_updated_at`、`last_error`、`etag`、`profile_update_interval`。
   - 更新失败不能覆盖旧可用节点。
2. 订阅 metadata：
   - 保存 upload/download/total/expire。
   - 支持从 header `subscription-userinfo` 解析。
   - 支持从 Clash YAML provider metadata 解析。
   - API 返回原始 bytes 和 expire timestamp。
3. 导入行为：
   - 第一个订阅自动 active。
   - 已有 active 时，新导入只保存，不自动切换。
   - 重复 URL/固定 ID 导入要更新原订阅，不丢历史流量。
4. 代理组：
   - 支持订阅原始 group。
   - 支持 country group。
   - 支持直接选择某个 group 让 group 自己 url-test/select。
   - 支持选择具体节点。
5. 节点测速：
   - timeout ms 可配置。
   - > timeout 的节点直接标 unavailable。
   - UI/API 支持 `only_available=true`。
   - 后台测速不影响当前代理使用。

验收：

- `cargo test --test subscription_store -- --nocapture` 通过。
- `cargo test --test subscription_tests -- --nocapture` 通过。
- `cargo test --test real_subscription_compat -- --nocapture` 默认 fixture 通过，真实 URL 测试保持 ignored/env gated。

## 8. P2：API 清理和 OpenAPI/CLI 能力

涉及文件：

- `src/api/mod.rs`
- `src/main.rs`
- `README.md`
- 新增 `docs/API.md`

要做：

1. 把 API 分组：
   - `/runtime`
   - `/subscriptions`
   - `/outbounds`
   - `/groups`
   - `/traffic`
   - `/smart`
   - `/background`
   - `/native-tun`
2. 每个 API 返回统一结构：
   - `ok`
   - `data`
   - `error`
   - `timestamp`
3. CLI：
   - `skyhook check -c xxx.yaml`
   - `skyhook run -c xxx.yaml`
   - `skyhook probe --all`
   - `skyhook subscriptions update-all`
   - `skyhook smart stats`
   - `skyhook traffic summary`
4. 文档：
   - `docs/API.md` 写请求/响应例子。
   - README 只放主要例子，不塞太长。

验收：

- CLI 每个命令至少有 smoke test 或 snapshot test。
- API handler 的核心逻辑不要写死假数据。

## 9. P2：清 warnings 和文档夸大

当前 warnings 来源包括：

- `src/background_tasks.rs` 未使用 import/变量。
- `src/inbound/native_tun.rs` 未使用 `e`。
- `src/inbound/native_tun_session.rs` 未使用 `src_endpoint`。
- `UdpSession.target`、`UdpSession.remote_addr` 未读。
- `TcpForwardSession.bytes_rx` 未读。
- 部分 tests 未使用变量/import。

要做：

1. 先判断 warning 是“未接入功能”还是“应该删除”。
2. 对未接入功能：
   - 接入真实逻辑后 warning 自然消失。
   - 不要简单加 `_` 掩盖假实现。
3. 对确实无用变量：
   - 删除 import。
   - 改 `_name`。
   - 或补真实断言。
4. README 和 `docs/MIMO_FINAL_COMPLETION_REPORT.md` 不要写“全部完成”。
   - 改成按协议/模块状态列矩阵。
   - 已完成、实验性、parse-only、未实现分开。

验收：

- 最终目标：`cargo test --all-targets` 不出现 warning。
- README 中文/英文都不夸大。

## 10. P3：性能和稳定性优化

要做：

1. TCP forwarder：
   - 减少 per-packet Vec clone。
   - data channel 容量可配置。
   - 对 backpressure 有策略：drop/close/slow down。
2. UDP：
   - direct UDP session 复用 socket，不要每个 packet 新建 socket。
   - 支持多响应窗口。
   - 支持 DNS/QUIC 特殊统计。
3. Background probe：
   - 限制并发。
   - 按国家/订阅/节点类型分批。
   - 最近成功节点优先。
4. Traffic：
   - 内存聚合，定期批量落盘。
   - 避免每包写文件。
5. Benchmark：
   - 新增 `benches/native_l3_tcp.rs`
   - 新增 `benches/native_l3_udp.rs`
   - 新增 `benches/routing_decision.rs`

验收：

- 有 baseline benchmark 文档。
- 每次优化写明前后数据。

## 11. 建议执行顺序

严格按以下顺序做：

1. P0-3：抽 `NativeL4Dispatcher`，把真实主路径变成可测试结构。
2. P0-1：补 TCP 状态机细节和失败 RST。
3. P0-2：补 UDP session/IPv6/timeout 配置。
4. P1 background：把后台任务变成 Runtime 真实服务。
5. P1 traffic：把 TrafficStore 接入 Runtime/outbound/native tun。
6. P1 smart：补智能规则 observation/probe/apply/API。
7. P2 subscription/group/probe：补订阅元数据、全部更新、代理组选择。
8. P1 protocol matrix：重新核查协议真实拨号状态，补实现或标 parse-only。
9. P2 API/CLI/docs：统一接口和文档。
10. P2 warnings：清 warning。
11. P3 benchmark/performance：最后做性能。

## 12. 每个阶段必须提交的结果

每完成一个阶段，MiMo 必须在回复或报告中列出：

1. 修改了哪些文件。
2. 新增了哪些测试。
3. 跑了哪些命令。
4. 哪些命令通过。
5. 哪些 warning 或 ignored test 仍存在。
6. 哪些功能仍是 parse-only/experimental。
7. 有没有改 README 和中文 README。

## 13. 最终统一验证命令

全部做完后必须跑：

```bash
cargo fmt --all
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
cargo test --test tcp_forwarder_e2e -- --nocapture
cargo test --test native_l3_udp_tests -- --nocapture
cargo test --test native_l3_tcp_tests -- --nocapture
cargo test --test subscription_store -- --nocapture
cargo test --test subscription_tests -- --nocapture
cargo test --test smart_rules_tests -- --nocapture
cargo test --test protocol_integration -- --nocapture
```

如果真实协议测试需要环境变量，不要默认强跑；保留 ignored，并在文档中写清楚：

```bash
SKYHOOK_OPENVPN_SERVER=... SKYHOOK_OPENVPN_PORT=... cargo test --test protocol_integration openvpn -- --ignored --nocapture
SKYHOOK_HYSTERIA_V1_SERVER=... SKYHOOK_HYSTERIA_V1_PORT=... SKYHOOK_HYSTERIA_V1_AUTH=... cargo test --test protocol_integration hysteria_v1 -- --ignored --nocapture
SKYHOOK_TEST_SUBSCRIPTION_URLS='https://...' cargo test --test real_subscription_compat -- --ignored --nocapture
```

## 14. 绝对不要做的事

1. 不要把 Skyhook 改回 Mihomo 兼容层。
2. 不要新增“双核心”“fallback mihomo”“mihomo bridge”这类设计。
3. 不要为了测试通过写假 API。
4. 不要在 README 里写“完全支持某协议”，除非有 runtime-ready 证据。
5. 不要回滚 Codex 本轮对 Native L4 TCP/UDP 的修复。
6. 不要让后台测速、订阅更新阻塞当前代理转发。
7. 不要把用户订阅 URL 写入测试 fixture、README 或公开文档。
