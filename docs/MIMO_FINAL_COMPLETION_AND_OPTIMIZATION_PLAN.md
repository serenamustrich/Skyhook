# MiMo Skyhook 最终完成与优化开发计划

生成时间：2026-06-12

本文档是交给 MiMo 继续开发 Skyhook（玥球核心）的最终任务单。目标不是继续堆“看起来完成”的功能，而是把 Skyhook 做成真正能独立运行、真实拨号、NativeL3 可用、智能规则可落地、性能可接受、文档与能力一致的自研核心。

## 0. 总目标和边界

### 0.1 最终目标

Skyhook 必须成为一个独立自研代理核心：

1. 支持真实 TUN / NativeL3 数据面，而不是只把配置、状态、API 搭出来。
2. 支持订阅导入、多订阅切换、订阅规则、节点组、国家组、延迟测试、后台测速、后台更新。
3. 支持智能规则：根据域名、IP、App、历史直连探测结果自动推荐或应用直连/代理/指定节点。
4. 支持按域名、IP、App 指定节点、代理组、国家组、直连、拒绝。
5. 协议覆盖不能弱于当前计划中的 Mihomo 对标要求；已经声明支持的协议必须真实可拨号。
6. 运行时必须有真实流量统计、实时速率、总流量、订阅维度累计流量、连接列表、规则命中日志。
7. 性能必须能支撑日常桌面代理使用，不允许测速、订阅更新、智能探测阻塞正在使用的代理连接。

### 0.2 明确不要做的事

1. 不要再做“双核心”或“兼容 Mihomo 作为目标”的设计。Skyhook 是独立核心，可以参考已有功能，但不要把兼容 Mihomo 当作产品方向。
2. 不要只改 README 或 capability 文案就宣称完成。
3. 不要把未知协议、占位协议、parser-only 协议包装成“已支持”。
4. 不要隐藏失败节点、unsupported 节点或 partial 限制；UI/API 可以过滤，但核心必须保留真实状态。
5. 不要让后台测速、直连探测、订阅更新影响现有代理连接。
6. 不要为了单测通过而绕过真实网络数据流。
7. 不要大规模重构无关代码。每个阶段只改与该阶段目标直接相关的模块。

### 0.3 当前已知状态

当前代码能通过格式化、编译和现有测试，但 NativeL3 的 L4 session engine 还不能验收。重点问题如下：

1. `src/inbound/native_tun_stack.rs` 有 `create_tcp_socket()`，但生产路径没有在收到 TUN TCP SYN 前创建/监听 socket，`process_tcp_events()` 又只遍历已有 `tcp_handles`，因此真实 TCP 会话大概率不会被 smoltcp 接住。
2. `src/inbound/native_tun.rs` 的 L4 task 调用了 `take_pending_writes()`，但没有把 packet 写回 TUN，也没有真正发给 write loop，导致回包丢失。
3. `src/inbound/native_tun_session.rs` 在首次 connect 成功后，没有把 sniffer 缓存和首包写给 outbound，反而调用 `stack.tcp_send()`，方向错误。
4. `drain_inbound()` 在主 L4 loop 内直接 `await read()`，可能被单个远端连接阻塞。
5. UDP relay 尚未完成。
6. Hysteria v1、OpenVPN、Snell UDP/TLS obfs、SSR 变体、部分 AnyTLS/ShadowTLS 能力仍需要真实互通证明。

这些问题必须优先修复，然后再做后续优化。

## 1. 开发顺序总览

按以下顺序开发，不要跳着做：

1. P0：NativeL3 L4 TCP 数据面打通。
2. P1：NativeL3 UDP relay 数据面打通。
3. P2：NativeL3 route/setup/hot-reload/metrics 收口。
4. P3：智能规则闭环增强。
5. P4：节点测速、国家组择优、后台任务优化。
6. P5：订阅系统和多配置切换收口。
7. P6：协议真实拨号补齐。
8. P7：Telemetry、日志、连接与流量统计完善。
9. P8：性能优化。
10. P9：最终测试、文档、能力矩阵验收。

开发中可以阶段性跑 `cargo check --tests` 防止明显坏掉，但不要每写一点就跑全量大测试。全量验证放到 P9。

## 2. P0：NativeL3 L4 TCP 数据面打通

### 2.1 目标

通过 NativeL3 TUN 捕获系统 TCP 连接后，Skyhook 能按规则选择 Direct、指定 Outbound、代理组、国家组，并完成真实 TCP 双向转发：

App -> TUN -> Skyhook L4 stack -> selected outbound/direct -> remote server

remote server -> selected outbound/direct -> Skyhook L4 stack -> TUN -> App

### 2.2 需要修改的模块

重点文件：

1. `src/inbound/native_tun.rs`
2. `src/inbound/native_tun_stack.rs`
3. `src/inbound/native_tun_session.rs`
4. `src/inbound/native_tun_flow.rs`
5. `src/inbound/native_tun_packet.rs`
6. `src/inbound/native_tun_metrics.rs`
7. `src/core/mod.rs`

### 2.3 具体任务

#### P0.1 重新定义 L4 task 的通道结构

在 `native_tun.rs` 中新增真实 L4 回包通道：

1. `l4_ingress_tx/l4_ingress_rx`：read loop -> L4 session manager，传入原始 IP packet。
2. `l4_egress_tx/l4_egress_rx`：L4 session manager -> write loop，传出需要写回 TUN 的原始 IP packet。
3. write loop 必须同时处理：
   - DNS hijack response
   - L3 decapsulated packet
   - L4 egress packet
4. 每次写回 TUN 都必须经过 `encode_tun_write_packet()`。
5. 写成功后更新 `NativeTunMetrics.record_write()`。
6. 编码失败后更新 `record_encode_error()`。

验收：

1. `take_pending_writes()` 返回的 packet 不允许被忽略。
2. 代码中不能再出现 `for _packet in response_packets` 这种占位丢包写法。
3. `/skyhook/tun/metrics` 的 write bytes 会随着 L4 回包增长。

#### P0.2 修复 smoltcp socket 创建和透明接入

当前 `create_tcp_socket()` 只在测试里用，生产路径没有调用。必须实现真实透明 TCP session 创建。

建议实现方式：

1. 在 L4 收到 packet 后先用 `parse_ip_packet()` 和 `extract_transport_ports()` 解析 `FlowKey`。
2. 如果是 TCP SYN 且 flow 不存在：
   - 创建 session。
   - 创建 smoltcp TCP socket。
   - 让 socket 监听该 flow 的目标端口。
   - 验证 smoltcp 是否需要 `any_ip` / unspecified local endpoint 才能接受目的地址为真实公网 IP 的包。
3. 如果 smoltcp 不能自然支持透明接入：
   - 不要继续硬凑。
   - 改成显式 transparent TCP state engine，至少实现 SYN/SYN-ACK/ACK、payload、FIN/RST、window/seq/ack 基础状态。
   - 也可以保留 smoltcp，但必须通过真实端到端测试证明它能接受任意目标 IP 的 TUN TCP 流。
4. `NativeTunStack::poll()` 后必须能产生：
   - `TcpSynReceived`
   - `TcpData`
   - `TcpClosed`
5. 每个 flow 只创建一个 socket/session。
6. 关闭后必须 remove socket，避免泄漏。

验收：

1. 新增测试：构造 SYN packet -> inject -> poll -> 能产生 session/event。
2. 新增测试：同一 flow 重复 packet 不会重复创建 socket。
3. 新增测试：closed session 会从 `tcp_handles` 和 `sessions` 移除。
4. 不允许只有 `inject_and_poll_no_crash` 这种不验证功能的测试。

#### P0.3 修复首包和 sniffer 缓存转发

当前 `handle_tcp_data()` 首次 connect 后没有把 sniffed data 写到 outbound。

必须改成：

1. `PayloadSniffer` 缓存收到的所有 payload。
2. sniff 完成后，使用缓存里的完整 payload 作为首批 outbound 数据。
3. connect 成功后：
   - `write_half.write_all(sniffer.buffer())`
   - `bytes_tx += buffer.len()`
   - 清空或标记 sniffer buffer 已转发
4. 之后再收到 TCP data，直接写 outbound。
5. 不要把客户端首包通过 `stack.tcp_send()` 发回 TUN。

验收：

1. HTTP GET 首包必须能被本地 echo/http server 收到。
2. TLS ClientHello 首包必须能被 outbound 收到。
3. 首包统计进入 `bytes_tx`。
4. sniff timeout 到期时也必须转发已缓存数据，不能丢。

#### P0.4 改成非阻塞双向 pump

当前 `drain_inbound()` 在主 loop 里 `await read()`，会阻塞所有 session。

必须改成：

1. 每个 established session 启动独立 outbound read pump，或者使用集中 poll + timeout/select。
2. 远端 read pump 从 outbound 读数据后，通过 channel 回到 session manager。
3. session manager 把远端数据写入 smoltcp/custom stack，再把生成的 IP packet 发到 `l4_egress_tx`。
4. 单个连接无数据不能阻塞其他连接。
5. session 必须有 idle timeout。
6. session 必须有最大数量限制，超过后按策略拒绝或回收。

建议结构：

```text
Tun read loop
  -> l4_ingress_tx(packet)

L4 manager
  -> parse flow
  -> stack/session input
  -> selected outbound connect
  -> outbound write
  -> stack output packet
  -> l4_egress_tx(packet)

Per-session outbound read task
  -> remote bytes
  -> session_event_tx(RemoteData)

Tun write loop
  <- l4_egress_rx(packet)
  <- l3 inbound_rx(packet)
  <- dns_response_rx(packet)
```

验收：

1. 100 个并发本地 TCP echo session 不互相阻塞。
2. 一个 server 不返回数据时，不影响其他 session。
3. idle session 会清理。
4. `/skyhook/connections/active` 能看到 active session 数变化。

#### P0.5 Direct、Outbound、Group、Country、Reject 全部生效

当前 router 能解析这些 target，但数据面必须验证：

1. Direct：直接 `TcpStream::connect(dst_addr)`。
2. Outbound：`runtime.connect_named_outbound(name, destination)`。
3. Group：`runtime.resolve_group_member(name)` 后 connect。
4. Country：`runtime.resolve_country_best(code)` 后 connect。
5. Reject：TCP RST 或明确关闭，不要静默丢包。
6. L3Profile：继续走 raw L3 path，不进入 L4 session。

验收：

1. 每种 target 都有独立测试。
2. Reject 的 metric 增长，日志可见原因。
3. Group/Country 连接要记录最终实际使用的 outbound name。
4. 如果 Group/Country 无可用节点，必须返回明确错误并关闭 session。

## 3. P1：NativeL3 UDP relay 数据面打通

### 3.1 目标

NativeL3 不只支持 TCP，还要支持 UDP：

1. DNS hijack 继续优先处理 UDP 53。
2. 非 DNS UDP 根据智能规则/订阅规则决定 Direct、Outbound、Group、Country、Reject。
3. UDP 回包必须能写回 TUN。
4. UDP session 有 idle timeout 和流量统计。

### 3.2 具体任务

#### P1.1 明确 Outbound UDP 能力接口

检查 `src/outbound/mod.rs` 的 Outbound trait 和已有 UDP 支持路径。

需要统一：

1. `tcp_supported`
2. `udp_supported`
3. UDP dial/associate/packet relay 方法
4. UDP 不支持时的错误类型

如果当前 trait 没有统一 UDP 方法，新增明确接口，不要用协议内部私有函数硬接。

#### P1.2 实现 Direct UDP

1. Direct UDP 使用 `tokio::net::UdpSocket`。
2. 每个 flow 维护一个 UDP relay session。
3. 从 TUN 收到 UDP payload -> 发到目标地址。
4. 从目标地址收到 UDP payload -> 构造反向 IP/UDP packet -> `l4_egress_tx`。
5. idle timeout 默认 60 秒，可配置。

验收：

1. 本地 UDP echo server 测试通过。
2. 回包源/目标地址端口正确反转。
3. metrics 记录 UDP packets/bytes。

#### P1.3 实现 Outbound UDP

按协议能力分层实现：

1. Shadowsocks UDP relay。
2. SOCKS5 UDP associate。
3. Trojan UDP over TCP/UDP 按现有协议能力接入。
4. Hysteria2 datagram。
5. TUIC UDP。
6. VLESS/VMess 支持 UDP 的路径。
7. 不支持 UDP 的协议明确 reject/drop 并记录原因。

验收：

1. `/skyhook/outbounds` 的 UDP capability 与真实能力一致。
2. UDP 请求不会误走 TCP-only 节点。
3. `include_unsupported=false` 时测速/选择不会选中 UDP 不可用节点用于 UDP 场景。

#### P1.4 UDP 智能规则和 metadata

1. UDP flow 也要生成观察记录。
2. DNS cache 可把 UDP 目标 IP 反查为域名。
3. QUIC 初始包能解析 SNI 时记录域名。
4. App metadata 可用时也进入 decision。

验收：

1. QUIC/HTTP3 域名能尽量识别。
2. 无域名时按 IP 记录。
3. App 规则高于域名/IP 推断。

## 4. P2：NativeL3 route/setup/hot-reload/metrics 收口

### 4.1 route/setup

继续完善 `src/inbound/native_tun_system.rs`：

1. macOS endpoint bypass：
   - IP literal 必须安装在默认 route 前。
   - 域名 endpoint 必须解析后安装 bypass。
   - DNS 变化时需要可刷新。
2. route cleanup：
   - 只清理 Skyhook 本次安装的 route。
   - 失败 rollback 必须对称。
   - 多次 start/stop 不应残留 route。
3. IPv6：
   - 如果启用 IPv6 route，DNS hijack 和 packet parser 要真实支持。
   - 如果不支持，配置检查必须给明确 warning，并默认不安装 IPv6 默认 route。
4. route_exclude：
   - 必须走原 gateway bypass。
   - 不允许 route 到 TUN。

验收：

1. route plan 单测覆盖 route_add、bypass、endpoint_bypass、cleanup。
2. macOS 上手动 start/stop 三次后 route 表无残留。
3. 代理服务器 endpoint 不会被 TUN 捕获导致回环。

### 4.2 hot reload

实现 `/skyhook/tun/reload`，不要继续返回 “not yet implemented”。

需要支持：

1. 重新应用 route include/exclude。
2. 重新加载 endpoint bypass。
3. 更新 MTU 时，如果必须重建 TUN，返回明确 `requires_restart=true`。
4. 不影响已有 L3/WireGuard session，除非配置确实需要重启。

验收：

1. 修改 route_exclude 后 reload 生效。
2. reload 失败能 rollback 到旧 route。
3. API 返回 changed/unchanged/requires_restart/warnings。

### 4.3 metrics

补齐 NativeL3 metrics：

1. read packets/bytes
2. write packets/bytes
3. TCP active sessions
4. UDP active sessions
5. direct sessions
6. proxy sessions
7. group/country resolved sessions
8. rejected sessions
9. dropped packets
10. decode/encode errors
11. DNS hijack queries/success/failure/unsupported IPv6
12. L4 unsupported targets
13. per-outbound bytes
14. per-subscription bytes

验收：

1. `/skyhook/tun/status` 和 `/skyhook/tun/metrics` 返回真实增长数据。
2. `/skyhook/traffic/realtime` 看到 NativeL3 产生的实时速率。
3. 总流量可持久化，重启不清零。

## 5. P3：智能规则闭环增强

### 5.1 目标

Skyhook 的方向不是让用户维护复杂规则，而是自动学习：

1. 每次访问域名/IP/App 都记录 observation。
2. 对代理命中的目标，后台尝试直连。
3. 如果直连可用且延迟可接受，推荐直连。
4. 如果直连失败，推荐代理。
5. 用户可一键启用全部推荐，也可启用单条。
6. 启用后的智能规则优先级高于订阅规则。
7. 支持指定 App/domain/IP 走指定节点、代理组、国家组、直连、拒绝。

### 5.2 需要修改的模块

1. `src/smart/mod.rs`
2. `src/routing/mod.rs`
3. `src/core/mod.rs`
4. `src/api/mod.rs`
5. `src/inbound/mixed.rs`
6. `src/inbound/native_tun_session.rs`
7. `src/inbound/native_tun_process.rs`
8. `src/telemetry/mod.rs`

### 5.3 observation 模型补强

当前已有 observation 和 recommendation，但需要补充字段：

1. `first_seen_at`
2. `last_seen_at`
3. `last_proxy_outbound`
4. `last_selected_group`
5. `last_selected_country`
6. `app_name`
7. `app_bundle_id`
8. `app_path`
9. `resolved_ip`
10. `sni`
11. `http_host`
12. `dns_name`
13. `direct_probe_history`
14. `proxy_success_count`
15. `proxy_failure_count`
16. `direct_success_ratio`
17. `recommendation_state`: pending/enabled/ignored

验收：

1. mixed inbound 和 NativeL3 inbound 都写入同一套 observation。
2. 同一个 domain 不因大小写、尾点、端口差异重复记录。
3. IP 和 domain 有关联关系时可以在 API 中展示。

### 5.4 直连探测策略

实现后台 direct probe：

1. 不阻塞当前连接。
2. 遵守 cooldown。
3. 遵守全局 concurrency。
4. 默认 timeout 可配置，建议 500ms。
5. 对 TCP 目标：
   - 优先 TCP connect 目标端口。
   - 对 HTTP/HTTPS 可选 HEAD/ClientHello 级探测。
6. 对 UDP 目标：
   - DNS 用真实 query。
   - QUIC 可做 UDP reachability 或 QUIC Initial 尝试。
7. 探测失败要记录错误类型：
   - timeout
   - refused
   - dns_failed
   - network_unreachable
   - tls_failed
8. 不要无限重复探测失败目标。

验收：

1. 代理命中的域名后台产生 direct probe result。
2. 成功/失败都会进入 recommendation stats。
3. direct probe 不改变当前请求的实际路由。

### 5.5 推荐逻辑

推荐直连条件：

1. 样本数 >= `min_samples`。
2. direct probe success ratio >= `direct_success_min_ratio`。
3. direct latency <= `direct_max_latency_ms`。
4. 最近失败次数没有超过阈值。

推荐代理条件：

1. direct probe failure ratio >= `proxy_failure_min_ratio`。
2. 目标曾经走 direct 失败。
3. 或用户启用了自动代理保护策略。

推荐指定节点/组/国家：

1. 如果目标历史上某个 outbound 成功率明显更高，可以推荐该 outbound。
2. 如果用户对某 App 设置了国家偏好，则推荐国家组。
3. 如果指定域名属于某订阅规则组，可推荐原规则组。

验收：

1. `/skyhook/smart-rules/stats` 返回代理命中但直连可用比例。
2. `/skyhook/smart-rules/recommendations` 分 direct/proxy/outbound/group/country buckets。
3. apply-all 只启用 pending recommendation，不启用 ignored。
4. 智能规则启用后优先级高于订阅规则。

### 5.6 API 完善

新增或补齐 API：

1. `GET /skyhook/smart-rules/stats`
2. `GET /skyhook/smart-rules/observations`
3. `GET /skyhook/smart-rules/recommendations`
4. `POST /skyhook/smart-rules/recommendations/apply-all`
5. `POST /skyhook/smart-rules/recommendations/apply-one`
6. `POST /skyhook/smart-rules/recommendations/ignore`
7. `POST /skyhook/smart-rules/probe`
8. `POST /skyhook/smart-rules/reset-observation`
9. `POST /skyhook/smart-rules/export`
10. `POST /skyhook/smart-rules/import`

返回值必须带：

1. `ok`
2. `error`
3. `changed`
4. `stats`
5. `items`
6. `next_probe_at` 或 `cooldown_remaining_ms`

## 6. P4：节点测速、国家组择优、后台任务优化

### 6.1 节点测速

要求：

1. 手动“测速所有节点”必须包含超时/失败/之前不可用节点。
2. 自动后台测速不能阻塞代理连接。
3. 超过 timeout_ms 的节点直接记超时，不继续等待。
4. timeout_ms 原生支持配置，默认建议 500ms。
5. 支持按订阅、按国家、按组、按协议过滤测速。
6. 支持健康结果持久化。
7. 支持上次使用节点优先：
   - 启动代理时先使用上次节点。
   - 上次节点不可用时才触发同组/同国家择优。
   - 不要启动代理就全局测速。

需要检查/修改：

1. `src/core/mod.rs`
2. `src/telemetry/mod.rs`
3. `src/runtime_state.rs`
4. `src/api/mod.rs`

验收：

1. 100 个节点测速耗时接近 `ceil(nodes/concurrency) * timeout_ms`，不能慢 10 倍。
2. 节点超过 500ms 时能按配置提前 timeout。
3. 后台测速期间已有连接延迟不明显抖动。
4. API 返回每个节点：
   - latency_ms
   - last_error
   - alive
   - tested_at
   - protocol
   - country
   - subscription_id

### 6.2 国家组择优

要求：

1. 自动识别节点国家。
2. 国家组可以直接被选为 outbound target。
3. 选择国家后，连接时使用该国家当前最低延迟可用节点。
4. 后台定时刷新国家内节点延迟。
5. 国家组不能只看节点名称，还要支持：
   - emoji/flag
   - country code
   - server IP GeoIP
   - subscription group hint
6. 国家组中没有可用节点时，返回明确错误。

验收：

1. `/skyhook/countries` 返回国家列表、节点数、可用数、最佳节点、延迟。
2. `POST /skyhook/countries/use` 会持久化选择。
3. NativeL3 L4 session 的 Country target 使用同一套择优逻辑。

### 6.3 后台任务调度

新增统一 background scheduler：

1. subscription update task
2. outbound probe task
3. country refresh task
4. smart direct probe task
5. traffic persist task
6. cleanup stale connection/session task

要求：

1. 每个任务有独立 interval/concurrency/timeout。
2. 所有任务可暂停/恢复。
3. 所有任务失败不影响 core 主循环。
4. API 可查询 task 状态。

建议 API：

1. `GET /skyhook/tasks`
2. `POST /skyhook/tasks/run`
3. `POST /skyhook/tasks/pause`
4. `POST /skyhook/tasks/resume`

## 7. P5：订阅系统和多配置切换收口

### 7.1 多订阅

要求：

1. 支持保存多个订阅。
2. 每个订阅保存：
   - id
   - name
   - url
   - raw text path
   - parsed config path
   - imported_at
   - updated_at
   - expires_at
   - upload_used
   - download_used
   - total_available
   - traffic total accumulated by Skyhook
   - node count
   - group count
   - rule count
   - unsupported count
3. 导入新订阅时：
   - 如果当前没有 active subscription，自动切到新订阅。
   - 如果已有 active subscription，只保存，不自动切换。
4. update-all 必须更新所有订阅，不只是当前订阅。
5. 更新订阅不能让 API 页面一闪但实际没更新，必须返回详细结果。

验收：

1. `GET /skyhook/subscriptions` 显示流量和到期日期。
2. `POST /skyhook/subscriptions/update-all` 返回每个订阅成功/失败/未变化。
3. 切换订阅后规则、节点、组、国家组、流量维度都切换。
4. 不同订阅的累计流量互不污染。

### 7.2 订阅解析能力

继续增强：

1. Clash YAML
2. base64 URI list
3. SS/SSR/VMess/VLESS/Trojan/Hysteria/Hysteria2/TUIC/WireGuard/Snell/Naive/AnyTLS/ShadowTLS
4. proxy-groups
5. rule-providers
6. classical/ipcidr/domain rule sets
7. remote rule provider 下载、缓存、失败回退
8. user-agent、redirect、gzip/br、timeout、etag/last-modified

验收：

1. 用户提供过的两个订阅 URL 都能导入。
2. 订阅 header 中的 upload/download/total/expire 被解析并存储。
3. 不能解析的节点进入 unsupported 列表，并说明原因。
4. 解析失败不影响已有订阅继续可用。

### 7.3 active config 构建

active subscription -> runtime config 的构建必须稳定：

1. 保留订阅原代理组。
2. 保留订阅规则。
3. 叠加智能规则，智能规则优先。
4. 叠加用户自定义规则，优先级高于订阅规则。
5. 支持选择：
   - 原订阅规则
   - 指定节点
   - 指定代理组
   - 指定国家组
   - direct
6. 切换 active subscription 时，不要丢失其他订阅保存信息。

验收：

1. `POST /skyhook/subscriptions/active-config` 返回 summary。
2. `cargo run -- check` 能校验 active config。
3. active config reload 后连接使用新订阅节点。

## 8. P6：协议真实拨号补齐

### 8.1 原则

所有协议必须分三种状态：

1. `production`：真实拨号、基础互通测试、capability 正确。
2. `partial`：真实拨号路径存在，但变体未覆盖，limitations 写清楚。
3. `unsupported` / `parser-only`：只能解析或完全不能拨号，绝不宣称支持。

### 8.2 优先级

按用户要求和当前缺口，顺序如下：

1. Hysteria v1
2. OpenVPN
3. SSR 完整变体
4. Snell UDP + TLS obfs
5. AnyTLS 加固
6. ShadowTLS v3 加固
7. Naive 能力确认和互通测试
8. Shadowsocks simple-obfs UDP/限制说明
9. Mieru/Juicity/MASQUE：如果 Mihomo 对标要求需要，则实现；否则保持 unsupported 但文档诚实。

### 8.3 Hysteria v1

需要实现：

1. QUIC v1 session。
2. auth。
3. TCP stream。
4. UDP datagram。
5. obfs，如果配置声明支持。
6. ALPN/SNI/TLS settings。
7. bandwidth/up/down 参数解析和应用。
8. capability 从 planned 改成真实状态。

验收：

1. 本地或 mock Hysteria v1 server 互通。
2. TCP echo 通过。
3. UDP echo 通过。
4. 错误 auth 明确失败。
5. README 不再写 planned，除非仍未完成。

### 8.4 OpenVPN

需要实现：

1. `.ovpn` parser 已有，继续补齐选项。
2. TLS control channel。
3. key negotiation。
4. data channel encrypt/decrypt。
5. UDP transport。
6. TCP transport。
7. keepalive/ping/reconnect。
8. route pushed options 解析。
9. compression 默认拒绝或明确 unsupported，不要静默启用不安全压缩。
10. username/password/cert/key inline block。

验收：

1. `start_l3(openvpn)` 不再默认返回 Unsupported。
2. OpenVPN profile status 能显示 connecting/connected/error。
3. 本地 OpenVPN test server 能 ping 通隧道内地址。
4. 不支持配置返回明确 reason。

### 8.5 SSR

需要补齐：

1. method coverage。
2. protocol coverage。
3. obfs coverage。
4. UDP。
5. auth params。
6. subscription URI parser 与 outbound config 一致。

验收：

1. SSR 常见订阅节点能真实 TCP 拨号。
2. 不支持的 method/protocol/obfs 在 capability limitations 中可见。
3. UDP 支持或明确 partial。

### 8.6 Snell

需要补齐：

1. UDP。
2. TLS obfs。
3. version 1/2/3 差异。
4. obfs-host。
5. 错误密码/版本的明确错误。

验收：

1. TCP echo 通过。
2. UDP echo 通过。
3. TLS obfs 节点可连。

### 8.7 AnyTLS / ShadowTLS / Naive

需要做：

1. 协议 spec 对齐。
2. subscription parser 字段对齐。
3. capability limitations 对齐。
4. TLS fingerprint/ALPN/SNI 设置确认。
5. 互通测试。

验收：

1. 每个协议至少一个真实或 mock server TCP 互通测试。
2. 错误配置有清晰 error。
3. README capability 不夸大。

## 9. P7：Telemetry、日志、连接与流量统计

### 9.1 连接列表

连接列表必须统一 mixed inbound 和 NativeL3：

1. connection id
2. inbound kind
3. source address
4. destination host/ip/port
5. app identity
6. selected route
7. selected outbound
8. subscription id
9. country/group
10. bytes up/down
11. realtime speed up/down
12. started_at
13. duration_ms
14. rule source
15. smart recommendation hit/miss

验收：

1. `/skyhook/connections/active` 有真实 active connection。
2. 连接结束后进入历史摘要或 telemetry。
3. NativeL3 TCP/UDP 都能记录。

### 9.2 流量统计

必须持久化：

1. global total
2. per subscription total
3. per outbound total
4. per protocol total
5. per rule target total
6. per app total

要求：

1. 重启不清零。
2. 定期刷盘。
3. 异常退出最多丢失一个 persist interval。
4. 多实例启动要避免破坏 state，可用 lock file。

验收：

1. 使用订阅 A 产生流量，切订阅 B 后 A 的累计值仍保留。
2. 重启后总流量继续累计。
3. 实时速率不再长期为 0。

### 9.3 日志分类

核心日志需要带 category，方便 App 分 tab：

1. system
2. proxy
3. direct
4. reject
5. rule
6. dns
7. subscription
8. probe
9. smart
10. native_l3
11. protocol

日志字段：

1. timestamp
2. level
3. category
4. message
5. connection_id
6. destination
7. outbound
8. rule
9. error

验收：

1. `/skyhook/logs?category=direct`
2. `/skyhook/logs?category=proxy`
3. 默认倒序返回，最新在前。
4. 支持 limit/cursor。

## 10. P8：性能优化

### 10.1 NativeL3 packet path

当前风险：

1. `Vec::remove(0)` 会导致 O(n)。
2. 每包 clone/copy 太多。
3. 单 loop sleep 1ms 可能造成延迟和 CPU 浪费。
4. session read 不能阻塞 manager。

优化要求：

1. 使用 `VecDeque` 或 bounded channel 替代 `Vec::remove(0)`。
2. 高频路径尽量使用 `bytes::Bytes` / `BytesMut`。
3. 避免不必要 clone packet。
4. 用事件驱动替代固定 sleep。
5. bounded queue 满时明确 drop/backpressure metrics。
6. session map 可考虑 `DashMap` 或单线程 actor，避免锁竞争。
7. process resolver 使用缓存，避免频繁 lsof。

验收：

1. 1000 active TCP session 不明显卡顿。
2. 本机 loopback TCP relay 吞吐达到可接受水平。
3. CPU 使用率有 benchmark 记录。

### 10.2 节点测速性能

1. concurrency 默认合理，例如 32 或 64，可配置。
2. timeout 500ms 时不应出现每节点串行等待。
3. DNS 解析可并发但有上限。
4. TLS/HTTP probe 复用配置。
5. 失败节点也要快速结束。

验收：

1. 100 个节点 timeout 500ms、concurrency 50，理论不超过 1-2 秒级别，加上调度开销不能到十几秒。
2. 用户手动测速期间代理仍能使用。

### 10.3 订阅更新性能

1. update-all 并发更新多个订阅，但限制 concurrency。
2. 支持 ETag/Last-Modified。
3. 未变化订阅不重复 parse/reload。
4. parse rule-provider 可缓存。
5. 失败不影响旧数据。

验收：

1. update-all 返回每个订阅耗时。
2. unchanged 订阅更新时间策略明确：可记录 checked_at，不乱改 updated_at。

## 11. P9：最终测试与验收

### 11.1 开发完成前必须新增的测试

#### NativeL3 TCP

1. `native_l3_tcp_direct_echo_roundtrip`
2. `native_l3_tcp_named_outbound_roundtrip`
3. `native_l3_tcp_group_resolves_best_member`
4. `native_l3_tcp_country_resolves_best_member`
5. `native_l3_tcp_reject_sends_close_or_rst`
6. `native_l3_tcp_first_payload_is_forwarded_once`
7. `native_l3_tcp_remote_response_written_to_tun`
8. `native_l3_tcp_idle_session_cleanup`
9. `native_l3_tcp_many_sessions_no_head_of_line_blocking`

#### NativeL3 UDP

1. `native_l3_udp_direct_echo_roundtrip`
2. `native_l3_udp_named_outbound_roundtrip`
3. `native_l3_udp_dns_hijack_records_cache`
4. `native_l3_udp_unsupported_outbound_records_drop`
5. `native_l3_udp_idle_session_cleanup`

#### 智能规则

1. `smart_observes_proxy_routed_domain`
2. `smart_recommends_direct_after_successful_probe`
3. `smart_recommends_proxy_after_direct_failures`
4. `smart_rule_overrides_subscription_rule`
5. `smart_app_rule_overrides_domain_rule`
6. `smart_apply_all_skips_ignored_items`

#### 订阅

1. `subscription_import_does_not_auto_switch_when_active_exists`
2. `subscription_first_import_auto_switches`
3. `subscription_update_all_updates_every_subscription`
4. `subscription_userinfo_header_persists_expire_and_traffic`
5. `subscription_runtime_config_preserves_groups_and_rules`
6. `subscription_switch_isolates_traffic_totals`

#### 协议

1. `hysteria_v1_tcp_roundtrip`
2. `hysteria_v1_udp_roundtrip`
3. `openvpn_profile_starts_or_returns_specific_unsupported_reason`
4. `ssr_common_variants_parse_and_dial`
5. `snell_udp_roundtrip`
6. `anytls_shadowtls_naive_interop_smoke`

### 11.2 最终命令

最后统一跑：

```bash
cargo fmt --all -- --check
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

如果实现了 benchmark，再跑：

```bash
cargo bench
```

如果有 macOS NativeL3 手动验收脚本，再跑：

```bash
sudo target/debug/skyhook run -c skyhook.example.yaml
```

注意：需要 sudo 的 macOS TUN 验收不要混进普通 CI，单独写手动步骤。

### 11.3 手动验收清单

1. 启动 Skyhook。
2. 导入订阅 A。
3. 导入订阅 B，不自动切走 A。
4. update-all，A/B 都有 checked/update result。
5. 切换到 B，节点/组/规则更新。
6. 启动 NativeL3。
7. 打开网页，连接成功。
8. `/skyhook/traffic/realtime` 速率非 0。
9. `/skyhook/traffic/subscriptions` 当前订阅总流量增长。
10. 停止 Skyhook 后重启，总流量不清零。
11. 选择国家组，连接使用该国家最低延迟节点。
12. 手动测速所有节点，包含失败节点，超时节点快速结束。
13. 智能规则页看到 proxy-routed-but-direct-available 比例。
14. apply direct recommendation 后，该域名走 direct。
15. 为某 App 指定节点后，该 App 流量走指定节点。
16. 日志页 direct/proxy/rule 分 tab 可过滤，默认最新在上。
17. 停止 NativeL3，route 无残留。

## 12. 文档和 capability 最终收口

### 12.1 README 必须诚实

完成后更新：

1. README capability matrix。
2. NativeL3 状态。
3. Smart rules 状态。
4. Protocol status。
5. Known limitations。
6. API list。
7. macOS setup notes。

规则：

1. 没有真实拨号测试的协议，不写 production。
2. 只解析不拨号的协议，写 parser-only。
3. 部分变体不支持，写 partial 并列出 limitations。
4. 已完成的 route/setup 不要继续写 unsupported。

### 12.2 新增开发者文档

建议新增：

1. `docs/native-l3-architecture.md`
2. `docs/smart-rules-architecture.md`
3. `docs/protocol-support-matrix.md`
4. `docs/subscription-state.md`
5. `docs/performance-benchmarks.md`
6. `docs/manual-native-l3-macos-test.md`

每个文档都要写：

1. 目标
2. 关键模块
3. 数据流
4. 状态文件
5. API
6. 测试方式
7. 已知限制

## 13. MiMo 提交要求

每完成一个 P 阶段，MiMo 需要在回复中写：

1. 修改了哪些文件。
2. 解决了哪些验收项。
3. 还有哪些未完成项。
4. 跑了哪些命令。
5. 哪些命令没跑，为什么。
6. 如果某协议仍是 partial/unsupported，必须明确写原因。

最终完成时必须提交：

1. 功能完成列表。
2. 未完成列表，如果为空就写“无”。
3. 全量测试结果。
4. NativeL3 手动验收结果。
5. 协议支持矩阵。
6. 性能测试摘要。
7. 文档更新列表。

## 14. 最终验收标准

只有同时满足以下条件，才能说“全部完成”：

1. NativeL3 TCP 真实双向转发可用。
2. NativeL3 UDP 真实双向转发可用。
3. Direct/Outbound/Group/Country/Reject/L3Profile target 全部生效。
4. 首包不丢，回包不丢，session 不阻塞。
5. 智能规则能观察、探测、推荐、启用，并高于订阅规则。
6. 节点测速快，超时受配置控制，后台测速不影响代理。
7. 国家组能自动择优。
8. 多订阅可保存、更新、切换，流量和到期信息可见。
9. 总流量和订阅流量重启后不清零。
10. 连接、日志、规则命中、速率都有真实数据。
11. 已声明 production 的协议都有真实拨号测试。
12. partial/unsupported 状态在 API 和 README 中诚实一致。
13. `cargo fmt --all -- --check` 通过。
14. `cargo check --tests` 通过。
15. `cargo test --all-targets` 通过。
16. `cargo run -- check -c skyhook.example.yaml` 通过。
17. macOS NativeL3 手动验收通过且 route cleanup 无残留。

MiMo 不要再以“现有测试通过”作为完成标准。Skyhook 是代理核心，真正的完成标准是流量能被正确接住、正确选择路由、正确转发、正确统计、正确清理。
