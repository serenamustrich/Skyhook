# MiMo 执行计划：Skyhook 最终吹满版

日期：2026-06-13  
项目目录：`/Users/chency/Downloads/clash/Skyhook`  
目标：把 Skyhook 做到可以公开宣传、经得住大佬审视、协议和 TUN 能力不再靠“partial / experimental / env-gated”撑门面。

## 0. 最终版定义

Skyhook 只有同时满足以下条件，才允许在 README、发布页、GitHub 简介里写“production-ready / full support / native core / high performance”：

1. 默认构建无 warning：
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo check --tests`
   - `cargo test --all-targets`

2. 所有声明为 `production` 的协议必须真实可拨号：
   - 有本地 mock server 或真实 server integration test。
   - TCP/UDP 支持情况与 capability API、README 矩阵完全一致。
   - 真实 server test 可以 `#[ignore]`，但必须可通过环境变量复现。

3. Native L3/TUN 必须真实可用：
   - macOS 真实 TUN 环境可启动。
   - TCP、UDP、DNS、IPv4、IPv6 能跑通。
   - 真实 TUN soak test 至少 30 分钟无 panic、无明显内存增长、无 session 泄漏。

4. 智能规则必须成为核心卖点：
   - 自动观察访问目标。
   - 后台 direct probe 不阻塞代理转发。
   - 自动推荐 direct/proxy/specific outbound/group/country。
   - 一键启用、单条启用、忽略、撤销、优先级高于订阅规则。
   - 有统计页/API 能证明“代理规则里其实可直连”的比例。

5. 流量统计必须可信：
   - 实时速率。
   - 总流量累计。
   - 按订阅、节点、代理组、规则、应用、域名/IP 统计。
   - 重启不丢。
   - 路径可配置。

6. 性能必须有证据：
   - benchmark 文件和结果文档。
   - 至少覆盖 TCP 转发、UDP relay、DNS、routing decision、节点测速、Native TUN。
   - 和当前旧版 Mihomo/玥球电梯核心做本机对比，不能只写口号。

7. 文档必须统一：
   - `README.md`
   - `README.zh-CN.md`
   - `docs/PROTOCOL_SUPPORT_MATRIX.md`
   - `docs/API.md`
   - `docs/PERFORMANCE_BENCHMARKS.md`
   - `docs/NATIVE_TUN_REAL_TEST_REPORT.md`

## 1. 执行硬规则

1. 不准做双核心。
2. 不准重新依赖 Mihomo。
3. 不准把 parser-only 写成 production。
4. 不准把 ignored test 当作通过，除非报告里写清楚环境变量和执行结果。
5. 不准把测试专用 fake server 的结果包装成真实公网验证。
6. 不准把订阅 URL、token、server secret 写进 README、测试 fixture 或日志。
7. 每完成一个阶段，必须更新本计划下方的验收清单，写明：
   - 改了哪些文件。
   - 新增哪些测试。
   - 跑了哪些命令。
   - 哪些真实环境测试没跑，为什么。
   - 哪些协议仍然 partial。

## 2. P0：建立最终验收基线

### P0-1. 新建状态矩阵文档

新增文件：

- `docs/PROTOCOL_SUPPORT_MATRIX.md`
- `docs/FINAL_ACCEPTANCE_CHECKLIST.md`
- `docs/REAL_WORLD_TEST_ENV.md`

`PROTOCOL_SUPPORT_MATRIX.md` 必须按协议列字段：

- protocol
- config parse
- subscription parse
- TCP runtime
- UDP runtime
- transports
- obfs
- TLS/security
- mock server test
- real server test
- default probe support
- limitations
- status：`production` / `partial` / `experimental` / `parser-only` / `planned`

必须覆盖：

- Direct
- HTTP proxy
- SOCKS5
- Shadowsocks AEAD
- Shadowsocks simple-obfs
- SSR
- Trojan
- VMess AEAD
- VLESS
- Reality/Vision
- Hysteria2
- Hysteria v1
- TUIC
- Naive
- SSH
- Snell
- AnyTLS
- ShadowTLS
- WireGuard
- OpenVPN
- Mieru
- Juicity
- MASQUE

验收：

```bash
rg -n "production|partial|parser-only|planned" docs/PROTOCOL_SUPPORT_MATRIX.md
```

每一行 production 都必须能指向对应测试文件。

### P0-2. 建立最终 CI 命令

新增脚本：

- `scripts/verify_final.sh`
- `scripts/verify_real_protocols.sh`
- `scripts/verify_native_tun_real.sh`
- `scripts/bench_final.sh`

`scripts/verify_final.sh` 必须执行：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --tests
cargo test --all-targets
cargo run -- check -c skyhook.example.yaml
```

`scripts/verify_real_protocols.sh` 只跑 env-gated 真实协议测试，例如：

```bash
SKYHOOK_HYSTERIA_V1_SERVER=... SKYHOOK_HYSTERIA_V1_PORT=... SKYHOOK_HYSTERIA_V1_AUTH=... cargo test --test protocol_integration hysteria_v1 -- --ignored --nocapture
SKYHOOK_OPENVPN_PROFILE=... cargo test --test openvpn_real_integration -- --ignored --nocapture
SKYHOOK_SNELL_SERVER=... cargo test --test snell_real_integration -- --ignored --nocapture
```

验收：

- `scripts/verify_final.sh` 本机通过。
- 没有 warning。

## 3. P1：协议生产级补全

目标：把当前 README 里所有 partial/parser-only 的高价值协议补到能宣传的级别；补不完就保持 partial，不准硬吹。

### P1-1. Hysteria v1 真拨号

当前状态：partial / env-gated。  
目标：production 或诚实 partial。

涉及文件：

- `src/outbound/mod.rs`
- `src/config/mod.rs`
- `src/subscription/mod.rs`
- `tests/protocol_integration.rs`
- 新增 `tests/hysteria_v1_mock.rs`
- 新增 `tests/hysteria_v1_real.rs`

必须做：

1. 重新核对 Hysteria v1 协议，不要照搬 Hysteria2。
2. 明确支持字段：
   - auth / auth_str
   - sni
   - skip_cert_verify
   - obfs
   - up/down
   - TCP stream relay
   - UDP relay
3. 实现或修正：
   - QUIC 连接建立。
   - 认证。
   - TCP stream open。
   - UDP packet relay。
   - timeout。
   - error mapping。
   - capability reporting。
4. 增加 mock server 测试：
   - TCP connect request。
   - TCP echo。
   - UDP echo。
   - auth failure。
   - timeout。
5. 增加真实 server ignored 测试：
   - `SKYHOOK_HYSTERIA_V1_SERVER`
   - `SKYHOOK_HYSTERIA_V1_PORT`
   - `SKYHOOK_HYSTERIA_V1_AUTH`
6. 更新 README 和协议矩阵。

允许写 production 的条件：

- mock TCP/UDP pass。
- real TCP/UDP ignored test 至少在本机跑过一次并记录输出。
- `probe_outbounds` 能测 Hysteria v1。
- obfs 如果没做，状态必须是 `partial`，不能 production。

### P1-2. OpenVPN Native L3 真拨号

当前状态：parser/control/data-channel partial。  
目标：至少做到实验可用 L3 tunnel；如果要吹满，必须 production。

涉及文件：

- `src/l3/openvpn/parser.rs`
- `src/l3/openvpn/control.rs`
- `src/l3/openvpn/data_channel.rs`
- `src/l3/openvpn/mod.rs`
- `src/l3/mod.rs`
- `src/inbound/native_tun.rs`
- `src/inbound/native_tun_dispatcher.rs`
- 新增 `tests/openvpn_packet_tests.rs`
- 新增 `tests/openvpn_real_integration.rs`

必须做：

1. Profile 支持：
   - remote 多节点。
   - proto udp/tcp-client。
   - dev tun。
   - ca/cert/key inline。
   - auth-user-pass。
   - cipher/data-ciphers。
   - auth digest。
   - tls-auth。
   - tls-crypt。
   - reneg-sec。
   - ping/ping-restart。
   - redirect-gateway。
   - route。
   - ifconfig/pushed options。
2. Control channel：
   - packet opcode parse/serialize。
   - session id。
   - packet id。
   - ACK。
   - hard reset。
   - TLS over OpenVPN control packets。
   - push request / push reply。
   - key material export。
3. Data channel：
   - AES-128-GCM。
   - AES-256-GCM。
   - ChaCha20-Poly1305。
   - packet id。
   - replay protection。
   - compression disabled/reject。
4. L3 bridge：
   - TUN packet -> OpenVPN data packet -> server。
   - server data packet -> decrypt -> TUN egress。
   - keepalive。
   - reconnect。
   - clean shutdown。
5. Tests：
   - parser unit tests。
   - packet codec roundtrip。
   - data channel encrypt/decrypt。
   - fake OpenVPN server handshake test。
   - real OpenVPN server ignored test。

允许 README 写 production 的条件：

- 本地 fake server 能完成控制通道和数据通道。
- 真实 OpenVPN server ignored test 能 ping 通 tunnel 内地址。
- Native TUN 使用 OpenVPN profile 能真实转发 IP packet。

### P1-3. Snell 补全

当前状态：TCP partial。  
目标：production 或明确 partial。

涉及文件：

- `src/outbound/mod.rs`
- `src/subscription/mod.rs`
- `tests/snell_tests.rs`
- `tests/snell_real_integration.rs`

必须做：

1. Snell v1/v2/v3 TCP 全覆盖。
2. 支持 TLS obfs。
3. 支持 HTTP obfs 参数完整解析。
4. 补 UDP relay：
   - 如果协议原生 UDP 可以实现，做原生 UDP。
   - 如果只能 TCP tunnel，README 必须写 `UDP over TCP tunnel`，不能写 native UDP。
5. 真实 server ignored test。
6. capability API 写清楚 UDP 模式。

允许 production 的条件：

- TCP mock pass。
- UDP mock pass。
- obfs mock pass。
- real server smoke pass。

### P1-4. SSR 变体补全

当前状态：partial。  
目标：至少覆盖机场常见 SSR 变体。

必须支持并测试：

- methods：
  - aes-128-cfb
  - aes-192-cfb
  - aes-256-cfb
  - chacha20-ietf
  - chacha20-ietf-poly1305 如不支持必须写 limitations
- protocol：
  - origin
  - auth_sha1_v4
  - auth_aes128_md5
  - auth_aes128_sha1
- obfs：
  - plain
  - http_simple
  - http_post
  - tls1.2_ticket_auth

验收：

- parser tests。
- request encoding tests。
- mock server tests。
- 真实节点 smoke test env-gated。

### P1-5. AnyTLS / ShadowTLS / Naive

目标：不要只“能连一次”，要把失败、TLS、安全参数、订阅字段都补完整。

必须做：

- AnyTLS：
  - auth/password。
  - stream open。
  - mux/session。
  - TLS verify/skip verify。
  - SNI。
  - mock + real tests。
- ShadowTLS v3：
  - ClientHello HMAC。
  - app-data framing。
  - password 校验。
  - fake SNI。
  - mock + real tests。
- Naive：
  - HTTPS CONNECT。
  - user/pass。
  - ALPN。
  - TLS verify。
  - proxy response parsing。

验收：

- 状态矩阵准确。
- production 必须有真实拨号证明。

## 4. P2：Native L3/TUN 做到可以吹

当前状态：核心 dispatcher/TCP/UDP 已接入，但还缺真实 TUN soak test 和生产硬化。

### P2-1. 抽象真实 TUN 测试 harness

新增：

- `tests/native_tun_privileged.rs`
- `scripts/run_native_tun_real_test.sh`
- `docs/NATIVE_TUN_REAL_TEST_REPORT.md`

测试必须覆盖：

1. macOS utun 创建。
2. route setup。
3. route cleanup。
4. DNS hijack。
5. TCP direct echo。
6. TCP proxy echo。
7. UDP direct echo。
8. UDP proxy echo。
9. IPv6 UDP echo。
10. FIN/RST。
11. 大包/MTU 边界。
12. 10k 短连接。
13. 30 分钟 soak。

真实测试需要 sudo，可以 `#[ignore]`，但脚本必须可运行。

### P2-2. TCP 转发器生产硬化

涉及文件：

- `src/inbound/native_tun_tcp_forward.rs`
- `tests/tcp_forwarder_e2e.rs`
- `tests/native_l4_dispatcher_tests.rs`

必须做：

1. duplicate SYN 重发 SYN-ACK，不创建重复 session。
2. outbound connect fail 回 RST。
3. FIN 双向关闭。
4. RST 立即清理。
5. seq/ack 推进覆盖：
   - payload 多段。
   - server 多段回包。
   - zero-window 或 backpressure。
6. channel 满时策略：
   - close session 或 backpressure。
   - 不准静默丢数据。
7. session metrics：
   - active。
   - closed。
   - bytes tx/rx。
   - error reason。

### P2-3. UDP relay 生产硬化

必须做：

1. direct UDP socket 复用，不要每包新建 socket。
2. NAT/session table：
   - flow key。
   - remote endpoint。
   - last activity。
   - bytes tx/rx。
3. 多响应支持。
4. timeout 配置化。
5. DNS/QUIC 特殊统计。
6. IPv6 checksum 验证测试。
7. outbound/group/country UDP 失败 telemetry。

### P2-4. Native L3 与智能规则联动

必须做：

1. DNS cache IP -> domain 在 dispatcher 中保持同一 session manager。
2. SNI/HTTP Host sniffing 可用于 routing decision。
3. app/process identity 可用于 smart rules。
4. fake-IP reverse mapping 支持。
5. 访问记录进入 smart observation。

验收：

- Native TUN 访问一个域名后，smart observation 里能看到 domain/ip/app。
- 用户应用规则后，下一次访问走指定节点。

## 5. P3：智能规则做成核心卖点

当前状态：observation/recommendation 有基础，但独立后台智能探测不完整。

### P3-1. Background Smart Probe Worker

涉及文件：

- `src/background_tasks.rs`
- `src/smart/mod.rs`
- `src/core/mod.rs`
- `src/api/mod.rs`
- `tests/smart_rules_tests.rs`
- 新增 `tests/smart_background_tests.rs`

必须实现：

1. worker 从 observations 取 pending probe。
2. 按 cooldown 去重。
3. 并发数可配置。
4. timeout 可配置。
5. direct probe 失败不影响当前代理连接。
6. probe 结果更新 observation。
7. 产生 recommendation。
8. `smart_probe` task run-now 真的执行 probe，而不是只打日志。
9. pause/resume 生效。
10. 任务状态记录：
    - last_started_at。
    - last_finished_at。
    - running。
    - success_count。
    - failure_count。
    - last_error。

验收：

- `cargo test --test smart_background_tests -- --nocapture`
- API run-now 后 recommendations 数量变化。

### P3-2. 智能规则优先级最终化

优先级必须固定：

1. 手动 app/path/bundle rule。
2. 手动 domain/ip/cidr rule。
3. 已启用智能规则。
4. 订阅规则。
5. 国家组/代理组默认策略。
6. core default outbound。

测试必须覆盖：

- app > domain。
- ip > subscription rule。
- enabled smart > subscription rule。
- ignored recommendation 不会 apply-all。
- undo 后恢复订阅规则。

### P3-3. 指定节点能力

必须支持：

- domain -> exact outbound。
- suffix domain -> exact outbound。
- ip -> exact outbound。
- cidr -> exact outbound。
- app name -> exact outbound。
- app path -> exact outbound。
- bundle id -> exact outbound。
- domain/app/ip -> group。
- domain/app/ip -> country。
- domain/app/ip -> direct。
- domain/app/ip -> reject。

API：

- `GET /skyhook/smart-rules/stats`
- `GET /skyhook/smart-rules/observations`
- `GET /skyhook/smart-rules/recommendations`
- `POST /skyhook/smart-rules/recommendations/apply-one`
- `POST /skyhook/smart-rules/recommendations/apply-all`
- `POST /skyhook/smart-rules/recommendations/ignore`
- `POST /skyhook/smart-rules/undo`
- `POST /skyhook/smart-rules/upsert-specific-outbound`

## 6. P4：后台任务系统生产化

当前状态：有默认任务和 run-now，但没有长期 worker 管理、cancel handle、interval 配置化。

必须做：

1. `BackgroundScheduler` 增加：
   - task id。
   - running。
   - next_run_at。
   - last_started_at。
   - last_finished_at。
   - success_count。
   - failure_count。
   - cancel handle。
   - interval update。
2. Runtime 启动后台任务：
   - subscription_update。
   - outbound_probe。
   - smart_probe。
   - traffic_persist。
   - session_cleanup。
3. 支持 shutdown：
   - Runtime drop 或 signal 时停止任务。
4. API：
   - `GET /skyhook/background/tasks`
   - `POST /skyhook/background/tasks/run-now`
   - `POST /skyhook/background/tasks/pause`
   - `POST /skyhook/background/tasks/resume`
   - `PATCH /skyhook/background/tasks`
5. 测试：
   - run-now 真执行。
   - pause 后不执行。
   - resume 后执行。
   - interval 到期自动执行。
   - shutdown 停止任务。

## 7. P5：流量统计最终版

当前状态：Telemetry 和 TrafficStore 都有，但 TrafficStore 路径固定，统计维度还不够。

必须做：

1. 配置化路径：
   - `core.state_dir` 或 `traffic.store_path`。
   - 不要硬写 `~/.skyhook/traffic.json`。
2. 统计维度：
   - global。
   - subscription。
   - outbound。
   - proxy group。
   - country group。
   - rule。
   - app。
   - domain。
   - ip/cidr。
   - protocol TCP/UDP/DNS。
3. 速率：
   - upload B/s。
   - download B/s。
   - per outbound rate。
   - per subscription rate。
4. 持久化：
   - 批量落盘。
   - crash-safe atomic write。
   - schema version。
   - migration。
5. API：
   - `GET /skyhook/traffic/realtime`
   - `GET /skyhook/traffic/summary`
   - `GET /skyhook/traffic/subscriptions`
   - `GET /skyhook/traffic/outbounds`
   - `GET /skyhook/traffic/rules`
   - `GET /skyhook/traffic/apps`
   - `GET /skyhook/traffic/domains`
6. 测试：
   - 重启后不丢。
   - 切订阅分别累计。
   - 删除订阅默认不删历史。
   - traffic_persist 任务落盘。

## 8. P6：订阅和代理组最终版

必须做：

1. 订阅更新所有订阅。
2. 更新失败不覆盖旧数据。
3. 订阅 metadata：
   - upload。
   - download。
   - total。
   - expire。
   - update interval。
   - last updated。
   - last error。
4. 支持订阅原始代理组。
5. 支持 country groups。
6. 支持 group select/url-test/fallback/load-balance。
7. 支持直接选择 group，由 group 自己择优。
8. 支持“只显示可用节点”。
9. 节点测速：
   - timeout ms 配置。
   - 默认 500ms。
   - > timeout 立即不可用。
   - 后台并发测速。
   - 不影响当前代理。
10. 真实订阅兼容：
   - Clash YAML。
   - base64 URI list。
   - mixed content。
   - userinfo header。
   - rule providers。

验收：

- `tests/real_subscription_compat.rs` 增加更多 fixture。
- 真实 URL env-gated 测试。
- API 返回 metadata 完整。

## 9. P7：DNS / fake-IP / rule provider

必须做：

1. DNS：
   - DoH。
   - DoT。
   - UDP DNS。
   - TCP DNS。
   - fallback DNS。
   - nameserver policy。
2. fake-IP：
   - fake-ip 分配。
   - reverse mapping。
   - TTL。
   - filter。
   - cache persistence。
3. rule provider：
   - domain set。
   - ip cidr set。
   - classical rules。
   - update interval。
   - cache。
4. Native TUN：
   - DNS hijack 使用 fake-IP reverse mapping。
   - smart observation 记录原始域名。

验收：

- DNS fake-IP roundtrip test。
- rule provider reload test。
- Native TUN DNS hijack real test。

## 10. P8：性能 benchmark 和压测

新增：

- `benches/routing_decision.rs`
- `benches/tcp_forwarder.rs`
- `benches/udp_relay.rs`
- `benches/dns.rs`
- `benches/subscription_parse.rs`
- `benches/probe_scheduler.rs`
- `docs/PERFORMANCE_BENCHMARKS.md`

必须测：

1. routing decision p50/p95/p99。
2. smart rule decision p50/p95/p99。
3. TCP direct throughput。
4. TCP proxy throughput。
5. UDP relay PPS。
6. DNS query latency。
7. subscription parse speed。
8. 100/500/1000 节点测速耗时。
9. 10k connection open/close。
10. memory growth 30 min soak。

建议目标：

- routing decision p95 < 50us。
- smart rule decision p95 < 100us。
- 500 节点测速在 500ms timeout 下总耗时 < 10s。
- Native L3 TCP loopback throughput 至少达到旧版玥球电梯/Mihomo 同机测试的 70%，后续再优化到持平或超过。
- 30 分钟 soak 后 active session 归零、RSS 增长 < 5%。

注意：如果达不到目标，不准改文档吹性能；必须写真实数据和下一步优化。

## 11. P9：安全和稳定性

必须做：

1. `cargo audit`。
2. `cargo deny`。
3. secrets redaction：
   - subscription URL。
   - password。
   - token。
   - private key。
   - auth。
4. TLS verify 默认开启。
5. skip cert verify 必须在 capability/metadata 标记风险。
6. socket timeout 全面配置化。
7. panic boundary：
   - 网络任务不 panic。
   - task failure 写 telemetry。
8. fuzz：
   - subscription parser。
   - SOCKS5 UDP parser。
   - VMess/VLESS request parser。
   - Native TUN packet parser。
   - OpenVPN packet parser。

新增：

- `fuzz/`
- `docs/SECURITY.md`

## 12. P10：API / CLI / 文档最终化

### API

统一响应格式：

```json
{
  "ok": true,
  "data": {},
  "error": null,
  "timestamp": "..."
}
```

必须补：

- `docs/API.md`
- OpenAPI JSON：`docs/openapi.json`

### CLI

必须支持：

```bash
skyhook check -c skyhook.yaml
skyhook run -c skyhook.yaml
skyhook probe --all
skyhook subscriptions import --url ...
skyhook subscriptions update-all
skyhook traffic summary
skyhook smart stats
skyhook native-tun test
skyhook bench
```

### 文档

必须有：

- `README.md`
- `README.zh-CN.md`
- `docs/QUICK_START.md`
- `docs/CONFIG_REFERENCE.md`
- `docs/PROTOCOL_SUPPORT_MATRIX.md`
- `docs/NATIVE_TUN_REAL_TEST_REPORT.md`
- `docs/PERFORMANCE_BENCHMARKS.md`
- `docs/SECURITY.md`
- `docs/API.md`

## 13. P11：GitHub 开源展示

目标：让 GitHub 大佬看了觉得这是认真项目，不是玩具。

必须做：

1. README 首屏：
   - Skyhook / 玥球核心定位。
   - 架构图。
   - 协议矩阵。
   - Native TUN 能力。
   - Smart routing 截图或 API 示例。
   - benchmark 表。
2. Badges：
   - CI。
   - tests。
   - license。
   - rust version。
3. examples：
   - minimal direct。
   - proxy groups。
   - subscription。
   - native tun。
   - smart rules。
   - traffic API。
4. GitHub Actions：
   - fmt。
   - clippy。
   - test。
   - audit。
   - docs link check。
5. Release：
   - macOS arm64 binary。
   - checksums。
   - changelog。

## 14. 最终验收顺序

MiMo 必须按顺序执行：

1. P0：状态矩阵和 final verify 脚本。
2. P1：协议生产级补全。
3. P2：Native L3/TUN 真实测试和硬化。
4. P3：智能规则后台探测。
5. P4：后台任务生产化。
6. P5：流量统计最终版。
7. P6：订阅和代理组最终版。
8. P7：DNS/fake-IP/rule provider。
9. P8：benchmark。
10. P9：安全。
11. P10：API/CLI/docs。
12. P11：GitHub 展示。

## 15. 最终一键验收命令

全部完成后，必须能运行：

```bash
scripts/verify_final.sh
scripts/bench_final.sh
```

如果有真实环境：

```bash
scripts/verify_real_protocols.sh
scripts/run_native_tun_real_test.sh
```

最终报告必须生成：

- `docs/FINAL_ACCEPTANCE_REPORT.md`
- `docs/PERFORMANCE_BENCHMARKS.md`
- `docs/NATIVE_TUN_REAL_TEST_REPORT.md`
- `docs/PROTOCOL_SUPPORT_MATRIX.md`

## 16. 允许吹满的最终文案条件

只有满足以下条件，README 才能写类似文案：

> Skyhook is a Rust-native intelligent proxy core with production-grade TCP/UDP dialing, native TUN support, smart routing, persistent traffic analytics, and reproducible performance benchmarks.

条件：

1. 所有 production 协议都有真实拨号或 mock+real env-gated 测试。
2. Native TUN 真实测试报告存在。
3. benchmark 报告存在。
4. `cargo clippy -D warnings` 通过。
5. README.zh-CN 与 README.md 状态一致。
6. 没有 “全部完成” 但实际 ignored 的矛盾。

## 17. 当前不能吹满的原因

截至当前复核，下面这些还没到吹满级别：

1. Hysteria v1 真实服务器测试仍 env-gated，没有固定通过报告。
2. OpenVPN 还不是 production native dialing。
3. Snell UDP/TLS obfs 不能标 production。
4. smart_probe 后台任务还不是完整 probe worker。
5. TrafficStore 路径固定，统计维度不足。
6. Native L3/TUN 缺真实 sudo/utun soak test。
7. benchmark 缺失。
8. GitHub Actions / API docs / 中文 README 还没最终化。

MiMo 完成上述 8 点后，再提交“最终吹满版验收报告”。

