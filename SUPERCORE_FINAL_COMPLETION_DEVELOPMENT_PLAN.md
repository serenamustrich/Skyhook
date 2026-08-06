# Supercore 最终完成版开发计划

> 项目目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore`  
> Rust 核心目录：`/Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore`  
> 最终目标：完成独立 Rust-native 代理核心 Supercore 与玥球电梯 macOS App，使其达到可以长期稳定使用、主要能力不弱于 Mihomo、TUN/DNS 安全可靠、协议状态诚实可验证的正式版本。

## 当前执行进度（2026-08-06）

- Rust 全量串行验收 `cargo test --all --no-fail-fast -- --test-threads=1`：23 个测试套件合计 `571 passed / 0 failed / 4 ignored`；`RUST_TEST_THREADS=4 cargo test --lib` 并发 lib 回归也通过。ignored 项是需要外部服务、账号或系统 entitlement 的互操作测试（例如 MPTCP、官方 OpenVPN UDP、外部订阅兼容测试），不是失败。
- Rust 严格检查 `cargo clippy --all-targets --all-features -- -D warnings`：通过。
- Swift 全量测试：102 passed、0 failed；新增 TUN running/failed/disabled 状态等待回归。
- 真实订阅兼容性：已验证 provider-only Clash YAML，异步导入会解析 `proxy-providers` 并保存节点；用户此前提供的一个真实地址已通过直连下载、解析和临时 store 导入，且不保存到仓库。空响应会被拒绝，且不会覆盖已有缓存；另一个地址复核为 HTTP 200 但空 body，已明确归类为上游响应异常，不再误报为解析成功。
- 新增性能基准：路由 1000 条规则/10000 次决策约 1.54s，10000 条 Fake-IP 映射约 7.24ms，1000 节点订阅解析约 6.26ms，1000 节点测速任务调度约 93.8us，10000 次 SOCKS5 framing 约 319.6us。基线记录在 `Supercore/docs/performance-baseline.md`。
- 新增 1000 并发直连流稳定性测试，当前本机通过；新增 `Scripts/stability_24h.sh`，已完成 300 秒真实进程稳定性测试并记录 RSS（10 次采样，基线 12736KB、峰值 12736KB、增长 0KB），正式 86400 秒门尚未执行。
- TUN supervisor 已改为跟随 `/v1/config/reload` 动态创建/停止 TUN 子任务；`/v1/tun` 现在报告 `disabled/starting/running/failed`，App 启动等待真实 `running`，停止/退出等待 `disabled`。当前无免密 sudo，普通用户动态启用 TUN 得到真实 `Operation not permitted` 并退出，无残留进程；真实管理员 TUN 矩阵仍未宣称通过。
- macOS 用户 LaunchAgent、root LaunchDaemon、手动 TUN 启动/卸载脚本已补齐并通过 `bash -n`、可执行权限和配置检查。
- 新增 `Scripts/tun_macos_matrix.sh`，固化 TUN 动态启停、正常退出、强杀清理和路由/DNS/网卡快照；当前机器无免密 sudo，预检按约定返回 `77/SKIP`，未伪造管理员 TUN 通过。
- `dist/玥球电梯.dmg` 已重新生成并只读挂载验收：Finder 背景、Applications 链接、arm64 App、内嵌 Supercore、签名和核心 `--help` 均通过；DMG 构建依赖记录在 `Scripts/requirements-dmg.txt`。
- TUN cleanup 的系统代理检测已修正为只识别启用中的 loopback 代理；当前机器 dry-run 显示无 198.18 路由、系统代理 clean，针对关闭开关但保留 127.0.0.1 配置的回归测试通过。
- DNS outbound 新增本地 length-prefixed TCP 回归和 secure upstream 解析断言；release Supercore 通过自身 DNS listener 调用 `https://cloudflare-dns.com/dns-query` 实际返回 `NOERROR`，并通过 `Scripts/dot_external_e2e.sh` 使用 `8.8.8.8:853` + `dns.google` 完成真实 DoT 查询并返回 `NOERROR`。Cloudflare 的 `853` 端口在本机单独探测超时只属于该 resolver 的环境差异，不再阻塞 DoT 基础能力结论；其他第三方 DoT 变体仍未覆盖。
- 全量测试默认高并发执行时曾出现一次 Hysteria 本地 QUIC 测试长时间等待；随后带 120 秒 watchdog 的默认 `cargo test --all --no-fail-fast`、`RUST_TEST_THREADS=4` 并发和串行验收均通过，当前未能复现，稳定性脚本保留 watchdog。
- 最新 release App 已完成 Rust/Swift 构建、签名验证和启动退出冒烟验证，已包含本轮 Swift 订阅空响应保护。
- 尚未被本机环境完全覆盖的门：真实管理员 macOS TUN/LaunchDaemon 网络矩阵、MPTCP entitlement、官方 OpenVPN UDP、需要外部账号的 Tailscale、TrustTunnel H3，以及其他第三方 DoT/DoH 服务端变体；DoH 公共 resolver 与 DoT `8.8.8.8:853` 已有 Supercore listener 实际验证。

## 历史阶段记录（截至2026-07-17）

- 本轮完整 Rust 回归：263 passed、0 failed、1 ignored；ignored 项仅为需要外部订阅 URL 环境变量的兼容测试。
- VMess gRPC、H2、UDP 的 3 个 ignored 真实拨号测试已经修复并取消 ignore。
- VMess TCP、WS、gRPC、H2、UDP 真实拨号测试全部通过。
- Trojan 已新增 `network`、path、host、gRPC service 配置。
- Trojan TLS+TCP、UDP、WS、gRPC、H2、HTTPUpgrade 真实拨号测试全部通过。
- Trojan 自定义 headers、显式 ALPN、UDP over WS/gRPC、TLS/HTTP/gRPC trailer/timeout 错误路径已经验证。
- Shadowsocks 旧 AEAD 与 2022-blake3 三种方法的 TCP/UDP 双向真实拨号已经完成，simple-obfs HTTP/TLS 与 v2ray-plugin WebSocket 已实拨。
- Shadowsocks SIP023 TCP/UDP 多用户 EIH 已完成真实拨号。
- ShadowsocksR 的 origin、旧 verify/auth 系列、auth_aes128_md5/sha1、auth_chain_a-f、6 种 stream cipher、TCP/UDP、多用户参数、HTTP simple/post 与 tls1.2_ticket_auth 已完成真实拨号；定向测试 41 个通过。
- Snell v1-v5 TCP、独立响应 salt、HTTP/TLS obfs、v3-v5 UDP-over-TCP 与 v4/v5 connection reuse 已完成真实拨号；定向测试 18 个通过。
- Snell reuse 支持 10 条连接池、15 秒空闲淘汰、零帧半关闭、HTTP/TLS 混淆状态延续和陈旧连接自动重拨。
- Swift 全量测试：89 passed、0 failed。
- M0 的 Rust 与 Swift release build 均通过；Rust 完整 LTO release 构建耗时 15m39s。M4 reuse 改动后的 release 重验按统一门策略留到下一协议门。
- M1 控制面已进入 `IMPLEMENTED`：Swift 全部迁移到独立 `/v1` API，旧根路径与
  `/supercore/*` 兼容入口已删除，控制地址限制为 loopback，写请求使用启动级 Bearer
  Token，错误返回包含稳定 code/kind/trace id。
- 普通核心每次启动生成新的 256-bit Token；TUN LaunchDaemon 通过 root-only `0600`
  文件读取 Token，plist 不包含明文凭据。
- `supercore run` 已禁止启动时下载订阅；定时测速首次执行等待完整间隔，不再启动后
  1 秒触发全局测速。
- 当前 M1 回归：Rust lib 78 passed、Swift full 91 passed；完整 Rust integration 和
  release 门留到 M1 模块拆分完成后统一执行。
- M1 异步任务控制面已在提交 `ad66698` 落地：全量测速、代理组测速、订阅导入和
  更新全部订阅返回 HTTP `202` + `task_id`，支持状态查询、底层取消和 SSE task
  进度。
- TaskManager 终态默认保留 24 小时、最多 512 条，活跃任务不被清理；invalid probe
  URL 也会为每个 requested node 返回真实终态，不再遗漏未找到节点。
- 本批次回归：Rust lib 90 passed、Swift full 93 passed。统一 telemetry event bus
  已接入 task、测速进度、运行状态、订阅更新、连接、流量、日志和节点健康事件，
  高频连接/流量事件按 250ms 节流。
- Swift 已接入标准 SSE parser、`Last-Event-ID`、指数退避重连和快照恢复；正常时
  使用事件更新实时速率、增量日志、节点健康和 task 进度，断线时自动退回 1 秒流量/
  2 秒日志轮询。
- 未知节点规模的全量测速 task 等待预算已从约 1 秒修正为至少 60 秒，更新全部订阅
  的 task 等待上限提高到 5 分钟。本批次 Swift full 96 passed。
- M0 长任务控制面已完成：单订阅/全部订阅更新、Provider 更新、Geo 更新、Doctor
  深检和诊断导出均返回 HTTP `202` + `task_id`/`trace_id`，支持真实取消和进度事件。
- 订阅、Provider 和 Geo 下载使用直连 `no_proxy` 客户端，限制响应大小并隐藏可能
  含 Token 的完整 URL；Provider 失败保留缓存或上次规范化数据。
- 诊断导出默认脱敏，文件权限为 `0600` 且有界保留；控制服务退出会取消所有活跃
  task。M0 最终回归：Rust lib 92 passed、订阅 13 passed、Geo 3 passed、Swift full
  97 passed，全部 0 failed，因此 M0 状态为 `VERIFIED`。
- M1 API 模块化第一批已完成：鉴权、错误、schema、SSE、路由表和测速 handler 已从
  `api/mod.rs` 拆到独立模块；Rust lib 92 passed、0 failed。订阅、Provider、系统、
  规则和 telemetry handler 仍待迁移，因此 M1 保持 `IN_PROGRESS`。

## 0. 开发总原则

1. Supercore 是独立核心，不嵌入、不包装、不运行 Mihomo。
2. 可以参考公开协议规范、Mihomo 配置语义和行为，但实现、测试和 API 必须属于 Supercore。
3. 不允许只修改计划、README 或能力矩阵来宣称完成。
4. 一个协议只有在真实 parser、真实 outbound、mock server 或真实服务端测试全部完成后，才能标记 `full`。
5. App 的测速、订阅切换、启动代理不能偷偷修改 TUN、系统代理或 DNS。
6. 所有 TUN/DNS 操作必须有失败回滚、退出清理和崩溃恢复。
7. 不提交用户真实订阅 URL、节点密码、私钥、Keychain 数据、运行日志或本地 profile。
8. 每个阶段先完成代码，再补足有效测试，阶段末统一回归。
9. 禁止 `XCTAssertTrue(true)`、永真断言、数组长度冒充协议测试。
10. 文档中的能力状态必须由代码和测试证据生成或人工逐项核实。

## 1. 当前基线

### 1.1 已经具备

- Swift macOS 菜单栏 App。
- Rust-native Supercore。
- 多订阅导入、保存、切换、更新和本地缓存。
- 节点、代理组、国家分组。
- 未启动代理时启动轻量测速 core。
- 节点测速、组测速、失败分类和失败汇总。
- 上次节点保存、启动恢复和同地区备用节点。
- 系统代理开启、恢复和网络诊断。
- TUN LaunchDaemon 管理。
- 流量统计与按订阅持久化。
- 智能规则观察、推荐和持久化。
- 自定义域名/IP/App 规则。
- Doctor 协议能力分级。
- 中文 README 和协议能力矩阵。

### 1.2 最近一次验证结果

- Rust 全量串行测试 23 个测试套件合计 `571 passed / 0 failed / 4 ignored`；并发 lib 回归通过。
- Swift 全量验证 102 个通过。
- `cargo clippy --all-targets --all-features -- -D warnings` 已通过。
- 已有可重复的 Rust 性能基准套件，基线见 `Supercore/docs/performance-baseline.md`。
- 最新 release App 已完成构建、签名验证和启动退出冒烟验证，构建日期为 2026-08-06。
- 1000 并发直连流测试通过；稳定性脚本本轮完成 300 秒真实进程稳定性测试（10 次健康采样并记录 RSS），正式 86400 秒门仍未执行。
- DMG 只读挂载验收通过，DMG 文件为 `dist/玥球电梯.dmg`。
- 从 DMG 挂载副本复制到临时安装目录后，签名验证、实际启动和干净退出均通过。
- `Scripts/build_dmg.sh` 已支持显式 `NOTARIZE=1` 的 Developer ID notarization、staple
  和 validate；当前本机包仍为 ad-hoc 本地验收包，未在没有 Apple Developer 凭据的环境中
  冒充 notarized 发布包。

### 1.3 当前已经进入 Rust 全量回归的安全改动

以下改动已经写入工作区，并通过本轮 Rust 全量回归：

- `AppState.prepareDelayTestingRuntime(profileID:)`
  - 测速 runtime 强制 `tunEnabled=false`。
  - 已有 Swift 定向测试通过。
- `FakeIpStore.lookup_or_create`
  - 改为返回 `Option<Ipv4Addr>`。
  - fake-ip filter 命中时不再返回 `0.0.0.0`。
  - blacklist、whitelist、rule 模式已接入。
- DNS fallback
  - 开始从 macOS `scutil --dns` 和 `/etc/resolv.conf` 读取系统 DNS。
  - 不再固定只使用 `8.8.8.8`。
- TUN backend validation
  - `auto_route` 映射到 tun2proxy `setup`。
  - 当前后端不支持的选项改为明确报错。
- Rust inbound 定向测试与完整 `cargo test` 已通过。
- 完整 `swift test`、Rust release build 和 Swift release build 已通过。

后续开发必须从这里继续，不要重新覆盖或删除这些改动。

## 2. P0：完成当前安全修复并全量验收

### 2.1 测速 runtime 必须绝对关闭 TUN

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/Services/ConfigManager.swift`
- `Tests/YueqiuElevatorSupercoreTests/PlanBehaviorTests.swift`

要求：

- 未运行代理时手动测速：
  - `tun.enabled=false`
  - `tun.setup=false`
  - `dns.enabled=false`
  - `dns.hijack_udp_53=false`
  - 不使用 LaunchDaemon
  - 不修改系统代理
  - 不刷新订阅
- 即使用户设置里保存了 `tunEnabled=true` 或 Fake-IP，也不能带入测速 runtime。

验收：

- 读取生成的 runtime YAML 验证以上字段。
- 测速前后比较系统代理和路由表。
- 测速 core 退出后无残留进程。

### 2.2 完成 Fake-IP filter

涉及文件：

- `Supercore/src/inbound/fakeip.rs`
- `Supercore/src/inbound/dns.rs`
- `Supercore/src/config/mod.rs`

要求：

- Blacklist：
  - 匹配 filter 的域名走真实 DNS。
  - 未匹配域名才返回 Fake-IP。
- Whitelist：
  - 只有匹配 filter 的域名返回 Fake-IP。
  - 其他域名走真实 DNS。
- Rule：
  - 第一阶段可按 blacklist 兼容。
  - 最终必须结合路由规则决定是否使用 Fake-IP。
- 支持：
  - 精确域名。
  - `.example.com`
  - `*.example.com`
  - `+.example.com`
  - `*`
- filter 命中不能返回 `0.0.0.0`。
- fake-ip entry 过期后必须清理正向和反向映射。
- 地址池循环时不能覆盖仍有效 entry。

测试：

- blacklist 精确匹配。
- blacklist 子域名匹配。
- whitelist 匹配与不匹配。
- rule 模式。
- TTL 过期。
- reverse lookup。
- 地址池循环。

### 2.3 完成系统 DNS fallback

涉及文件：

- `Supercore/src/inbound/dns.rs`
- `Supercore/src/core/mod.rs`
- `Supercore/src/config/mod.rs`

要求：

1. macOS 优先从 `scutil --dns` 读取 resolver。
2. 其他 Unix 可读取 `/etc/resolv.conf`。
3. 回退顺序：
   - 当前系统 resolver。
   - `direct_nameserver`。
   - `default_nameserver`。
   - 普通 `nameserver` 中可直连的 IP resolver。
   - 最后才使用配置中的 `dns.server`。
4. 排除当前核心自己的 DNS listen 地址，防止递归。
5. 每个 resolver 独立短 timeout。
6. 支持 IPv4 和 IPv6 resolver。
7. UDP 失败后可以尝试 TCP DNS。
8. 日志显示实际使用了哪个 resolver，但不得打印用户敏感数据。

测试：

- scutil 输出解析。
- resolv.conf 解析。
- IPv4/IPv6。
- 多 resolver，第一个失败、第二个成功。
- 排除自身 listen。
- UDP 失败后 TCP 成功。
- 所有 resolver 失败时返回明确错误。

### 2.4 修正 DNS 配置默认值

当前 Rust 默认仍有：

- `dns.server=8.8.8.8:53`
- `tun.dns_addr=8.8.8.8`

要求：

- App 生成配置继续使用用户选择值，默认可保持 `223.5.5.5`。
- Rust 默认配置不要把“系统 DNS”实现成固定外部 DNS。
- Direct 模式应优先系统 resolver。
- Over-TCP 模式才使用指定 DNS TCP upstream。
- Virtual 模式才启用 fake-ip。

## 3. P0：TUN 生命周期和网络安全

### 3.1 明确当前 tun2proxy 后端边界

涉及文件：

- `Supercore/src/inbound/tun.rs`
- `Supercore/src/config/mod.rs`
- `Supercore/docs/tun-capabilities.md`（新增）

当前 tun2proxy 0.8.1 实际支持：

- TUN 创建。
- setup 路由。
- MTU。
- DNS strategy。
- DNS addr。
- virtual DNS pool。
- bypass CIDR。
- IPv6 开关。
- TCP/UDP timeout。
- max sessions。

当前配置模型中存在但后端没有直接支持的字段：

- `stack=gvisor/mixed`
- `auto_detect_interface`
- `strict_route`
- `auto_redirect`
- GSO
- 自定义 inet address/route address
- UID/package/process include/exclude

要求：

- 未实现的字段不能只写日志。
- 配置启用未支持字段时必须：
  - 明确返回配置错误；或
  - 真正实现。
- README 和 UI 不展示没有生效的高级开关。

### 3.2 TUN 启动事务

启动顺序：

1. 保存当前系统代理快照。
2. 保存默认路由、DNS 和活跃网卡快照。
3. 生成 runtime。
4. 校验 runtime。
5. 启动或热重载 daemon。
6. 等待 TUN device 出现。
7. 等待本地 mixed/control port。
8. 验证 DNS。
9. 验证直连和代理链路。
10. 最后标记 App 为运行中。

任一步失败：

- 停止新 core。
- TUN off。
- 恢复系统代理。
- 恢复路由/DNS。
- 输出明确错误。

### 3.3 TUN 停止事务

停止顺序：

1. 停止后台测速和自动切换。
2. 保存流量快照。
3. 将 daemon runtime 改为 `tun.enabled=false`。
4. 等待热重载完成。
5. 恢复系统代理。
6. 检查 Fake-IP 路由。
7. 检查默认路由。
8. 更新 UI 状态。

### 3.4 App 退出和崩溃恢复

要求：

- `applicationShouldTerminate` 返回 `.terminateLater`。
- 等待 `prepareForQuit()` 完成后才退出。
- 强杀 App 后 daemon 不得继续保持 TUN on。
- 下次启动自动检测：
  - 本 App 系统代理残留。
  - TUN daemon 残留。
  - 198.18.0.0/15 路由残留。
  - core 进程残留。
- 提供一键恢复网络。

### 3.5 TUN macOS 真实验收矩阵

执行入口：`Scripts/tun_macos_matrix.sh --with-tun --root`。脚本会验证动态启停、
正常退出、强杀 core 清理，并保存路由、DNS、系统代理和网卡快照；Wi-Fi/有线切换、
DHCP、休眠唤醒、VPN 共存和 IPv6-only/双栈仍需在对应真实网络环境补充人工记录。

必须人工/自动化验证：

- Wi-Fi。
- 有线网络。
- Wi-Fi 切换。
- DHCP 地址变化。
- 休眠/唤醒。
- VPN 共存。
- App 正常退出。
- App 强杀。
- core 崩溃。
- LaunchDaemon 重启。
- 无管理员权限。
- DNS 服务器不可达。
- IPv6-only / 双栈网络。

## 4. P0：协议文档立即纠偏（历史基线已处理）

涉及文件：

- `Supercore/docs/protocol-matrix.md`
- `Supercore/README.md`
- `README.zh-CN.md`
- `README.md`

本节记录的早期审计问题已经在当前工作区处理，不能再作为当前能力结论：

- Trojan 已有 WS/gRPC/H2/HTTPUpgrade transport 实现和真实 mock 拨号覆盖。
- VMess gRPC/H2/UDP 真实拨号测试已取消 ignored 并通过。
- Shadowsocks 2022、SIP023、plugin/UoT 路径已有真实拨号覆盖。

后续任何协议状态都必须继续以 `docs/protocol-matrix.md`、代码和当前测试证据为准；外部服务端/账号/entitlement 门单独列为未执行环境门。

当前矩阵已经按适用的 TCP/UDP 路径和本地/mock/官方证据重新核对：已实现协议
均按实际能力标记为 `full`，协议自身不适用的 UDP、平台限制和外部账号/entitlement
限制写在对应备注中。当前不再保留“先标 partial”或“parse-only”的过期建议；新的
协议状态必须先有对应代码和测试证据，再同步矩阵与 README。

## 5. P1：测速能力最终完成

### 5.1 核心 probe 正确性

要求：

- 每个 requested name 必须有且只有一个结果。
- 未进入 job 队列的节点不能标 timeout。
- 节点不存在为 `outbound_not_found`。
- 协议不可用为 `protocol_unsupported`。
- DNS、TLS、HTTP status、empty response 分开。
- 延迟从开始拨号到收到健康 HTTP status。
- 500ms 及以上在 UI 中不可用。
- 核心 timeout 与 App request timeout 分离。

### 5.2 并发调度

要求：

- 采用固定 worker 数或 semaphore。
- 不一次 spawn 数千任务。
- 支持取消。
- 测速结束等待所有 requested nodes 完成。
- 后台测速优先级低于真实代理流量。
- 自动择优不能阻塞代理连接。

### 5.3 与 Sparkle/Mihomo 对比

已有：

- `Scripts/collect_probe_parity.sh`
- `Scripts/compare_probe_results.py`
- `Scripts/export_mihomo_probe.py`

最终验收：

- 同一订阅。
- 同一 URL。
- 同一 500ms timeout。
- 同一测试时间段。
- 对比可用率、P50、P90。
- 结果差异必须能按协议和失败原因解释。
- 不保存真实订阅 URL。

### 5.4 App 测速 UX

显示：

- 准备本地缓存。
- 启动测速 core。
- 已提交节点数。
- 已完成数量。
- 可用。
- 超时。
- 协议不支持。
- 核心无此节点。
- 其他错误。

支持：

- 测速当前组。
- 测速所有节点。
- 包含历史超时节点重新测速。
- 只显示可用节点。
- 取消测速。

## 6. P1：协议真实拨号最终补齐

每个协议完成条件：

1. Clash YAML 解析。
2. URI 解析。
3. Outbound config validation。
4. TCP mock server。
5. UDP mock server（协议支持时）。
6. transport mock server。
7. probe 测试。
8. 错误分类。
9. capability snapshot。
10. 文档同步。

### 6.1 Shadowsocks

- 3 个 AEAD TCP 已有真实 mock。
- 补 3 个 2022-blake3 真实 mock 拨号。
- 补 2022 UDP。
- 补 simple-obfs HTTP/TLS E2E。
- 补 v2ray-plugin WebSocket E2E。
- plugin 开启时 UDP 能力必须明确。

### 6.2 ShadowsocksR

- 逐个验证 cipher。
- 逐个验证 protocol。
- 逐个验证 obfs。
- `protocol_param` 必须真正使用。
- 补 UDP 或明确 partial。
- 不能只验证 build 不 panic。

### 6.3 Trojan

当前只支持 TLS+TCP/UDP。

需要新增 config 字段：

- `network`
- `ws_path`
- `ws_host`
- `grpc_service_name`
- H2 path/host

完成：

- TCP。
- UDP。
- WebSocket。
- gRPC。
- H2。
- HTTPUpgrade（若目标与 Mihomo 对齐）。

### 6.4 VMess

必须解决 3 个 ignored test：

- `vmess_grpc_transport_real_dial`
- `vmess_h2_transport_real_dial`
- `vmess_udp_real_dial`

重点：

- H2 flow-control。
- request body 首包时序。
- gRPC framing。
- UDP session destination 模型。
- per-destination session 与 multiplex session 选择。

三个测试取消 `#[ignore]` 后才能标 full。

### 6.5 VLESS

- TLS TCP。
- WS。
- gRPC。
- H2。
- HTTPUpgrade。
- UDP。
- Reality 完整握手。
- Vision flow。
- Reality fingerprint。
- short ID。
- spiderX。
- 不支持组合必须明确拒绝。

### 6.6 Hysteria2

- 建本地 QUIC/H3 mock server。
- TCP tunnel E2E。
- UDP datagram E2E。
- fragmentation/reassembly。
- Salamander。
- Gecko。
- congestion control。
- session pool。
- 丢包、乱序、重复包。

### 6.7 TUIC

- 本地 QUIC mock server。
- v5 authentication。
- TCP connect。
- native UDP。
- QUIC stream UDP。
- fragmentation。
- session pool。
- congestion control。

### 6.8 Snell

- v1/v2/v3 差异。
- method。
- obfs。
- UDP。
- 不能用 Shadowsocks framing 近似替代协议。

### 6.9 WireGuard

- private/public/preshared key。
- allowed_ips。
- reserved。
- MTU。
- IPv4。
- IPv6。
- DNS destination。
- keepalive。
- rekey。
- counter rollover。
- TCP 流包装正确性。
- UDP 数据报。

### 6.10 AnyTLS

- 真实认证。
- multiplex。
- padding。
- TCP stream。
- UDP（规范支持时）。
- 服务端拒绝。
- TLS 证书错误。

### 6.11 ShadowTLS

- v3 完整握手。
- 与底层代理组合。
- standalone 行为。
- UDP 能力明确。
- SNI/证书。

### 6.12 Naive

- Chromium/NaiveProxy 行为对齐。
- HTTP/2 CONNECT。
- HTTP/1.1 CONNECT 兼容路径已实现；UDP 对 NaiveProxy 不适用。
- authentication。
- padding。
- TLS fingerprint 边界。

### 6.13 Hysteria v1

- QUIC transport。
- auth。
- bandwidth。
- obfs。
- TCP。
- UDP。
- macOS `faketcp` 依赖平台 packet backend，已作为明确的平台边界拒绝；普通 QUIC
  TCP/UDP 路径保持 full。

### 6.14 Mieru / Juicity / MASQUE / OpenVPN

Mieru、Juicity、MASQUE、OpenVPN 当前均已有 native outbound 和对应本地/mock
或官方互操作证据，矩阵按适用路径标记为 full；OpenVPN 的官方 UDP、外部服务端
和平台 packet backend 仍按环境门或平台边界单独记录，不能用 parse-only 掩盖。

## 7. P1：订阅和 provider 最终完成

### 7.1 下载策略

- 用户手动导入和后台更新默认优先直连。
- 直连失败后是否通过代理重试必须由用户设置决定。
- 支持 User-Agent。
- 支持自定义 header。
- 支持 redirect。
- 支持 gzip/br。
- 支持 ETag/Last-Modified。
- 支持 timeout/retry/backoff。

### 7.2 本地缓存

每个订阅保存：

- 原始订阅文本。
- 解析节点。
- 代理组。
- provider payload。
- 规则。
- rule-provider。
- subscription-userinfo。
- 到期日期。
- 更新时间。
- last selected node。
- selected group nodes。
- 流量统计。

切换订阅：

- 只切本地数据。
- 不下载。
- 不测速。
- 不重启不必要的服务。

### 7.3 Provider

- provider 本地缓存。
- provider 更新失败回退旧缓存。
- provider 名特殊字符。
- provider 嵌套组。
- include-all。
- filter。
- exclude-filter。
- health-check。
- override。

### 7.4 真实订阅兼容测试

`real_subscription_compat.rs`：

- 保持环境变量输入。
- 测试结束不保存 URL。
- 输出只显示域名掩码。
- 对每个 unsupported node 输出协议和原因。
- 用户提供的两个真实订阅必须人工验证，但不得写进仓库。

## 8. P1：规则、Geo 和智能学习

### 8.1 规则类型

最终支持：

- DOMAIN。
- DOMAIN-SUFFIX。
- DOMAIN-KEYWORD。
- DOMAIN-REGEX。
- IP-CIDR。
- IP-CIDR6。
- SRC-IP-CIDR。
- DST-PORT。
- SRC-PORT。
- IN-PORT。
- NETWORK。
- PROCESS-NAME。
- PROCESS-PATH。
- APP-BUNDLE。
- RULE-SET。
- GEOSITE。
- GEOIP。
- MATCH/FINAL。

### 8.2 优先级

固定：

1. 用户手动规则。
2. 用户启用的智能规则。
3. 订阅规则。
4. 智能观察但未启用的规则不参与路由。
5. fallback。

### 8.3 智能规则

- 记录 domain/IP/app。
- 后台做直连探测。
- 区分 DNS 可达和目标端口可达。
- 记录样本次数、成功率和最近时间。
- 推荐直连。
- 推荐代理。
- 单条启用。
- 批量启用。
- 可撤销。
- 可清除学习数据。
- 避免频繁抖动。
- 对 CDN、动态 IP 和 QUIC 目标谨慎学习。

### 8.4 App 级路由

macOS TUN 下需要可靠获取：

- PID。
- bundle ID。
- executable path。
- process name。

不能只依赖 mixed proxy 客户端没有提供的元数据。

## 9. P1：流量、日志和可观测性

### 9.1 流量

- 实时上传速率。
- 实时下载速率。
- runtime 总量。
- 按订阅生命周期累计。
- App 重启不丢失。
- core 崩溃后不重复累计。
- profile 切换不串数据。

### 9.2 连接表

- 目标。
- app。
- 规则。
- 实际 outbound。
- 代理组选择。
- 上传/下载。
- 开始时间。
- 持续时间。
- 关闭原因。

### 9.3 日志

- 最新在上。
- Tab：
  - 全部。
  - 代理。
  - 直连。
  - 规则。
  - DNS。
  - TUN。
  - 错误。
  - 系统。
- URL token、Authorization、密码、UUID、私钥脱敏。
- 日志大小限制和轮转。

## 10. P2：性能优化

### 10.1 建立 benchmark

新增：

- `Supercore/benches/routing.rs`
- `Supercore/benches/probe_scheduler.rs`
- `Supercore/benches/fakeip.rs`
- `Supercore/benches/protocol_framing.rs`
- `Supercore/benches/subscription_parse.rs`

指标：

- 路由规则 1K/10K/100K。
- 节点 100/1K/10K。
- Probe 并发 10/50/100/256。
- Fake-IP 10K/100K entry。
- 订阅 1MB/10MB。
- TCP relay throughput。
- UDP packets/sec。

### 10.2 性能目标

- App 空闲 CPU 接近 0。
- 后台测速不能明显影响当前代理延迟。
- 1000 节点切换订阅不重新下载。
- 1000 节点列表滚动无明显卡顿。
- core 稳态内存可解释且无持续增长。
- 24 小时长连接无泄漏。
- 1000 并发连接不崩溃。

### 10.3 Profiling

- cargo flamegraph。
- Instruments Time Profiler。
- Allocations。
- Leaks。
- SwiftUI update 检查。
- Tokio task 数量监控。

### 10.4 编译和代码质量

- 修完 `cargo clippy --all-targets --all-features -- -D warnings`。
- 只格式化修改过的 Rust 文件，避免无关大 diff。
- 拆分 `outbound/mod.rs`：
  - shadowsocks.rs
  - ssr.rs
  - trojan.rs
  - vmess.rs
  - vless.rs
  - hysteria2.rs
  - tuic.rs
  - wireguard.rs
  - transports/
- 减少重复 TLS、WS、H2、gRPC 代码。

## 11. P2：App UI 最终版

### 11.1 节点页

- 当前订阅。
- 当前代理组。
- 当前实际节点。
- 当前节点延迟。
- 国家网格。
- 横向/纵向滚动完整。
- 搜索。
- 协议筛选。
- 国家筛选。
- 延迟排序。
- 只显示可用。
- 测速当前组。
- 测速所有节点。
- 取消测速。

延迟颜色：

- `<50ms` 绿色。
- `50-150ms` 蓝色。
- `150-499ms` 红色。
- `>=500ms` 超时。

### 11.2 订阅页

- 多订阅选择。
- 添加。
- 删除。
- 更新所有。
- 当前使用状态。
- 节点数。
- unsupported 数。
- 上传/下载/总流量。
- 套餐使用量。
- 到期日期。
- 上次更新时间。
- 更新进度。

### 11.3 智能规则页

- 统计区。
- 代理规则但直连可用比例。
- 推荐直连。
- 推荐代理。
- 单条启用。
- 批量启用。
- 搜索和筛选。
- 撤销和删除。

### 11.4 设置页

- 系统代理模式。
- TUN 虚拟网卡模式。
- TUN DNS 处理方式。
- Fake-IP 高级风险确认。
- 测速 URL。
- timeout。
- 并发。
- 后台测速间隔。
- 后台订阅更新间隔。
- 一键恢复网络。
- Doctor。

## 12. P2：安全

- Control API 仅监听 loopback。
- 增加随机 API token。
- App 启动 core 时注入 token。
- 所有写操作校验 token。
- Keychain 存订阅 URL/token。
- 文件权限限制到当前用户。
- TUN daemon runtime 不保存订阅 URL。
- 日志脱敏。
- DMG 不包含用户数据。
- release 不包含测试订阅。

## 13. P2：发布、DMG 和 GitHub

### 13.1 README

- 只描述真实功能。
- 中文、英文一致。
- 不写开发过程。
- 不写未验证能力。
- 协议矩阵链接明确。

### 13.2 GitHub

- 提交前更新 README。
- 检查敏感数据。
- tag。
- release notes。
- DMG 上传 Release。
- README 放下载链接。

### 13.3 macOS 发布

- Release Swift build。
- Release Rust arm64 build。
- App bundle。
- 嵌入 Supercore。
- codesign。
- notarization。
- staple。
- DMG 使用已经确认的背景和布局。
- 安装、覆盖安装、卸载测试。

## 14. 最终测试矩阵

### 14.1 每次提交

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo test

cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test
swift build
```

### 14.2 阶段验收

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo build --release
cargo clippy --all-targets --all-features -- -D warnings

cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift build -c release
```

### 14.3 发布验收

- 安装 DMG。
- 新用户首次启动。
- 导入订阅。
- 未启代理测速。
- 选择节点。
- 启动系统代理。
- 启动 TUN。
- 浏览网页。
- UDP/QUIC。
- 流量统计。
- 切换订阅。
- 更新所有订阅。
- 退出 App。
- 检查网络恢复。
- 强杀 App 后恢复。
- 休眠唤醒。

## 15. 最终完成定义

只有以下全部满足，才能说“开发完成”：

- P0 全部完成。
- 无已知会导致断网的 TUN/DNS bug。
- 测速不会启 TUN。
- Fake-IP filter 不返回 `0.0.0.0`。
- 系统 DNS fallback 不固定依赖单一公共 DNS。
- 所有 full 协议有真实拨号测试。
- 必需本地协议测试不得保留无解释的 ignored；需要外部服务、账号或 entitlement 的
  测试必须在对应环境执行，或明确标记为未执行环境门并保留失败分类。
- 文档与代码一致。
- Rust/Swift 测试通过。
- clippy `-D warnings` 通过。
- release 构建通过。
- 真实订阅通过。
- TUN macOS E2E 通过。
- 24 小时稳定性测试通过。
- 性能基准建立。
- DMG 安装运行通过。
- 仓库无用户敏感数据。

## 16. 当前收口顺序

协议、订阅、规则、流量、日志、性能基线、App UI 和 DMG 已进入当前工作区；后续
不得重新执行已经有证据的历史开发步骤。剩余验收严格按下面顺序收口：

1. 在有管理员授权的 macOS 上执行 `Scripts/tun_macos_matrix.sh --with-tun --root`，
   保存动态启停、正常退出和强杀清理证据。
2. 在 Wi-Fi、有线、DHCP 变化、休眠唤醒、第三方 VPN、IPv6-only/双栈环境补齐
   TUN 网络矩阵，并确认 App 的网络恢复状态与系统实际状态一致。
3. 为 MPTCP entitlement、官方 OpenVPN UDP、外部 Tailscale 和 TrustTunnel H3 提供
   目标环境凭据后，运行对应 ignored/外部互操作测试；DoT 基础外部 resolver 已由
   `Scripts/dot_external_e2e.sh` 验证，但其他第三方 DoT/DoH 变体仍必须保留为环境门。
4. 运行 `Scripts/stability_24h.sh 86400`，保留完整日志、采样数、退出码和无残留
   进程证据；短时冒烟不能替代 24 小时门。
5. 重新执行 Rust/Swift 全量回归、严格 Clippy、敏感数据扫描、release 构建、DMG
   只读挂载和 App 启停验收。
6. 对照第 15 节逐项审计；只有全部证据齐全后，才可以声明最终完成。

## 17. 禁止事项

- 不要再次写“全部完成”但保留 ignored test。
- 不要把 parse-only 写成 full。
- 不要用配置解析测试证明真实拨号。
- 不要用 `result.is_ok() || result.is_err()` 作为有效测试。
- 不要在测速时启 TUN。
- 不要把系统 DNS 写死为 `8.8.8.8`。
- 不要让 Fake-IP filter 返回 `0.0.0.0`。
- 不要静默忽略 TUN 配置字段。
- 不要启动代理时刷新订阅或全局测速。
- 不要把真实订阅 URL 写入代码、测试、README、日志或 Release。
- 不要覆盖用户已有本地数据。
