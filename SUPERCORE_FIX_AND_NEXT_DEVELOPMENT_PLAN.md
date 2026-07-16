# Supercore 修复与后续开发计划

> 目标：先修正 mimo 当前实现中的虚假完成、文档过度宣称和薄弱测试，再继续补齐 Supercore 的真实能力。  
> 原则：每一项完成必须有代码实现、有效测试、可运行验证和文档同步，不能只改计划打勾。

## 0. 当前结论

当前代码可以通过 `cargo test` 和 `swift test`，说明工程基本可编译、已有功能没有明显断裂。但还不能宣称已经达到 Mihomo 同等能力，主要原因：

- 协议矩阵文档存在过度宣称，部分协议写成 full，但代码仍是 partial 或 unsupported。
- 新增测试里存在 `assert true`、硬编码数组长度、永真表达式等无效测试。
- 代理组测速 API 仍有路径编码、嵌套组展开、特殊节点过滤等风险。
- `supercore doctor` 的协议统计错误，把节点名当成协议类型统计。
- WireGuard、Snell、SSR、Hysteria v1、ShadowTLS、AnyTLS、Naive 等协议仍需要更真实的握手、传输、UDP 或兼容性验证。
- TUN/DNS 已有安全改动，但还需要真实退出清理、异常恢复、系统网络状态验证脚本。

## 1. P0：先修复当前错误和虚假完成

### 1.1 重写协议矩阵，禁止过度宣称

涉及文件：

- `Supercore/docs/protocol-matrix.md`
- `README.md`
- `README.zh-CN.md`

要做：

1. 按真实代码能力重新标记每个协议状态。
2. 状态只能使用：
   - `full`: 已解析、已拨号、已通过本地 mock 握手/传输测试。
   - `partial`: 可解析或可拨号，但缺少关键参数、UDP、传输层、插件或真实测试。
   - `parse-only`: 只保存配置，不能真实连接。
   - `unsupported`: 不可用。
3. 对每个 partial 协议写明缺什么。
4. 删除“状态：全部完成”这种总括性结论，改成“当前支持矩阵”。
5. README 只描述真实功能，不写开发过程，不写计划，不吹没有验证过的能力。

完成标准：

- 文档中不能再出现同一协议前面写 full、后面又写 partial 的矛盾。
- 文档每个 `full` 协议都能在测试中找到对应 mock 或单元测试。
- README 不出现 “Mihomo parity 已完成” 这种未验证表述。

### 1.2 删除或替换无效测试

涉及文件：

- `Tests/YueqiuElevatorSupercoreTests/PlanBehaviorTests.swift`
- `Supercore/tests/plan_behavior.rs`
- 必要时新增：
  - `Supercore/tests/protocol_capability.rs`
  - `Supercore/tests/probe_behavior.rs`
  - `Supercore/tests/tun_safety.rs`

必须删除或替换的测试类型：

- `XCTAssertTrue(true, "...")`
- `assert!(x.is_empty() || !x.is_empty())`
- 只构造数组再判断长度的“协议支持测试”
- 只判断路径非 nil 的“缓存测试”
- 只判断 AppState 初始状态的“启动使用上次节点测试”

替换方式：

1. 协议能力测试必须调用真实 parser、config builder、outbound capability 或 mock connect。
2. 测速测试必须验证：
   - 每个 requested name 都有结果。
   - 不存在的节点返回 `outbound_not_found`。
   - 不支持协议返回 `protocol_unsupported`。
   - timeout 结果与 `timeout_ms` 一致。
3. 缓存测试必须真实写入 provider cache，再切换 profile，确认不重新下载也能显示节点。
4. 启动测试必须确认启动代理不触发订阅刷新、不触发全局测速、直接使用上次节点。

完成标准：

- 仓库内搜索不到 `XCTAssertTrue(true`。
- 仓库内搜索不到 `is_empty() || !is_empty()`。
- 协议相关测试不再只是数组长度。
- `cargo test` 和 `swift test` 通过。

### 1.3 修复 `supercore doctor` 统计错误

涉及文件：

- `Supercore/src/main.rs`

问题：

当前 Doctor 使用 `outbound.name()` 统计类型，导致每个节点名都被当成一种协议。

要做：

1. 新增或复用 `outbound_config_kind(&OutboundConfig)`。
2. Doctor 输出按协议统计：
   - direct
   - reject
   - ss
   - ssr
   - trojan
   - vmess
   - vless
   - hysteria2
   - tuic
   - wireguard
   - snell
   - anytls
   - shadowtls
   - naive
   - unknown
3. Doctor 同时输出：
   - total outbounds
   - supported count
   - partial count
   - unsupported count
   - rule count
   - active subscription
   - provider cache 是否存在

完成标准：

- 用包含多个同协议节点的 fixture 运行 doctor，输出协议数量正确。
- 新增 Rust test 覆盖 doctor 的统计函数。

### 1.4 修复代理组测速 API 的组名编码和嵌套展开

涉及文件：

- `Sources/YueqiuElevatorSupercore/Services/SupercoreAPIClient.swift`
- `Supercore/src/api/mod.rs`
- `Supercore/src/core/mod.rs`
- `Sources/YueqiuElevatorSupercore/App/AppState.swift`

问题：

- Swift 端把 group name 直接拼到 path，组名含 `/`、空格、emoji、中文特殊字符可能请求失败。
- Core API 只取当前 group 的 members，没有递归展开嵌套 group。
- `DIRECT`、`REJECT`、group 名称可能混进待测节点。

推荐改法：

1. 不再使用 `POST /supercore/probe/groups/{name}` 作为主要接口。
2. 新增更安全接口：

```http
POST /supercore/probe/group
Content-Type: application/json

{
  "group": "节点选择",
  "url": "http://www.gstatic.com/generate_204",
  "timeout_ms": 500,
  "concurrency": 50
}
```

3. Core 内递归展开 group，过滤：
   - `DIRECT`
   - `REJECT`
   - 空名称
   - 已访问过的 group，避免循环引用
4. 旧接口可保留兼容，但 App 改用 body 版本。

完成标准：

- 组名包含 `/`、空格、中文、emoji 时能正常测速。
- 嵌套代理组只测速最终具体节点。
- 返回结果里没有 group 名、DIRECT、REJECT。

## 2. P0：测速能力重新对齐 Sparkle/Mihomo

### 2.1 建立真实测速基准

涉及文件：

- `Supercore/src/core/mod.rs`
- `Supercore/src/outbound/mod.rs`
- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/Models/CoreModels.swift`

要做：

1. 默认测速 URL 保持：

```text
http://www.gstatic.com/generate_204
```

2. 默认 timeout 保持 500ms。
3. 每个节点必须真实发起 outbound connect，再请求 generate_204。
4. 不能因为任务队列、HTTP request timeout 或 API timeout 提前结束。
5. 结果分类必须清晰：
   - `success`
   - `timeout`
   - `outbound_not_found`
   - `protocol_unsupported`
   - `dial_error`
   - `dns_error`
   - `tls_error`
   - `http_status`
   - `empty_response`
6. UI 显示可用率时，不要把 `outbound_not_found` 算成网络超时。

完成标准：

- 100 个节点、并发 50、timeout 500ms，总耗时应接近两批 timeout 加少量 buffer，不应瞬间结束。
- 所有 requested nodes 都有返回结果。
- 对于不可测原因，UI 能显示分类数量。

### 2.2 App 端测速流程优化

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift`
- `Sources/YueqiuElevatorSupercore/Services/SupercoreAPIClient.swift`

要做：

1. 用户手动测速时，如果 core 没启动，启动一个轻量 delay-testing core。
2. delay-testing core：
   - 不开启 TUN。
   - 不修改系统代理。
   - 不刷新订阅。
   - 只加载本地缓存订阅。
3. 测速完成后，如果用户没有启动代理，不要偷偷开启代理。
4. 节点页增加测速状态：
   - 准备 core
   - 加载本地节点
   - 测速中 x/y
   - 汇总结果
5. 可用率统计拆开：
   - 可用
   - 超时
   - 协议不支持
   - 核心无此节点
   - 其他错误

完成标准：

- 未启动代理时可以测速。
- 测速不会改变系统代理/TUN 状态。
- 测速不会刷新订阅。
- 测速结果不会大量误标超时。

### 2.3 与 Sparkle 对比验证脚本

新增文件：

- `Scripts/probe_compare_notes.md`
- `Supercore/tests/probe_behavior.rs`

要做：

1. 写一个本地说明文档，明确如何使用同一订阅、同一 URL、同一 timeout 与 Sparkle 对比。
2. 记录对比字段：
   - 节点总数
   - 可用节点数
   - 超时数
   - 协议不支持数
   - 平均延迟
   - P50/P90 延迟
3. 先不要写死真实订阅 URL。

完成标准：

- 不提交用户订阅链接。
- 对比流程可复现。

## 3. P1：订阅、本地缓存和启动速度

### 3.1 切换订阅必须只切本地数据

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/Services/SubscriptionManager.swift`
- `Sources/YueqiuElevatorSupercore/Services/ConfigManager.swift`
- `Supercore/src/subscription_store.rs`

要做：

1. 导入订阅后保存：
   - 原始 URL，只进 Keychain 或用户本地私有目录。
   - 原始订阅文本。
   - 解析后的节点列表。
   - 代理组。
   - 规则。
   - provider nodes。
   - userinfo 流量/到期信息。
2. 切换订阅时只读取本地缓存，不下载。
3. 只有用户点击“更新所有订阅”或后台定时更新时才下载。
4. 启动代理时不刷新订阅、不测速。

完成标准：

- 已下载过的订阅切换耗时应小于 300ms 到 800ms，取决于节点数量。
- 启动代理日志中不能再出现“同步订阅到 supercore”这种重活。
- 首次没有缓存时才提示需要更新订阅。

### 3.2 启动代理使用上次节点

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/Services/ConfigManager.swift`
- `Sources/YueqiuElevatorSupercore/Models/Profile.swift`

要做：

1. 保存每个订阅的 last selected node。
2. 启动代理时：
   - 优先使用 last selected node。
   - 如果节点存在且协议支持，直接启动。
   - 如果节点不存在，才切同国家可用节点。
   - 如果同国家也没有，再提示用户测速。
3. 不要启动时全局测速。

完成标准：

- 启动代理路径无网络下载。
- 启动代理路径无全局测速。
- UI 明确显示当前使用节点和延迟。

## 4. P1：TUN/DNS 安全继续加固

### 4.1 TUN 模式文案和风险隔离

涉及文件：

- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift`
- `Sources/YueqiuElevatorSupercore/Models/Profile.swift`
- `Sources/YueqiuElevatorSupercore/Services/ConfigManager.swift`

要做：

1. UI 只把 TUN 叫做“虚拟网卡模式”。
2. DNS 选项单独解释：
   - 系统 DNS：最安全，不接管 DNS。
   - DNS over TCP：核心通过 TCP 查询 DNS，避免 UDP DNS 劫持问题。
   - Fake-IP 虚拟 DNS：高级模式，会生成虚拟 IP，需要更严格清理。
3. 默认保持系统 DNS。
4. Fake-IP 模式必须二次确认。

完成标准：

- 用户不会再把虚拟网卡和虚拟 DNS 混成一个概念。
- 默认配置不会导致退出后断网。

### 4.2 一键恢复网络真实可用

涉及文件：

- `Sources/YueqiuElevatorSupercore/App/AppState.swift`
- `Sources/YueqiuElevatorSupercore/Services/SystemProxyManager.swift`
- `Sources/YueqiuElevatorSupercore/Services/TunLaunchDaemonManager.swift`
- `Supercore/src/main.rs`

要做：

1. 一键恢复执行：
   - 关闭系统 HTTP/HTTPS/SOCKS 代理。
   - 若 daemon 存在，热重载 `tun.enabled=false`。
   - 停止 App 自己启动的 core。
   - 检查 `198.18.0.0/15` 相关残留路由。
2. 操作前后记录诊断快照。
3. 没权限时明确提示需要管理员授权。

完成标准：

- App 强退后重新打开，能恢复系统代理。
- 恢复动作不删除订阅、不删除配置。
- 恢复后用户网络可正常直连。

## 5. P1：协议真实拨号补齐

### 5.1 先建立协议能力分级测试

新增或修改：

- `Supercore/tests/protocol_capability.rs`
- `Supercore/tests/config_and_runtime.rs`
- `Supercore/docs/protocol-matrix.md`

每个协议至少要有：

1. YAML 解析测试。
2. URI 解析测试。
3. Capability 测试。
4. 本地 mock handshake 或 mock server 测试。
5. 如果支持 UDP，必须有 UDP relay 测试。

完成标准：

- 文档里每个 full 协议都能对应到测试。
- partial 协议必须列出缺失项。

### 5.2 协议补齐顺序

按用户实际订阅常见程度，按这个顺序做：

1. Shadowsocks
   - 补全 2022-blake3 的真实验证。
   - 验证 simple-obfs。
   - 验证 v2ray-plugin websocket。
   - 验证 UDP。
2. Trojan
   - 验证 TCP。
   - 验证 WS/gRPC/H2 transport。
   - 验证 UDP over associate。
3. VMess
   - 验证 AEAD。
   - 验证 WS/gRPC/H2/httpupgrade。
   - 验证 UDP。
4. VLESS
   - 验证 TLS。
   - 验证 Reality。
   - 验证 Vision flow。
   - 验证 WS/gRPC/H2/httpupgrade。
5. Hysteria2
   - 验证 TCP。
   - 验证 UDP。
   - 验证 salamander/gecko obfs。
6. TUIC
   - 验证 v5。
   - 验证 UDP relay mode。
7. SSR
   - 补足真实协议握手测试。
   - 明确 UDP 是否支持，不支持就文档写 partial。
8. Snell
   - 补 obfs。
   - 明确 v1/v2/v3 差异。
9. WireGuard
   - 真正使用 `allowed_ips`、`reserved`、`mtu`。
   - 验证 DNS、IPv4、IPv6。
10. AnyTLS / ShadowTLS / Naive
   - 加 mock server。
   - 验证认证失败、证书失败、正常 connect。
11. Hysteria v1
   - 当前若仍 unsupported，文档必须写 unsupported 或 parse-only。
   - 如果要做，单独立项，不要假装已经完成。

完成标准：

- 一个协议没有 mock server 或传输测试，不能写 full。
- 一个协议 connect 会直接返回 unsupported，文档必须写 unsupported。

## 6. P2：智能规则和应用级规则增强

涉及文件：

- `Supercore/src/smart`
- `Supercore/src/routing`
- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift`
- `Sources/YueqiuElevatorSupercore/App/AppState.swift`

要做：

1. 智能规则记录访问目标：
   - domain
   - IP
   - app name
   - app bundle
   - app path
2. 对新目标后台直连探测。
3. 直连可达则推荐 direct。
4. 直连不可达则推荐 proxy。
5. 用户启用推荐后，生成高优先级规则。
6. 自定义规则优先级：
   - 用户手动规则最高。
   - 智能启用规则其次。
   - 订阅规则再次。
   - fallback 最后。

完成标准：

- 智能规则页能显示统计。
- 推荐直连/代理可单条启用、批量启用。
- 启用后的规则优先级高于订阅规则。

## 7. P2：UI 和用户可解释性

涉及文件：

- `Sources/YueqiuElevatorSupercore/UI/SettingsWindow.swift`
- `Sources/YueqiuElevatorSupercore/App/AppState.swift`

要做：

1. 节点页显示：
   - 当前订阅。
   - 当前代理组。
   - 当前实际节点。
   - 延迟颜色：
     - 小于 50ms：绿色
     - 50 到 150ms：蓝色
     - 150ms 以上：红色
     - 500ms 以上：超时
2. 节点列表支持：
   - 只显示可用节点。
   - 按国家筛选。
   - 按延迟排序。
   - 按协议筛选。
   - 搜索节点名。
3. 代理组交互：
   - 单击代理组只是查看组内节点。
   - 明确按钮“选择该组自动择优”。
   - 明确按钮“测速当前组”。
4. 订阅页显示：
   - 上传流量。
   - 下载流量。
   - 总流量。
   - 到期日期。
   - 更新时间。
   - 节点数量。
   - unsupported 节点数量。

完成标准：

- 用户能明确知道当前到底走的是哪个节点。
- 用户能明确知道测速失败原因。
- 用户切换订阅不会卡住或无反馈。

## 8. 最终验收清单

完成后必须执行：

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore/Supercore
cargo test

cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
swift test
swift build
```

还必须人工验证：

1. 未启动代理时可以测速。
2. 测速不会开启系统代理。
3. 启动代理不刷新订阅。
4. 启动代理不全局测速。
5. 启动代理使用上次节点。
6. 切换订阅只切本地缓存。
7. TUN 退出后系统代理恢复。
8. App 强退后能一键恢复网络。
9. 节点页当前节点显示正确。
10. 订阅页流量和到期日期显示正确。
11. 文档没有过度宣称。
12. 仓库没有用户订阅 URL、节点密钥、日志、Keychain 数据。

## 9. 本轮开发顺序

严格按这个顺序做：

1. 修协议矩阵和 README，先让文档诚实。
2. 删除/替换假测试。
3. 修 Doctor 统计。
4. 修代理组测速 API。
5. 重做测速结果分类和 UI 汇总。
6. 优化未启动代理测速流程。
7. 修订阅切换和启动代理速度。
8. 加固 TUN/DNS 恢复。
9. 建协议能力测试框架。
10. 按协议优先级逐个补真实拨号。
11. 做 UI 可解释性增强。
12. 最后统一测试、打包、更新 README。

## 10. 不允许的完成方式

以下做法不能算完成：

- 只在计划文件里打勾。
- 只改 README 吹能力。
- 只写数组长度测试。
- 只判断对象不为 nil。
- 只 parse 配置就说协议 full。
- connect 返回 unsupported 还写 full。
- 未跑测试就说已完成。
- 测速失败但 UI 统一显示超时。
- 启动代理时偷偷刷新订阅或测速。
- 提交用户真实订阅链接。
