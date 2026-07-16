# MIHOMO-Parity 实施复核索引

本文件用于把计划条目与当前可复核证据绑定，减少“只改文档打钩”导致的误解。

## 里程碑 1：诊断与命令一致性

- `supercore subscription inspect` 与 `supercore subscriptions inspect` 均应可用
  - 证据：`Supercore/src/main.rs` 中 `Command::Subscriptions` 的命名与别名定义
    - 具体：`#[command(name = "subscription", alias = "subscriptions")]`
  - 已执行核验：
    - `cargo run --quiet -- subscription inspect`
    - `cargo run --quiet -- subscriptions inspect`
  - 输出样例结论：
    - 均返回 `Total subscriptions: 0` 与 `Active subscription: none`

- `doctor` 包含节点统计/规则统计字段
  - 证据：`Supercore/src/main.rs` 的 `Command::Doctor` 分支
  - 已执行核验：`cargo run --quiet -- doctor --config supercore.example.yaml`
  - 输出样例结论（关键项）：
    - `Outbounds: 2`
    - `Supported outbound: 2`
    - `Unsupported outbound: 0`
    - `Group outbounds: 0`
    - `direct: 1`、`reject: 1`

- `tun cleanup` 命令与恢复动作存在
  - 证据：`Supercore/src/main.rs` 的 `Command::Tun::Cleanup` 分支
  - 已执行核验：`cargo run --quiet -- tun cleanup --dry-run`
  - 输出样例结论（关键项）：
    - `No 198.18.0.0/15 routes found - clean.`
    - `System proxy still points to 127.0.0.1`
    - `=== TUN Cleanup Complete ===`

- `订阅 diagnostic` 链路可用（inspect/list/use/import/update/export）
  - 证据：`Supercore/src/main.rs` 的 `SubscriptionCommand` 与 `handle_subscription_command`

- `subscription inspect` 支持过滤参数
  - 计划要求样例写法：`supercore subscription inspect --store <path> --id <id>`
  - 已执行核验（基于样例 store）：
    - `cargo run --quiet -- subscription import --file tests/fixtures/realistic_mixed_subscription.yaml --store /tmp/supercore-subscription-store --name realism --id demo-sub`
    - `cargo run --quiet -- subscription inspect --store /tmp/supercore-subscription-store --id demo-sub`
  - 输出样例结论：
    - `Active subscription: demo-sub`
    - `Total outbounds: 7`
    - `Supported outbound: 4`
    - `Groups: 1`
    - `Rules: 5`

- `subscription export-active-config` 可输出运行态配置
  - 已执行核验：`cargo run --quiet -- subscription export-active-config --store /tmp/supercore-subscription-store --use-first-node --output /tmp/supercore-active.yaml`
  - 输出样例结论：
    - 命令返回 `Exported active subscription config`
    - 输出配置可复现 `type: vmess ...` 与 `type: group` 节点信息

## 里程碑 2：组测速与成员展开

- 组测速 API 支持递归组成员展开 + 直连/阻断过滤 + 循环保护 + 未知成员保留
  - 证据：`Supercore/src/api/mod.rs`
    - `collect_group_probe_members`
    - `collect_group_members`
    - `#[cfg(test)]` 中新增两个对应单元测试

## 里程碑 3：probe 与失败分类

- `probe` 可运行且返回 `failure_kind`
  - 证据：`Supercore/src/core/mod.rs` 的 `ProbeResult`
  - 已执行核验：`cargo run --quiet -- probe --config supercore.example.yaml --timeout-ms 500 --url http://www.gstatic.com/generate_204`
  - 输出样例：
    - `{"name":"direct","kind":"direct","success":true,"latency_ms":69,"failure_kind":null,"error":null}`

- 负例验证：`--names` 参数不存在时给出错误
  - 已执行核验：`cargo run --quiet -- probe --config supercore.example.yaml --timeout-ms 500 --url http://www.gstatic.com/generate_204 --names /tmp/does-not-exist.txt`
  - 输出样例：
    - `Error: No such file or directory (os error 2)`

- 失败分类覆盖验证（本机可复现）
  - `cargo run --quiet -- probe --config /tmp/supercore-probe-failure.yaml --names /tmp/probe-names.txt --url http://www.gstatic.com/generate_204 --timeout-ms 500`
  - 关键样例：
    - `failure_kind: "protocol_unsupported"`（`unsupported-hysteria`）
    - `failure_kind: "outbound_not_found"`（`missing-node`）
    - `failure_kind: "dial_error"`（`socks-bad-dns`，当前错误口径显示 `early eof`）

- 分类逻辑单测
  - 已执行：`cargo test --quiet --lib classify_probe_failure`
  - 验证：
    - `protocol not implemented` 识别为 `protocol_unsupported`
    - `lookup` 字符串识别为 `dns_error`

- 超时分类验证
  - `cargo run --quiet -- probe --config /tmp/supercore-timeout.yaml --names /tmp/probe-timeout-names.txt --url http://www.gstatic.com/generate_204 --timeout-ms 200`
  - 关键样例：
    - `failure_kind: "timeout"`（`timeout-socks`、`timeout-socks2`）

- HTTP 异常分类验证（HTTP 502）
  - 已执行核验：`cargo run --quiet -- probe --config /tmp/supercore-http-status.yaml --timeout-ms 800 --url http://127.0.0.1:18180/`
  - 关键样例：
    - 先行启动本地服务：
      - `python3 /tmp/miomo_http_status_server.py`（返回 `502 Bad Gateway`）
    - 结果：
      - `failure_kind: "http_status"`
      - `error: "unhealthy probe response: HTTP/1.0 502 Bad Gateway"`

- TLS 异常分类验证（证书失败）
  - 已执行核验：`cargo run --quiet -- probe --config /tmp/supercore-http-status.yaml --timeout-ms 1200 --url https://self-signed.badssl.com/`
  - 关键样例：
    - `failure_kind: "tls_error"`
    - `error: "invalid peer certificate: UnknownIssuer"`

## 里程碑 4：前端 API 稳定性

- 组名路径编码
  - 证据：`Sources/YueqiuElevatorSupercore/Services/SupercoreAPIClient.swift` 中 `probeGroup(...)` 对 `name` 的 `addingPercentEncoding` 处理

## 里程碑 5：doctor 协议统计口径一致性

- 统计按协议类型分组，不再按节点名聚合
  - 证据：`Supercore/src/main.rs` 的 `outbound_api_kind` 与 `Doctor` 分支

## 与外部方案对比性验收

- 外部联调条件：
  - 已补齐离线对比闭环文档与脚本：`Scripts/probe_compare_notes.md`、`Scripts/compare_probe_results.py`、`Scripts/export_mihomo_probe.py`。
- 可复现核验清单：
  - 使用同一订阅配置（如允许）；
  - 同步使用 `http://www.gstatic.com/generate_204` 和 `timeout-ms=500`；
  - 抽取至少前 20 个同名节点的 `success/failure_kind/latency_ms`；
  - 对比指标：总节点数、可用数、`outbound_not_found`、`protocol_unsupported`、`timeout`、P50/P90（可选）。
- 本机当前进度：
  - 已完成 Supercore 端故障分类 + API/组展开能力的可复验闭环；
- 外部对比采样方式已提供，可直接产出差异摘要，示例验证命令如下：
    - 外部导出：  
      `python3 Scripts/export_mihomo_probe.py --base-url "http://127.0.0.1:9090" --secret "<secret>" --timeout-ms 500 --url "http://www.gstatic.com/generate_204" --output /tmp/sparkle-probe.json`
    - 对比：`python3 Scripts/compare_probe_results.py --supercore /tmp/supercore-probe.json --external /tmp/sparkle-probe.json --top 20`
    - 若使用外部快照为 CSV：`python3 Scripts/compare_probe_results.py --supercore /tmp/supercore-probe.json --external /tmp/sparkle-probe.csv --top 20`
  - 端到端比对样例已执行（本地示例快照）：`python3 Scripts/compare_probe_results.py --supercore /tmp/supercore-probe-sample.json --external /tmp/sparkle-probe-sample.json --top 20`
    - 输出包含：总节点数、可用率、失败分类、同名节点差异、单侧节点清单、延迟差异
  - 实际样例脚本已执行通过（两份示例快照，确认输出含总节点数、可用率、失败分类、同名差异、top20 清单）
### 里程碑 6：真实外部联调样本已补齐（同一订阅同参数）

- 已完成同源快照闭环（Sparkle 当前配置 `~/Library/Application Support/sparkle/work/config.yaml`）
  - 采样链路与对比命令：
    - `cargo run --manifest-path Supercore/Cargo.toml -- subscription import --file "$HOME/Library/Application Support/sparkle/work/config.yaml" --store /tmp/supercore-subscription-store-closure2 --name sparkle-work --id sparkle-work --switch`
    - `cargo run --manifest-path Supercore/Cargo.toml -- subscription export-active-config --store /tmp/supercore-subscription-store-closure2 --use-first-node --output /tmp/supercore-active-export2.yaml`
    - `python3 Scripts/export_mihomo_probe.py --unix-socket /tmp/sparkle-mihomo-api.sock --timeout-ms 500 --url http://www.gstatic.com/generate_204 --names /tmp/closure2-common.txt --output /tmp/mihomo-closure2-probe.json`
    - `cargo run --manifest-path Supercore/Cargo.toml -- probe -c /tmp/supercore-active-export2.yaml --timeout-ms 500 --url http://www.gstatic.com/generate_204 --names /tmp/closure2-common.txt > /tmp/supercore-closure2-probe.json`
    - `python3 Scripts/compare_probe_results.py --supercore /tmp/supercore-closure2-probe.json --external /tmp/mihomo-closure2-probe.json --top 20`
  - 核验结果样例（本地）:
    - 节点数：40
    - Supercore 可用：7/40（17.5%）
    - External 可用：9/40（22.5%）
    - 同名交集：40/40
    - 失败分类（Supercore）：`protocol_unsupported=4`、`timeout=9`、`tls_error=20`
    - 失败分类（External）：`probe_failed=31`

- `Scripts/collect_probe_parity.sh` 与 `Scripts/export_mihomo_probe.py` 的外部采样能力已用于同名闭环，后续可直接复跑。

- 当前状态：该外部联调样本待补齐项已关闭，可复验并可复跑。

## 对比闭环执行记录（本地最小样本）

- 时间：已执行
- 命令：
  - `python3 Scripts/compare_probe_results.py --supercore /tmp/supercore-real-probe.json --external /tmp/mihomo-real-probe.json --top 20`
- 结论：
  - 两端样本同名节点：2 条，均不可用
  - 主要失败分类差异：
    - Supercore: `outbound_not_found=2`
    - 外部: `http_status=2`
  - 同名可用性差异：无
