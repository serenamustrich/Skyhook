# Probe 对比验收说明（Supercore vs Sparkle/Mihomo）

目的：为里程碑“与外部方案对比”建立可复现流程。该流程不要求联网抓包，只要能拿到两端导出的延迟快照即可。

## 约束与前置

- 同一订阅配置（如含敏感 URL，请勿在公开环境直接粘贴）
- 同一个测速 URL 与 timeout（默认 `http://www.gstatic.com/generate_204`，`500ms`）
- 同一批次节点（至少 20 个同名节点建议）
- 同步导出或保存两端测速结果

## 本机可复核：Supercore

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
cargo run --quiet -- probe -c supercore.example.yaml --timeout-ms 500 --url http://www.gstatic.com/generate_204 > /tmp/supercore-probe.json
```

导出的 JSON 形态可直接被比较脚本识别（`results` 字段或节点数组）。

## 外部端可复核

在 Sparkle/Mihomo 侧导出相同条件的测速结果：

- 至少保留字段：
  - `name`
  - 是否可用（`success` / `ok` / 类似字段）
  - 延迟（`latency_ms` / `delay` / `ms`）
  - 失败分类（如有）

保存为 JSON 或 CSV，放到本机可读路径（不含敏感 URL）。

若你本地已跑 `MihomoTrayMac` 或兼容 Mihomo external-controller，推荐直接用脚本导出：

```bash
python3 Scripts/export_mihomo_probe.py \
  --base-url "http://127.0.0.1:9090" \
  --secret "<external-controller-secret>" \
  --timeout-ms 500 \
  --url "http://www.gstatic.com/generate_204" \
  --output /tmp/sparkle-probe.json
```

- `--secret` 为 Mihomo 配置里的 `secret`。
- 脚本会过滤掉 proxy-group 与系统固定条目（如 `DIRECT`/`REJECT`），输出直接兼容 `compare_probe_results.py`。

## 对比命令

```bash
python3 Scripts/compare_probe_results.py \
  --supercore /tmp/supercore-probe.json \
  --external /tmp/sparkle-probe.json \
  --top 20
```

输出会包含：

- 总节点数
- 可用率
- 失败分类（按外部端与 Supercore）
- P50/P90（可用节点）
- 前 `20` 个同名节点可用性 + 延迟差异
- 仅在一侧存在的节点清单

## 建议核验字段（每次记录）

- `总节点数`
- `可用数`
- `outbound_not_found`
- `protocol_unsupported`
- `timeout`
- `失败分类占比`
- `P50 / P90`
- `前 20 个同名节点（name/success/latency/failure_kind）`

## 注意

- 当前环境未发现可自动读取 Sparkle 的统一 CLI 导出接口，故本流程以“导入外部端样本文件 + 脚本对比”为主。
- 若希望加入自动抓取外部端导出，可在确认对方端点后补充到该文档。

补充对齐参数：

- 外部导出可用 `--names` 文件参数限制为同名节点集合，减少两端覆盖集合差异：

```bash
python3 Scripts/export_mihomo_probe.py \
  --base-url "http://127.0.0.1:9090" \
  --secret "<external-controller-secret>" \
  --timeout-ms 500 \
  --url "http://www.gstatic.com/generate_204" \
  --names /tmp/same-names.txt \
  --output /tmp/sparkle-probe.json
```

`/tmp/same-names.txt` 每行一个代理名，支持 UTF-8，空行会被自动忽略。
