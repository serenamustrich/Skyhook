# 玥球电梯 Supercore

这是一个独立的 macOS 菜单栏代理客户端，核心只使用本仓库的 Rust `Supercore`。它参考旧版玥球电梯的产品能力，但不提供双核心切换，也不依赖外部第三方核心运行时。

## Current MVP

- 导入常见 Clash/YAML 或 URI 订阅链接。
- 保存多个订阅、订阅 URL、套餐流量和到期信息。
- 按订阅保存原始订阅、Supercore runtime、节点选择、智能规则和累计流量。
- 从 App 启动、停止 Supercore。
- 通过 `/supercore/*` 读取代理组、国家分组、节点延迟、日志、流量和智能规则建议。
- 选择具体节点、代理组择优、国家自动择优。
- 后台更新订阅、后台测速，不阻塞当前代理使用。
- 支持自定义域名/IP 规则，并让这些规则优先于订阅规则。
- 提供系统代理快照恢复路径。

## Run

```bash
cd /Users/chency/Downloads/clash/YueqiuElevatorSupercore
Scripts/bootstrap_supercore.sh
Scripts/run_app.sh
```

不要用 `swift run` 作为日常启动方式。`Scripts/run_app.sh` 会先构建 `.app` bundle，再按真实 macOS App 方式启动，菜单栏、Bundle ID、图标和权限行为都更接近最终产品。

Supercore 安装位置：

```text
~/Library/Application Support/YueqiuElevator/cores/supercore
```

App 数据位置：

```text
~/Library/Application Support/YueqiuElevator
~/Library/Logs/YueqiuElevator
```

## Notes

TUN 模式需要 root/LaunchDaemon 才能完整接管 macOS 路由和 DNS。普通 App 启动可用于 mixed 代理、订阅、测速和界面调试；需要长期免输密码运行 TUN 时，使用 `Supercore/scripts/install_macos_launch_daemon.sh` 走 Supercore 的 LaunchDaemon 路径。

`Supercore` 是本项目原生核心，不会自动拉取第三方核心更新。
