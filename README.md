# 玥球电梯 Supercore

这是一个独立的 macOS 菜单栏代理客户端，核心只使用本仓库的 Rust `Supercore`。它参考旧版玥球电梯的产品能力，但不提供双核心切换，也不依赖外部第三方核心运行时。

## 功能

- 导入常见 Clash/YAML 或 URI 订阅链接。
- 保存多个订阅、订阅 URL、套餐流量和到期信息。
- 按订阅保存原始订阅、Supercore runtime、节点选择、智能规则和累计流量。
- 从 App 启动、停止 Supercore。
- 通过独立 `/v1/*` 控制接口读取代理组、国家分组、节点延迟、日志、流量和智能规则建议。
- 节点、代理组、订阅、规则、日志和任务等列表支持统一的筛选、排序与游标分页。
- 选择具体节点、代理组择优、国家自动择优。
- 后台更新订阅、后台测速，不阻塞当前代理使用。
- Shadowsocks 支持完整 TCP/UDP 拨号、SIP022/SIP023、UoT v1/v2、simple-obfs 和
  v2ray-plugin WebSocket/TLS。
- Snell 支持 v1-v5 TCP、v3-v5 UDP-over-TCP、HTTP/TLS 混淆和 v4/v5 连接复用。
- Trojan 支持 TCP/UDP、WebSocket、gRPC、HTTP/2、HTTPUpgrade、自定义请求头和 ALPN。
- VMess 支持 AEAD 与 legacy alterId、TCP/UDP、WebSocket、gRPC、HTTP/2、HTTP camouflage、
  HTTPUpgrade、自定义请求头和 ALPN；XHTTP 配置会在拨号前明确返回不支持。
- VLESS 支持 TCP/UDP、TLS/无 TLS、WebSocket、gRPC、HTTP/2、HTTP camouflage、
  HTTPUpgrade、自定义请求头和 ALPN；Reality 支持 ClientHello 认证、short ID、临时证书
  校验和 fingerprint profile，Vision 支持双向 padding 与 TLS 1.3 direct copy。
- 节点测速、订阅导入/更新、Provider 更新、Geo 更新、Doctor 和诊断导出使用可取消异步任务。
- 订阅与 Provider 下载默认使用直连通道，失败时保留已有本地缓存。
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

## TUN

TUN 模式需要 root/LaunchDaemon 才能完整接管 macOS 路由和 DNS。普通 App 启动可用于 mixed 代理、订阅、测速和界面调试；需要长期免输密码运行 TUN 时，使用 `Supercore/scripts/install_macos_launch_daemon.sh` 走 Supercore 的 LaunchDaemon 路径。

`Supercore` 是本项目原生核心，不会自动拉取第三方核心更新。
