# Supercore TUN 能力边界

Supercore 当前 macOS TUN 入站基于 `tun2proxy 0.8.1`。本文件记录真实生效能力，避免配置字段存在但运行时没有效果。

## 当前已接入

- 创建 macOS utun 虚拟网卡。
- `setup` 路由和系统配置。
- `auto_route` 作为 `setup` 的显式别名。
- SOCKS5 回环转发到 Supercore mixed inbound。
- MTU。
- Direct、Over-TCP、Virtual 三种 tun2proxy DNS strategy。
- DNS resolver address。
- Virtual DNS pool。
- IPv4/IPv6 bypass CIDR。
- IPv6 开关。
- TCP/UDP session timeout。
- 最大并发 session。
- 可选 utun 名称。

## 当前不支持

以下字段如果启用，核心会在 TUN 启动前返回明确配置错误：

- `stack: gvisor`
- `stack: mixed`
- `auto_detect_interface`
- `strict_route`
- `auto_redirect`
- GSO
- 自定义 `inet4_address` / `inet6_address`
- 自定义 `inet4_route_address` / `inet6_route_address`
- UID include/exclude
- package include/exclude
- process include/exclude

## DNS 安全

- App 的独立测速 runtime 强制关闭 TUN 和核心 DNS。
- Fake-IP filter 命中时走真实 DNS，不返回 `0.0.0.0`。
- DNS fallback 优先读取 macOS `scutil --dns`，再使用配置的 direct/default resolver。
- fallback 会排除核心自己的 DNS listen 地址，避免递归。

## 后续目标

- TUN 启停事务化。
- 崩溃后自动回滚路由与 DNS。
- Wi-Fi 切换、休眠唤醒和 DHCP 变化恢复。
- 可靠的进程/bundle 识别。
- 自定义路由、strict-route 和自动接口探测。
- IPv6-only 和双栈完整验收。
