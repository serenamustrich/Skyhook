# Supercore TUN 能力边界

Supercore 的 TUN 入站使用 Rust `tun2proxy` 用户态转发后端。配置只在
后端明确支持时生效；当前版本不会静默吞掉未知或暂未实现的 Mihomo 配置项。

## 已实现

- macOS/Linux 用户态 TUN 创建与关闭
- TCP、UDP 转发到本地 SOCKS5 mixed 入站
- `setup`/`auto-route` 路由安装
- MTU、IPv6 开关、TCP/UDP 空闲超时、最大会话数
- `direct`、`over-tcp`、`virtual` 三种 TUN DNS 策略
- Fake-IP 虚拟 DNS 地址池与 bypass CIDR
- `udpgw-server` UDP over gateway
- 运行时取消时关闭转发任务；App 侧在启动失败、停止和退出时执行回滚
- `/v1/tun` 提供 `disabled`、`starting`、`running`、`failed` 运行态；macOS
  会等待新出现的 `utun*` 设备后才报告 `running`

## 当前明确拒绝的配置

以下配置模型已经能被解析，但当前后端没有对应实现，启用时会返回错误：

- `stack: gvisor`、`stack: mixed`
- `auto-detect-interface`
- `strict-route`
- `auto-redirect`
- `gso` 与自定义 GSO 大小
- 自定义 TUN 地址和路由地址
- UID、包名、进程名过滤

这类配置不会被当成“已经生效”，UI 也不应该把它们展示成可用能力。

## 退出与恢复边界

- 普通用户态 core 收到取消信号后释放 TUN 转发资源。
- App 停止代理时先停止后台任务，再恢复系统代理；LaunchDaemon 路径先热重载
  `tun.enabled=false`，重载失败时 bootout daemon 作为最后回滚。
- App 启动失败时会停止普通 core 或回滚 LaunchDaemon，并再次刷新 daemon 状态。
- TUN supervisor 支持通过 `/v1/config/reload` 动态创建/停止 TUN 子任务；停止和
  App 退出会等待 runtime 状态回到 `disabled`，超时则进入网络恢复状态。
- 如果系统管理员权限、系统路由或第三方 VPN 阻止回滚，App 必须将网络状态标记为
  `networkRecoveryNeeded`，而不能显示“已恢复”。

## 还需要真实 macOS 环境验收的项目

Wi-Fi/有线切换、DHCP 变化、休眠唤醒、第三方 VPN 共存、强杀 App、core 崩溃、
IPv6-only/双栈网络仍需在真实 macOS 机器上逐项验收。可使用仓库中的
`Scripts/tun_macos_matrix.sh --with-tun --root` 固化动态启停、正常退出和强杀清理
证据；代码单测不能替代这些系统级网络验证。
