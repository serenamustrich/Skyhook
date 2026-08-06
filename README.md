# 玥球电梯 Supercore

这是一个独立的 macOS 菜单栏代理客户端，核心只使用本仓库的 Rust `Supercore`。它参考旧版玥球电梯的产品能力，但不提供双核心切换，也不依赖外部第三方核心运行时。

## 下载

[下载玥球电梯 v0.2.0 DMG](https://github.com/serenamustrich/Skyhook/releases/download/v0.2.0/YueqiuElevator-v0.2.0-e331d7f.dmg)

## 功能

- 导入常见 Clash/YAML 或 URI 订阅链接。
- 保存多个订阅、订阅 URL、套餐流量和到期信息。
- 按订阅保存原始订阅、Supercore runtime、节点选择、智能规则和累计流量。
- 从 App 启动、停止 Supercore。
- App 只接入本地受管理的 Supercore 进程或已加载的 TUN LaunchDaemon，不会因为端口相同而接入无关核心；已安装但未加载的权限服务不会被普通代理启动强行加载。
- TUN 生命周期测试会记录虚拟网卡、路由、DNS 和系统代理快照，并用本次测试 Token 确认控制的是自己的核心；矩阵默认使用隔离的 mixed/control 端口，动态启停已验证，完整管理员矩阵仍需显式授权后执行，核心停止会使用有界等待并在超时后强制清理。
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
- Hysteria v1 支持原生 QUIC TCP/UDP、鉴权、上下行带宽协商、速率感知拥塞控制、连接与
  UDP 会话复用、分片重组、fast-open，以及 UDP、wechat-video 和 xplus 混淆传输。
- Mieru v3 支持 TCP/UDP underlay、用户名密码认证、XChaCha20-Poly1305、标准/no-wait
  握手、多路复用、随机 padding、MTU 分片、可靠 UDP 重传与拥塞控制、TCP 和 SOCKS5
  UDP ASSOCIATE；支持官方分享格式、固定端口和 `port-range`，并与官方服务端完成互通。
- Juicity v0 支持 UUID/password TLS exporter 鉴权、原生 QUIC TCP、可靠 UDP stream relay、
  BBR/Cubic/NewReno、keepalive、连接与 UDP 会话复用、断线重建和证书链 SHA-256 pin；
  TCP/UDP 与错误鉴权已通过官方 v0.5.0 服务端互操作。
- MASQUE 支持 HTTP/3 和 HTTP/2 CONNECT-IP、HTTP/3 L4 CONNECT 与标准 CONNECT-UDP，
  提供 ECDSA mTLS、服务端 SPKI pin、用户态 IPv4/IPv6 TCP/UDP、远端 DNS、datagram/capsule、
  URI template、会话复用、BBR/Cubic/NewReno 和显式握手超时。
- WireGuard 使用原生用户态网络栈，支持 IPv4/IPv6、TCP/UDP、隧道内 DNS、MTU、reserved、
  pre-shared key、persistent keepalive、多 Peer 和 allowed IP 最长前缀路由。
- AnyTLS v2 支持 TLS 认证、动态 padding、会话复用与空闲回收、SYNACK/心跳、TCP 和
  sing-box UoT v2 UDP，并提供真实独立服务端拨号验证。
- ShadowTLS v3 支持 TLS 1.3 ClientHello 认证、握手流量校验与还原、TLS camouflage、
  Shadowsocks `shadow-tls` 插件和 dialer-proxy backend 组合；原生协议仅承载 TCP，
  Shadowsocks 场景可通过 UoT 承载 UDP。
- Naive 支持 HTTP/2 CONNECT、按配置启用 HTTP/3 CONNECT、HTTP/1.1 兼容路径、Basic
  Auth、官方请求头与前 8 帧双向 padding、连接复用和 IPv6 目标；NaiveProxy 协议仅承载
  TCP 流，不把不存在的 CONNECT-UDP 能力标记为可用。
- HTTP 代理支持明文 HTTP CONNECT 与 TLS 保护的 HTTPS CONNECT、Basic Auth、SNI、
  证书校验、IPv4/IPv6 目标和握手后预读数据保留。
- SOCKS5 支持无认证与用户名密码认证、域名/IPv4/IPv6 TCP CONNECT，以及带有界会话池的
  UDP ASSOCIATE。
- SSH 支持固定主机公钥或 SHA-256 指纹、主机密钥算法约束、密码/内联或文件私钥认证、
  keepalive、direct-tcpip 并发通道复用和断线重连；SSH 协议没有标准 UDP relay。
- Sudoku 支持 KIP/AEAD、纯 Sudoku 与 6-bit packed 下行、UoT UDP、HTTP/WebSocket 伪装和
  自定义表轮换；TrustTunnel 支持 TLS+HTTP/2、QUIC/HTTP3 extended CONNECT、Basic 认证、
  TCP relay 与 `_udp2` UDP 帧，并有本地 H2/H3 TCP 及 H3 `_udp2` 双向拨号回环；Tailscale 使用独立 userspace，
  不调用系统 Tailscale 进程。
- DNS outbound 支持 UDP/TCP/DoT/DoH raw DNS 查询，Rematch 支持规则重新匹配、命名上下文、
  循环检测与最大深度保护；外部 DoT 验证脚本使用可隔离的本地监听端口，不依赖默认混合端口。
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

稳定性脚本和 TUN 矩阵在正常退出或中断时都会清理自己启动的 Supercore 子进程；稳定性脚本默认使用隔离的 mixed/control 端口，避免误连其他核心；它们不会修改用户订阅数据。

App 数据位置：

```text
~/Library/Application Support/YueqiuElevator
~/Library/Logs/YueqiuElevator
```

## TUN

TUN 模式需要 root/LaunchDaemon 才能完整接管 macOS 路由和 DNS。普通 App 启动可用于 mixed 代理、订阅、测速和界面调试；需要长期免输密码运行 TUN 时，使用 `Supercore/scripts/install_macos_launch_daemon.sh` 走 Supercore 的 LaunchDaemon 路径。真实 TUN 生命周期矩阵是单独的运维测试，只有显式执行 `Scripts/tun_macos_matrix.sh --with-tun --root` 才需要管理员授权，应用启动和普通测速不会触发该授权。只有启用 TUN 或复用已运行的 daemon 时，App 才会接入权限服务。

`Supercore` 是本项目原生核心，不会自动拉取第三方核心更新。
正式运行默认使用本机 9197 控制端口；隔离测试可通过 `SKYHOOK_TEST_CONTROL_PORT` 指定测试端口，不会改变正式 App 的默认配置。
