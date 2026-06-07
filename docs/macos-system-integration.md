# macOS System Integration

Skyhook has two macOS launch modes:

1. User LaunchAgent: starts Skyhook at login for mixed proxy, control API,
   subscriptions, background probes, smart rules, and telemetry.
2. Root LaunchDaemon: starts Skyhook at boot with enough permission for TUN
   device and route setup.

TUN mode changes network interfaces and routes on macOS. That requires root
permission. A normal user LaunchAgent cannot remove the password prompt if
`tun.enabled=true` and `tun.setup=true`; use the LaunchDaemon flow for that.

## User LaunchAgent

Use this when TUN is disabled, or when another privileged helper owns TUN setup.

```bash
./scripts/install_macos_launch_agent.sh
./scripts/uninstall_macos_launch_agent.sh
```

Installed paths:

- Binary: `~/Library/Application Support/Skyhook/bin/skyhook`
- Config: `~/Library/Application Support/Skyhook/skyhook.yaml`
- Logs: `~/Library/Application Support/Skyhook/logs`
- Plist: `~/Library/LaunchAgents/cn.yueqiu.elevator.skyhook.plist`

## Root LaunchDaemon

Use this when Skyhook owns TUN setup. It asks for the admin password once
during installation, then launchd starts the core as root.

```bash
./scripts/install_macos_launch_daemon.sh
./scripts/uninstall_macos_launch_daemon.sh
```

Installed paths:

- Binary: `/Library/Application Support/Skyhook/bin/skyhook`
- Config: `/Library/Application Support/Skyhook/skyhook.yaml`
- Logs: `/Library/Logs/Skyhook`
- Plist: `/Library/LaunchDaemons/cn.yueqiu.elevator.skyhook.plist`

## Manual TUN Run

For development and diagnosis:

```bash
./scripts/run_macos_tun.sh skyhook.example.yaml
```

This validates the config, builds the release binary when needed, and runs:

```bash
sudo -E env RUST_LOG=skyhook=info,info skyhook run -c <config>
```

## Configuration Notes

For full-device proxying, set:

```yaml
tun:
  enabled: true
  setup: true
```

For app-controlled route setup, set `tun.setup: false` and let the app or helper
create the interface/routes before starting Skyhook.

The control API defaults to `127.0.0.1:9197`, and the mixed proxy defaults to
`127.0.0.1:7897`.
