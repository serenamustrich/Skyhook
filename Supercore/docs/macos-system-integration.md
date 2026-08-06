# macOS System Integration

Supercore has two macOS launch modes:

1. User LaunchAgent: starts Supercore at login for mixed proxy, control API,
   subscriptions, background probes, smart rules, and telemetry.
2. Root LaunchDaemon: starts Supercore at boot with enough permission for TUN
   device and route setup.

TUN mode changes network interfaces and routes on macOS. That requires root
permission. A normal user LaunchAgent cannot remove the password prompt if
`tun.enabled=true` and `tun.setup=true`; use the LaunchDaemon flow for that.

## User LaunchAgent

Use this when TUN is disabled, or when another privileged helper owns TUN setup.

The copied config should be a generated runtime config without user subscription
URLs. Set `SKYHOOK_CONTROL_TOKEN` to reuse a known token, or let the installer
generate a random one for the user LaunchAgent.

```bash
./Scripts/install_macos_launch_agent.sh
./Scripts/uninstall_macos_launch_agent.sh
```

Installed paths:

- Binary: `~/Library/Application Support/YueqiuElevatorSupercore/bin/supercore`
- Config: `~/Library/Application Support/YueqiuElevatorSupercore/supercore.yaml`
- Logs: `~/Library/Application Support/YueqiuElevatorSupercore/logs`
- Plist: `~/Library/LaunchAgents/cn.yueqiu.elevator.supercore.plist`

## Root LaunchDaemon

Use this when Supercore owns TUN setup. It asks for the admin password once
during installation, then launchd starts the core as root.

Set `SKYHOOK_CONTROL_TOKEN` before installing. The daemon stores only the
root-owned control token and runtime config; subscription source URLs remain in
the App's user profile store.

```bash
./Scripts/install_macos_launch_daemon.sh
./Scripts/uninstall_macos_launch_daemon.sh
```

Installed paths:

- Binary: `/Library/Application Support/YueqiuElevatorSupercore/bin/supercore`
- Config: `/Library/Application Support/YueqiuElevatorSupercore/supercore.yaml`
- Logs: `/Library/Logs/YueqiuElevatorSupercore`
- Plist: `/Library/LaunchDaemons/cn.yueqiu.elevator.supercore.plist`

## Manual TUN Run

For development and diagnosis:

```bash
./Scripts/run_macos_tun.sh Supercore/supercore.example.yaml
```

This validates the config, builds the release binary when needed, and runs:

```bash
sudo -E env RUST_LOG=supercore=info,info supercore run -c <config>
```

## TUN Lifecycle Matrix

For an operator-assisted system test, review a config with `tun.setup: false`,
authorize sudo once, and run:

```bash
sudo -v
./Scripts/tun_macos_matrix.sh --with-tun --root --keep-artifacts
```

The matrix records route/DNS/proxy/interface snapshots and verifies dynamic
TUN start, dynamic stop, normal core termination, and forced core termination.
It exits with code `77` when administrator authorization is unavailable; that
is a skipped environment gate, not a successful TUN test. Route-changing
configs require an explicit `--allow-route-changes` review flag.

## Configuration Notes

For full-device proxying, set:

```yaml
tun:
  enabled: true
  setup: true
```

For app-controlled route setup, set `tun.setup: false` and let the app or helper
create the interface/routes before starting Supercore.

The control API defaults to `127.0.0.1:9197`, and the mixed proxy defaults to
`127.0.0.1:7897`.
