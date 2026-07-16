#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${SUPERCORE_DAEMON_LABEL:-cn.yueqiu.elevator.supercore}"
APP_SUPPORT="/Library/Application Support/YueqiuElevatorSupercore"
BIN_DIR="$APP_SUPPORT/bin"
BIN_PATH="$BIN_DIR/supercore"
CONFIG_PATH="$APP_SUPPORT/supercore.yaml"
LOG_DIR="/Library/Logs/YueqiuElevatorSupercore"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
LOG_LEVEL="${SUPERCORE_LOG_LEVEL:-supercore=info,info}"

if [[ "$(id -u)" != "0" ]]; then
  if [[ -z "${SUPERCORE_BINARY:-}" ]]; then
    cargo build --release --manifest-path "$ROOT/Cargo.toml"
    export SUPERCORE_BINARY="$ROOT/target/release/supercore"
  fi
  export SUPERCORE_SOURCE_ROOT="$ROOT"
  exec sudo -E bash "$0" "$@"
fi

ROOT="${SUPERCORE_SOURCE_ROOT:-$ROOT}"
SOURCE_BIN="${SUPERCORE_BINARY:-$ROOT/target/release/supercore}"
SOURCE_CONFIG="${SUPERCORE_SOURCE_CONFIG:-$ROOT/supercore.example.yaml}"

install -d -m 755 "$BIN_DIR" "$LOG_DIR"
install -m 755 "$SOURCE_BIN" "$BIN_PATH"

if [[ ! -f "$CONFIG_PATH" ]]; then
  install -m 644 "$SOURCE_CONFIG" "$CONFIG_PATH"
fi

cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_PATH</string>
    <string>run</string>
    <string>-c</string>
    <string>$CONFIG_PATH</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$APP_SUPPORT</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key>
    <string>$LOG_LEVEL</string>
  </dict>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/supercore.out.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/supercore.err.log</string>
</dict>
</plist>
PLIST

chown root:wheel "$PLIST_PATH"
chmod 644 "$PLIST_PATH"
plutil -lint "$PLIST_PATH" >/dev/null
launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap system "$PLIST_PATH"
launchctl enable "system/$LABEL"
launchctl kickstart -k "system/$LABEL"

echo "Installed Supercore LaunchDaemon: $PLIST_PATH"
echo "Binary: $BIN_PATH"
echo "Config: $CONFIG_PATH"
echo "Logs: $LOG_DIR"
