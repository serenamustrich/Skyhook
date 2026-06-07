#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${SKYHOOK_DAEMON_LABEL:-cn.yueqiu.elevator.skyhook}"
APP_SUPPORT="/Library/Application Support/Skyhook"
BIN_DIR="$APP_SUPPORT/bin"
BIN_PATH="$BIN_DIR/skyhook"
CONFIG_PATH="$APP_SUPPORT/skyhook.yaml"
LOG_DIR="/Library/Logs/Skyhook"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
LOG_LEVEL="${SKYHOOK_LOG_LEVEL:-skyhook=info,info}"

if [[ "$(id -u)" != "0" ]]; then
  if [[ -z "${SKYHOOK_BINARY:-}" ]]; then
    cargo build --release --manifest-path "$ROOT/Cargo.toml"
    export SKYHOOK_BINARY="$ROOT/target/release/skyhook"
  fi
  export SKYHOOK_SOURCE_ROOT="$ROOT"
  exec sudo -E bash "$0" "$@"
fi

ROOT="${SKYHOOK_SOURCE_ROOT:-$ROOT}"
SOURCE_BIN="${SKYHOOK_BINARY:-$ROOT/target/release/skyhook}"
SOURCE_CONFIG="${SKYHOOK_SOURCE_CONFIG:-$ROOT/skyhook.example.yaml}"

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
  <string>$LOG_DIR/skyhook.out.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/skyhook.err.log</string>
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

echo "Installed Skyhook LaunchDaemon: $PLIST_PATH"
echo "Binary: $BIN_PATH"
echo "Config: $CONFIG_PATH"
echo "Logs: $LOG_DIR"
