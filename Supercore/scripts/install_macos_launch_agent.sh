#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${SUPERCORE_LAUNCH_LABEL:-cn.yueqiu.elevator.supercore}"
APP_SUPPORT="${SUPERCORE_APP_SUPPORT:-$HOME/Library/Application Support/YueqiuElevatorSupercore}"
BIN_DIR="$APP_SUPPORT/bin"
BIN_PATH="$BIN_DIR/supercore"
CONFIG_PATH="${SUPERCORE_CONFIG:-$APP_SUPPORT/supercore.yaml}"
LOG_DIR="$APP_SUPPORT/logs"
PLIST_PATH="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_LEVEL="${SUPERCORE_LOG_LEVEL:-supercore=info,info}"

if [[ "$(id -u)" == "0" ]]; then
  echo "Do not install the user LaunchAgent as root. Run this script as the login user." >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$LOG_DIR" "$(dirname "$PLIST_PATH")"

if [[ -n "${SUPERCORE_BINARY:-}" ]]; then
  SOURCE_BIN="$SUPERCORE_BINARY"
else
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
  SOURCE_BIN="$ROOT/target/release/supercore"
fi

install -m 755 "$SOURCE_BIN" "$BIN_PATH"

if [[ ! -f "$CONFIG_PATH" ]]; then
  install -m 644 "$ROOT/supercore.example.yaml" "$CONFIG_PATH"
fi

KEEP_ALIVE_XML="<true/>"
if [[ "${SUPERCORE_KEEP_ALIVE:-true}" == "false" || "${SUPERCORE_KEEP_ALIVE:-true}" == "0" ]]; then
  KEEP_ALIVE_XML="<false/>"
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
  $KEEP_ALIVE_XML
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

plutil -lint "$PLIST_PATH" >/dev/null
launchctl bootout "gui/$(id -u)" "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
launchctl enable "gui/$(id -u)/$LABEL"
launchctl kickstart -k "gui/$(id -u)/$LABEL"

echo "Installed Supercore LaunchAgent: $PLIST_PATH"
echo "Binary: $BIN_PATH"
echo "Config: $CONFIG_PATH"
echo "Logs: $LOG_DIR"
