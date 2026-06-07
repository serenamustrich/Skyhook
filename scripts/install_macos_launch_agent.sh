#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${SKYHOOK_LAUNCH_LABEL:-cn.yueqiu.elevator.skyhook}"
APP_SUPPORT="${SKYHOOK_APP_SUPPORT:-$HOME/Library/Application Support/Skyhook}"
BIN_DIR="$APP_SUPPORT/bin"
BIN_PATH="$BIN_DIR/skyhook"
CONFIG_PATH="${SKYHOOK_CONFIG:-$APP_SUPPORT/skyhook.yaml}"
LOG_DIR="$APP_SUPPORT/logs"
PLIST_PATH="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_LEVEL="${SKYHOOK_LOG_LEVEL:-skyhook=info,info}"

if [[ "$(id -u)" == "0" ]]; then
  echo "Do not install the user LaunchAgent as root. Run this script as the login user." >&2
  exit 1
fi

mkdir -p "$BIN_DIR" "$LOG_DIR" "$(dirname "$PLIST_PATH")"

if [[ -n "${SKYHOOK_BINARY:-}" ]]; then
  SOURCE_BIN="$SKYHOOK_BINARY"
else
  cargo build --release --manifest-path "$ROOT/Cargo.toml"
  SOURCE_BIN="$ROOT/target/release/skyhook"
fi

install -m 755 "$SOURCE_BIN" "$BIN_PATH"

if [[ ! -f "$CONFIG_PATH" ]]; then
  install -m 644 "$ROOT/skyhook.example.yaml" "$CONFIG_PATH"
fi

KEEP_ALIVE_XML="<true/>"
if [[ "${SKYHOOK_KEEP_ALIVE:-true}" == "false" || "${SKYHOOK_KEEP_ALIVE:-true}" == "0" ]]; then
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
  <string>$LOG_DIR/skyhook.out.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/skyhook.err.log</string>
</dict>
</plist>
PLIST

plutil -lint "$PLIST_PATH" >/dev/null
launchctl bootout "gui/$(id -u)" "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
launchctl enable "gui/$(id -u)/$LABEL"
launchctl kickstart -k "gui/$(id -u)/$LABEL"

echo "Installed Skyhook LaunchAgent: $PLIST_PATH"
echo "Binary: $BIN_PATH"
echo "Config: $CONFIG_PATH"
echo "Logs: $LOG_DIR"
