#!/usr/bin/env bash
set -euo pipefail

LABEL="${SKYHOOK_DAEMON_LABEL:-cn.yueqiu.elevator.skyhook}"
APP_SUPPORT="/Library/Application Support/Skyhook"
LOG_DIR="/Library/Logs/Skyhook"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
PURGE_DATA=false

for arg in "$@"; do
  case "$arg" in
    --purge-data)
      PURGE_DATA=true
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" != "0" ]]; then
  exec sudo bash "$0" "$@"
fi

launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
rm -f "$PLIST_PATH"

if [[ "$PURGE_DATA" == "true" ]]; then
  rm -rf "$APP_SUPPORT" "$LOG_DIR"
fi

echo "Removed Skyhook LaunchDaemon: $PLIST_PATH"
if [[ "$PURGE_DATA" == "true" ]]; then
  echo "Removed data directory: $APP_SUPPORT"
  echo "Removed log directory: $LOG_DIR"
fi
