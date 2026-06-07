#!/usr/bin/env bash
set -euo pipefail

LABEL="${SKYHOOK_LAUNCH_LABEL:-cn.yueqiu.elevator.skyhook}"
APP_SUPPORT="${SKYHOOK_APP_SUPPORT:-$HOME/Library/Application Support/Skyhook}"
PLIST_PATH="$HOME/Library/LaunchAgents/$LABEL.plist"
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

if [[ "$(id -u)" == "0" ]]; then
  echo "Do not uninstall the user LaunchAgent as root. Run this script as the login user." >&2
  exit 1
fi

launchctl bootout "gui/$(id -u)" "$PLIST_PATH" >/dev/null 2>&1 || true
rm -f "$PLIST_PATH"

if [[ "$PURGE_DATA" == "true" ]]; then
  rm -rf "$APP_SUPPORT"
fi

echo "Removed Skyhook LaunchAgent: $PLIST_PATH"
if [[ "$PURGE_DATA" == "true" ]]; then
  echo "Removed data directory: $APP_SUPPORT"
fi
