#!/usr/bin/env bash
set -euo pipefail

LABEL="cn.yueqiu.elevator.supercore"
APP_SUPPORT="/Library/Application Support/YueqiuElevatorSupercore"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

sudo /bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
sudo /bin/rm -f "${PLIST_PATH}" "${APP_SUPPORT}/control-token"
echo "Uninstalled ${LABEL}; cached configuration and logs were retained."
