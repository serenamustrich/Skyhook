#!/usr/bin/env bash
set -euo pipefail

LABEL="cn.yueqiu.elevator.supercore.user"
PLIST_PATH="${HOME}/Library/LaunchAgents/${LABEL}.plist"

/bin/launchctl bootout "gui/$(id -u)/${LABEL}" >/dev/null 2>&1 || true
/bin/rm -f "${PLIST_PATH}"
echo "Uninstalled ${LABEL}; cached configuration, token and logs were retained."
