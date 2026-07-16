#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="$("${ROOT}/Scripts/build_app.sh")"

pkill -f "${APP_PATH}/Contents/MacOS/YueqiuElevatorSupercore" 2>/dev/null || true
sleep 0.5
if ! open "${APP_PATH}"; then
  echo "open failed; launching executable directly as fallback" >&2
  nohup "${APP_PATH}/Contents/MacOS/YueqiuElevatorSupercore" >/tmp/yueqiu-elevator.stdout.log 2>/tmp/yueqiu-elevator.stderr.log &
fi
echo "Opened ${APP_PATH}"
