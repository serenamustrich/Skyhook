#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="cn.yueqiu.elevator.supercore.user"
APP_SUPPORT="${HOME}/Library/Application Support/YueqiuElevatorSupercore"
BIN_DIR="${APP_SUPPORT}/bin"
CONFIG_PATH="${APP_SUPPORT}/supercore.yaml"
TOKEN_PATH="${APP_SUPPORT}/control-token"
LOG_DIR="${APP_SUPPORT}/logs"
PLIST_DIR="${HOME}/Library/LaunchAgents"
PLIST_PATH="${PLIST_DIR}/${LABEL}.plist"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/release/supercore}"
CONFIG="${SUPERCORE_CONFIG:-${ROOT}/Supercore/supercore.example.yaml}"
TOKEN="${SKYHOOK_CONTROL_TOKEN:-}"

if [[ ! -x "${CORE}" ]]; then
  cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi
if [[ ! -f "${CONFIG}" ]]; then
  echo "Config not found: ${CONFIG}" >&2
  exit 1
fi
if [[ -z "${TOKEN}" ]]; then
  TOKEN="$(/usr/bin/openssl rand -hex 32)"
fi
if [[ "${#TOKEN}" -lt 32 ]]; then
  echo "Control token must contain at least 32 bytes." >&2
  exit 1
fi

"${CORE}" check -c "${CONFIG}"
TMP_PLIST="$(mktemp -t yueqiu-supercore-agent).plist"
cleanup() { rm -f "${TMP_PLIST}"; }
trap cleanup EXIT

/bin/mkdir -p "${BIN_DIR}" "${LOG_DIR}" "${PLIST_DIR}"
/usr/bin/install -m 755 "${CORE}" "${BIN_DIR}/supercore"
/usr/bin/install -m 600 /dev/stdin "${TOKEN_PATH}" <<<"${TOKEN}"
/usr/bin/install -m 600 "${CONFIG}" "${CONFIG_PATH}"

cat >"${TMP_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>${BIN_DIR}/supercore</string><string>run</string><string>-c</string><string>${CONFIG_PATH}</string></array>
  <key>WorkingDirectory</key><string>${APP_SUPPORT}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>RUST_LOG</key><string>supercore=info,info</string>
    <key>SKYHOOK_CONTROL_TOKEN_FILE</key><string>${TOKEN_PATH}</string>
  </dict>
  <key>StandardOutPath</key><string>${LOG_DIR}/supercore.out.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/supercore.err.log</string>
</dict>
</plist>
EOF

/usr/bin/install -m 644 "${TMP_PLIST}" "${PLIST_PATH}"
/usr/bin/plutil -lint "${PLIST_PATH}"
/bin/launchctl bootout "gui/$(id -u)/${LABEL}" >/dev/null 2>&1 || true
/bin/launchctl bootstrap "gui/$(id -u)" "${PLIST_PATH}"
/bin/launchctl enable "gui/$(id -u)/${LABEL}"
/bin/launchctl kickstart -k "gui/$(id -u)/${LABEL}"
echo "Installed and started ${LABEL}."
