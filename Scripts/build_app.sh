#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCT_NAME="玥球电梯"
EXECUTABLE_NAME="YueqiuElevatorSupercore"
CONFIGURATION="${CONFIGURATION:-debug}"
PRODUCT_DIR="${ROOT}/dist"
APP_DIR="${PRODUCT_DIR}/${PRODUCT_NAME}.app"
CONTENTS="${APP_DIR}/Contents"
MACOS="${CONTENTS}/MacOS"
RESOURCES="${CONTENTS}/Resources"

cd "${ROOT}"
swift build -c "${CONFIGURATION}" >&2
cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml" >&2

BIN_PATH="$(swift build -c "${CONFIGURATION}" --show-bin-path 2>/dev/null)"
EXECUTABLE="${BIN_PATH}/${EXECUTABLE_NAME}"

rm -rf "${APP_DIR}"
mkdir -p "${MACOS}" "${RESOURCES}"
cp "${EXECUTABLE}" "${MACOS}/${EXECUTABLE_NAME}"
cp "${ROOT}/Resources/Info.plist" "${CONTENTS}/Info.plist"
if [[ -f "${ROOT}/Resources/AppIcon.icns" ]]; then
  cp "${ROOT}/Resources/AppIcon.icns" "${RESOURCES}/AppIcon.icns"
fi
cp "${ROOT}/Supercore/target/release/supercore" "${RESOURCES}/supercore"

chmod +x "${MACOS}/${EXECUTABLE_NAME}"
chmod +x "${RESOURCES}/supercore"

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "${APP_DIR}" >&2
fi

echo "${APP_DIR}"
