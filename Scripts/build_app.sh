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
ENTITLEMENTS="${ROOT}/Resources/Skyhook.entitlements"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
MPTCP_PROVISIONING_PROFILE="${MPTCP_PROVISIONING_PROFILE:-}"

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
  USE_MPTCP_ENTITLEMENTS=0
  PROFILE_PLIST=""
  cleanup_profile_plist() {
    if [[ -n "${PROFILE_PLIST}" ]]; then
      rm -f "${PROFILE_PLIST}"
    fi
  }
  trap cleanup_profile_plist EXIT

  if [[ -n "${MPTCP_PROVISIONING_PROFILE}" ]]; then
    if [[ "${CODESIGN_IDENTITY}" == "-" ]]; then
      echo "MPTCP signing requires a non-ad-hoc CODESIGN_IDENTITY" >&2
      exit 1
    fi
    if [[ ! -f "${MPTCP_PROVISIONING_PROFILE}" ]]; then
      echo "MPTCP provisioning profile not found: ${MPTCP_PROVISIONING_PROFILE}" >&2
      exit 1
    fi
    if ! command -v security >/dev/null 2>&1; then
      echo "security is required to validate the MPTCP provisioning profile" >&2
      exit 1
    fi

    PROFILE_PLIST="$(mktemp -t skyhook-mptcp-profile)"
    security cms -D -i "${MPTCP_PROVISIONING_PROFILE}" >"${PROFILE_PLIST}"
    PROFILE_MPTCP="$(/usr/libexec/PlistBuddy -c \
      'Print :Entitlements:com.apple.developer.networking.multipath' \
      "${PROFILE_PLIST}" 2>/dev/null || true)"
    if [[ "${PROFILE_MPTCP}" != "true" ]]; then
      echo "Provisioning profile does not authorize the multipath entitlement" >&2
      exit 1
    fi

    cp "${MPTCP_PROVISIONING_PROFILE}" "${CONTENTS}/embedded.provisionprofile"
    USE_MPTCP_ENTITLEMENTS=1
  fi

  if [[ "${USE_MPTCP_ENTITLEMENTS}" == "1" ]]; then
    codesign --force --options runtime --entitlements "${ENTITLEMENTS}" \
      --sign "${CODESIGN_IDENTITY}" "${RESOURCES}/supercore" >&2
    codesign --force --options runtime --entitlements "${ENTITLEMENTS}" \
      --sign "${CODESIGN_IDENTITY}" "${APP_DIR}" >&2
  else
    codesign --force --options runtime \
      --sign "${CODESIGN_IDENTITY}" "${RESOURCES}/supercore" >&2
    codesign --force --options runtime \
      --sign "${CODESIGN_IDENTITY}" "${APP_DIR}" >&2
  fi
  codesign --verify --strict --deep "${APP_DIR}" >&2
fi

echo "${APP_DIR}"
