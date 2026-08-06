#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRODUCT_NAME="玥球电梯"
APP_NAME="${PRODUCT_NAME}.app"
DIST="${ROOT}/dist"
STAGING="${DIST}/dmg-root"
MOUNT_DIR="/Volumes/${PRODUCT_NAME}"
RW_DMG="${DIST}/${PRODUCT_NAME}.rw.dmg"
DMG_PATH="${DIST}/${PRODUCT_NAME}.dmg"
BACKGROUND="${ROOT}/Resources/DMGBackground.png"
ATTACH_INFO="${DIST}/dmg-attach.plist"
PYTHON="${PYTHON:-python3}"
NOTARIZE="${NOTARIZE:-0}"
NOTARY_PROFILE="${NOTARY_PROFILE:-}"
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"

if ! "${PYTHON}" -c 'import PIL, ds_store, mac_alias' >/dev/null 2>&1; then
  echo "DMG build requires Pillow, ds-store, and mac-alias; install Scripts/requirements-dmg.txt in a Python environment and set PYTHON=/path/to/python" >&2
  exit 1
fi

cleanup() {
  if mount | grep -Fq "${MOUNT_DIR}"; then
    hdiutil detach "${MOUNT_DIR}" -force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cd "${ROOT}"
"${PYTHON}" "${ROOT}/Scripts/generate_dmg_assets.py" >&2
APP_PATH="$("${ROOT}/Scripts/build_app.sh")"

cleanup
rm -rf "${STAGING}" "${RW_DMG}" "${DMG_PATH}" "${ATTACH_INFO}"
mkdir -p "${STAGING}"

hdiutil create \
  -size 128m \
  -fs HFS+ \
  -volname "${PRODUCT_NAME}" \
  "${RW_DMG}" >/dev/null

hdiutil attach "${RW_DMG}" \
  -readwrite \
  -noverify \
  -noautoopen \
  -plist > "${ATTACH_INFO}"
MOUNT_DIR="$(
  "${PYTHON}" - "${ATTACH_INFO}" <<'PY'
import plistlib
import sys
with open(sys.argv[1], "rb") as handle:
    plist = plistlib.load(handle)
for entity in plist.get("system-entities", []):
    mount_point = entity.get("mount-point")
    if mount_point:
        print(mount_point)
        break
else:
    raise SystemExit("No mount point in hdiutil attach plist")
PY
)"

cp -R "${APP_PATH}" "${MOUNT_DIR}/${APP_NAME}"
mkdir -p "${MOUNT_DIR}/.background"
cp "${BACKGROUND}" "${MOUNT_DIR}/.background/DMGBackground.png"
ln -s /Applications "${MOUNT_DIR}/Applications"
chflags hidden "${MOUNT_DIR}/.background" 2>/dev/null || true

"${PYTHON}" "${ROOT}/Scripts/write_dmg_dsstore.py" "${MOUNT_DIR}" "${PRODUCT_NAME}" >&2

sync
hdiutil detach "${MOUNT_DIR}" >/dev/null || hdiutil detach "${MOUNT_DIR}" -force >/dev/null
hdiutil convert "${RW_DMG}" \
  -format UDZO \
  -imagekey zlib-level=9 \
  -o "${DMG_PATH}" >/dev/null
rm -f "${RW_DMG}"

if [[ "${NOTARIZE}" == "1" ]]; then
  if [[ "${CODESIGN_IDENTITY}" == "-" ]]; then
    echo "NOTARIZE=1 requires a Developer ID CODESIGN_IDENTITY; ad-hoc signatures cannot be notarized" >&2
    exit 1
  fi
  if [[ -z "${NOTARY_PROFILE}" ]]; then
    echo "NOTARIZE=1 requires NOTARY_PROFILE created with xcrun notarytool store-credentials" >&2
    exit 1
  fi
  if ! command -v xcrun >/dev/null 2>&1; then
    echo "NOTARIZE=1 requires xcrun" >&2
    exit 1
  fi
  xcrun notarytool submit "${DMG_PATH}" \
    --keychain-profile "${NOTARY_PROFILE}" \
    --wait >&2
  xcrun stapler staple "${DMG_PATH}" >&2
  xcrun stapler validate "${DMG_PATH}" >&2
fi

echo "${DMG_PATH}"
