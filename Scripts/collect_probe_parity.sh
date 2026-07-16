#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  Scripts/collect_probe_parity.sh --supercore-config <path> --external-base-url <url> --external-secret <secret> [options]

必需参数:
  --supercore-config      Supercore 配置文件路径
  --external-base-url     Mihomo/Sparkle external-controller URL，如 http://127.0.0.1:9090
  --external-secret       external-controller secret

可选参数:
  --supercore-output      Supercore 导出文件路径（默认: /tmp/supercore-probe.json）
  --external-output       外部导出文件路径（默认: /tmp/sparkle-probe.json）
  --names                 节点名文件（与两端共用，逐行一个 name）
  --timeout-ms            超时毫秒（默认: 500）
  --url                   Probe URL（默认: http://www.gstatic.com/generate_204）
  --max-workers           外部探测并发（默认: 32）
  --top                   对比报告 topN（默认: 20）
  --skip-compare          仅采样不对比

示例:
  Scripts/collect_probe_parity.sh \
    --supercore-config Supercore/supercore.example.yaml \
    --external-base-url http://127.0.0.1:9191 \
    --external-secret test-secret \
    --names /tmp/supercore-names.txt \
    --timeout-ms 500 \
    --url http://www.gstatic.com/generate_204
USAGE
}

SUPERCORE_CONFIG=""
EXTERNAL_BASE_URL=""
EXTERNAL_SECRET=""
SUPERCORE_OUTPUT="/tmp/supercore-probe.json"
EXTERNAL_OUTPUT="/tmp/sparkle-probe.json"
NAMES_FILE=""
TIMEOUT_MS=500
PROBE_URL="http://www.gstatic.com/generate_204"
MAX_WORKERS=32
TOP=20
SKIP_COMPARE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --supercore-config)
      SUPERCORE_CONFIG="$2"
      shift 2
      ;;
    --external-base-url)
      EXTERNAL_BASE_URL="$2"
      shift 2
      ;;
    --external-secret)
      EXTERNAL_SECRET="$2"
      shift 2
      ;;
    --supercore-output)
      SUPERCORE_OUTPUT="$2"
      shift 2
      ;;
    --external-output)
      EXTERNAL_OUTPUT="$2"
      shift 2
      ;;
    --names)
      NAMES_FILE="$2"
      shift 2
      ;;
    --timeout-ms)
      TIMEOUT_MS="$2"
      shift 2
      ;;
    --url)
      PROBE_URL="$2"
      shift 2
      ;;
    --max-workers)
      MAX_WORKERS="$2"
      shift 2
      ;;
    --top)
      TOP="$2"
      shift 2
      ;;
    --skip-compare)
      SKIP_COMPARE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SUPERCORE_CONFIG" || -z "$EXTERNAL_BASE_URL" || -z "$EXTERNAL_SECRET" ]]; then
  echo "Missing required arguments" >&2
  usage
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "[1/2] Supercore probe..."
SUPERCORE_CMD=(cargo run --quiet --manifest-path Supercore/Cargo.toml -- probe -c "$SUPERCORE_CONFIG" --timeout-ms "$TIMEOUT_MS" --url "$PROBE_URL")
if [[ -n "$NAMES_FILE" ]]; then
  SUPERCORE_CMD+=(--names "$NAMES_FILE")
fi
"${SUPERCORE_CMD[@]}" > "$SUPERCORE_OUTPUT"

echo "[2/2] External controller probe..."
EXTERNAL_CMD=(python3 Scripts/export_mihomo_probe.py --base-url "$EXTERNAL_BASE_URL" --secret "$EXTERNAL_SECRET" --timeout-ms "$TIMEOUT_MS" --url "$PROBE_URL" --output "$EXTERNAL_OUTPUT" --max-workers "$MAX_WORKERS")
if [[ -n "$NAMES_FILE" ]]; then
  EXTERNAL_CMD+=(--names "$NAMES_FILE")
fi
"${EXTERNAL_CMD[@]}"

echo "[3/3] Compare..."
if [[ "$SKIP_COMPARE" -eq 1 ]]; then
  echo "Skip compare by request."
  echo "Supercore sample: $SUPERCORE_OUTPUT"
  echo "External sample: $EXTERNAL_OUTPUT"
  exit 0
fi

python3 Scripts/compare_probe_results.py --supercore "$SUPERCORE_OUTPUT" --external "$EXTERNAL_OUTPUT" --top "$TOP"
echo "Supercore sample: $SUPERCORE_OUTPUT"
echo "External sample: $EXTERNAL_OUTPUT"
