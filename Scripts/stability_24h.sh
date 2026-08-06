#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/release/supercore}"
CONFIG="${SUPERCORE_STABILITY_CONFIG:-${ROOT}/Supercore/supercore.example.yaml}"
DURATION_SECS="${1:-86400}"
SAMPLE_SECS="${SUPERCORE_STABILITY_SAMPLE_SECS:-30}"
CONTROL_PORT="${SUPERCORE_STABILITY_CONTROL_PORT:-19198}"
MIXED_PORT="${SUPERCORE_STABILITY_MIXED_PORT:-17898}"
CONTROL_URL="${SUPERCORE_STABILITY_CONTROL_URL:-http://127.0.0.1:${CONTROL_PORT}}"

if ! [[ "${DURATION_SECS}" =~ ^[0-9]+$ ]] || (( DURATION_SECS < 1 )); then
  echo "duration must be a positive integer number of seconds" >&2
  exit 2
fi
if ! [[ "${SAMPLE_SECS}" =~ ^[0-9]+$ ]] || (( SAMPLE_SECS < 1 )); then
  echo "SUPERCORE_STABILITY_SAMPLE_SECS must be a positive integer" >&2
  exit 2
fi
if [[ ! -x "${CORE}" ]]; then
  cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi

WORK_DIR="$(mktemp -d /tmp/skyhook-stability.XXXXXX)"
LOG_FILE="${WORK_DIR}/supercore.log"
METRICS_FILE="${WORK_DIR}/metrics.tsv"
RUNTIME_CONFIG="${WORK_DIR}/supercore.yaml"
PID=""
BASE_RSS_KB=""
MAX_RSS_KB=0
CLEANUP_DONE=0

terminate_process_tree() {
  local pid="$1" signal="$2" child
  while read -r child; do
    [[ -n "$child" ]] || continue
    terminate_process_tree "$child" "$signal"
  done < <(pgrep -P "$pid" 2>/dev/null || true)
  kill "-${signal}" "$pid" 2>/dev/null || true
}

process_state() {
  ps -o state= -p "$1" 2>/dev/null | tr -d '[:space:]' || true
}

wait_for_process_exit() {
  local pid="$1" tenths="$2" state
  for ((i = 0; i < tenths; i++)); do
    kill -0 "$pid" 2>/dev/null || return 0
    state="$(process_state "$pid")"
    [[ "$state" == Z* ]] && return 0
    sleep 0.1
  done
  return 1
}

stop_core() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null || return 0
  terminate_process_tree "$pid" TERM
  if ! wait_for_process_exit "$pid" 40; then
    terminate_process_tree "$pid" KILL
    if ! wait_for_process_exit "$pid" 30; then
      echo "ERROR: core pid ${pid} did not exit after SIGTERM/SIGKILL" >&2
      return 1
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  if (( CLEANUP_DONE == 1 )); then
    return
  fi
  CLEANUP_DONE=1
  trap - EXIT INT TERM
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    stop_core "${PID}" || true
  fi
  PID=""
  if [[ "${KEEP_STABILITY_LOG:-0}" != "1" ]]; then
    find "${WORK_DIR}" -type f -delete 2>/dev/null || true
    rmdir "${WORK_DIR}" 2>/dev/null || true
  else
    echo "stability log: ${LOG_FILE}"
  fi
}
on_signal() {
  local exit_code="$1"
  cleanup
  exit "$exit_code"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

prepare_isolated_config() {
  python3 - "${CONFIG}" "${RUNTIME_CONFIG}" "${CONTROL_URL}" "${MIXED_PORT}" <<'PY'
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

source, target, control_url, mixed_port = sys.argv[1:]
parsed = urlparse(control_url)
if parsed.port is None:
    raise SystemExit(f"control URL must include a port: {control_url}")

lines = Path(source).read_text(encoding="utf-8").splitlines(keepends=True)
output = []
mixed_changed = False
control_changed = False
for line in lines:
    if re.match(r"^\s+mixed_listen:\s*", line) and not mixed_changed:
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        output.append(f"{indent}mixed_listen: 127.0.0.1:{mixed_port}\n")
        mixed_changed = True
    elif re.match(r"^\s+control_listen:\s*", line) and not control_changed:
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        output.append(f"{indent}control_listen: 127.0.0.1:{parsed.port}\n")
        control_changed = True
    else:
        output.append(line)
if not mixed_changed or not control_changed:
    raise SystemExit("config is missing core.mixed_listen or core.control_listen")
Path(target).write_text("".join(output), encoding="utf-8")
PY
}

cd "${WORK_DIR}"
prepare_isolated_config
"${CORE}" check -c "${RUNTIME_CONFIG}" >/dev/null
printf 'sample\telapsed_s\trss_kb\tstatus_bytes\n' >"${METRICS_FILE}"
"${CORE}" run -c "${RUNTIME_CONFIG}" >"${LOG_FILE}" 2>&1 &
PID=$!

ready=0
for _ in {1..60}; do
  if ! kill -0 "${PID}" 2>/dev/null; then
    echo "Supercore exited before health became ready" >&2
    cat "${LOG_FILE}" >&2
    exit 1
  fi
  if curl --noproxy '*' --fail --silent --max-time 3 "${CONTROL_URL}/health" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.5
done
if (( ready == 0 )); then
  echo "Supercore health endpoint did not become ready" >&2
  cat "${LOG_FILE}" >&2
  exit 1
fi

deadline=$((SECONDS + DURATION_SECS))
samples=0
while (( SECONDS < deadline )); do
  if ! kill -0 "${PID}" 2>/dev/null; then
    echo "Supercore exited during stability run after ${samples} samples" >&2
    cat "${LOG_FILE}" >&2
    exit 1
  fi
  curl --noproxy '*' --fail --silent --max-time 3 "${CONTROL_URL}/health" >/dev/null
  status_body="$(curl --noproxy '*' --fail --silent --max-time 3 "${CONTROL_URL}/v1/status")"
  rss_kb="$(ps -o rss= -p "${PID}" | tr -d ' ' || true)"
  [[ "${rss_kb}" =~ ^[0-9]+$ ]] || rss_kb=0
  status_bytes="$(printf '%s' "${status_body}" | wc -c | tr -d ' ')"
  elapsed=$((SECONDS))
  if [[ -z "${BASE_RSS_KB}" ]]; then
    BASE_RSS_KB="${rss_kb}"
  fi
  (( rss_kb > MAX_RSS_KB )) && MAX_RSS_KB="${rss_kb}"
  samples=$((samples + 1))
  printf '%s\t%s\t%s\t%s\n' "${samples}" "${elapsed}" "${rss_kb}" "${status_bytes}" >>"${METRICS_FILE}"
  remaining=$((deadline - SECONDS))
  sleep "$((remaining < SAMPLE_SECS ? remaining : SAMPLE_SECS))"
done

RSS_GROWTH_KB=$((MAX_RSS_KB - ${BASE_RSS_KB:-0}))
echo "stability run passed: duration=${DURATION_SECS}s samples=${samples} base_rss_kb=${BASE_RSS_KB:-0} peak_rss_kb=${MAX_RSS_KB} rss_growth_kb=${RSS_GROWTH_KB}"
if [[ "${KEEP_STABILITY_LOG:-0}" == "1" ]]; then
  echo "stability metrics: ${METRICS_FILE}"
fi
