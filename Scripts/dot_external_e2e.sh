#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/release/supercore}"
DOT_HOST="${1:-8.8.8.8}"
DOT_SNI="${2:-dns.google}"
DOT_MIXED_PORT="${SUPERCORE_DOT_MIXED_PORT:-17897}"
CONTROL_PORT="${SUPERCORE_DOT_CONTROL_PORT:-9297}"
DNS_PORT="${SUPERCORE_DOT_DNS_PORT:-15353}"

if [[ ! -x "${CORE}" ]]; then
  cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi
command -v dig >/dev/null 2>&1 || {
  echo "dot e2e requires dig" >&2
  exit 2
}

WORK_DIR="$(mktemp -d /tmp/skyhook-dot-e2e.XXXXXX)"
CONFIG="${WORK_DIR}/dot.yaml"
LOG_FILE="${WORK_DIR}/core.log"
PID=""

cleanup() {
  if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
    kill -TERM "${PID}" 2>/dev/null || true
    for _ in {1..30}; do
      kill -0 "${PID}" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "${PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

cp "${ROOT}/Supercore/supercore.example.yaml" "${CONFIG}"
python3 - "${CONFIG}" "${DOT_HOST}" "${DOT_SNI}" "${DOT_MIXED_PORT}" "${CONTROL_PORT}" "${DNS_PORT}" <<'PY'
from pathlib import Path
import sys

path, host, sni, mixed_port, control_port, dns_port = sys.argv[1:]
config = Path(path).read_text()
config = config.replace(
    "  mixed_listen: 127.0.0.1:7897\n",
    f"  mixed_listen: 127.0.0.1:{mixed_port}\n",
)
config = config.replace(
    "  control_listen: 127.0.0.1:9197\n",
    f"  control_listen: 127.0.0.1:{control_port}\n",
)
config = config.replace(
    "  hijack_udp_53: true\n",
    "  hijack_udp_53: false\n"
    f"  listen: 127.0.0.1:{dns_port}\n"
    "  enhanced_mode: redir-host\n"
    "  nameserver:\n"
    f"    - tls://{host}:853?sni={sni}\n",
)
config = config.replace("  update_on_start: true\n", "  update_on_start: false\n")
config = config.replace("  auto_update: true\n", "  auto_update: false\n")
Path(path).write_text(config)
PY

"${CORE}" run -c "${CONFIG}" >"${LOG_FILE}" 2>&1 &
PID=$!
ready=0
for _ in {1..60}; do
  if ! kill -0 "${PID}" 2>/dev/null; then
    cat "${LOG_FILE}" >&2
    exit 1
  fi
  if curl --noproxy '*' --fail --silent --max-time 2 \
    "http://127.0.0.1:${CONTROL_PORT}/health" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done
if (( ready == 0 )); then
  cat "${LOG_FILE}" >&2
  exit 1
fi

dig +tcp "@127.0.0.1" -p "${DNS_PORT}" example.com A +time=5 +tries=1
echo "external DoT E2E passed: ${DOT_HOST}:853 (SNI ${DOT_SNI})"
