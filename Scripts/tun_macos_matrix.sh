#!/usr/bin/env bash
set -euo pipefail

# Destructive system-network checks are opt-in. The default command only prints
# the prerequisites so an accidental invocation cannot change the host routes.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="${SUPERCORE_BINARY:-${ROOT}/Supercore/target/release/supercore}"
CONFIG="${SUPERCORE_TUN_MATRIX_CONFIG:-${ROOT}/Supercore/supercore.example.yaml}"
CONTROL_PORT="${SUPERCORE_TUN_MATRIX_CONTROL_PORT:-19197}"
CONTROL_URL="${SUPERCORE_TUN_MATRIX_CONTROL_URL:-http://127.0.0.1:${CONTROL_PORT}}"
MIXED_PORT="${SUPERCORE_TUN_MATRIX_MIXED_PORT:-17897}"
TOKEN="${SKYHOOK_CONTROL_TOKEN:-}"
WITH_TUN=0
ROOT_MODE=0
ALLOW_ROUTE_CHANGES=0
KEEP_ARTIFACTS=0
CLEANUP_DONE=0

usage() {
  cat <<'USAGE'
Usage:
  Scripts/tun_macos_matrix.sh --with-tun --root [options]

This is an operator-assisted macOS TUN lifecycle matrix. It records route,
DNS, proxy, and interface snapshots, then verifies:
  - disabled -> starting -> running -> disabled through /v1/config/reload
  - normal core termination
  - forced core termination and resource cleanup

Options:
  --with-tun             opt into creating a real utun device
  --root                run Supercore through sudo -n (requires sudo -v first)
  --allow-route-changes allow a config whose TUN setup/auto-route is enabled
  --core <path>         release Supercore binary
  --config <path>       config with a disabled TUN section
  --control-url <url>   control API base URL (default: http://127.0.0.1:19197)
  --mixed-port <port>   isolated local mixed port (default: 17897)
  --token <token>       control token; otherwise a random test token is used
  --keep-artifacts      retain snapshots and core log under /tmp
  -h, --help            show this help

Exit 77 means the matrix was intentionally skipped because the machine lacks
the required administrator authorization. No user subscription data is read.
USAGE
}

die() { echo "ERROR: $*" >&2; exit 1; }
skip() { echo "SKIP: $*" >&2; exit 77; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-tun) WITH_TUN=1; shift ;;
    --root) ROOT_MODE=1; shift ;;
    --allow-route-changes) ALLOW_ROUTE_CHANGES=1; shift ;;
    --core) CORE="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --control-url) CONTROL_URL="$2"; shift 2 ;;
    --mixed-port) MIXED_PORT="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --keep-artifacts) KEEP_ARTIFACTS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "this matrix is only supported on macOS"
[[ -f "$CONFIG" ]] || die "config not found: $CONFIG"
if [[ ! -x "$CORE" ]]; then
  cargo build --release --manifest-path "${ROOT}/Supercore/Cargo.toml"
fi
[[ -x "$CORE" ]] || die "Supercore binary is not executable: $CORE"

if (( WITH_TUN == 0 )); then
  echo "TUN matrix is opt-in. Re-run with --with-tun --root after reviewing the config."
  echo "config=${CONFIG}"
  echo "core=${CORE}"
  exit 0
fi
if (( ROOT_MODE == 0 )); then
  skip "real TUN requires --root; no system changes were attempted"
fi
if ! sudo -n true 2>/dev/null; then
  skip "sudo authorization is not cached; run sudo -v once, then rerun this matrix"
fi

if (( ALLOW_ROUTE_CHANGES == 0 )); then
  if grep -Eq '^[[:space:]]+(setup|auto_route):[[:space:]]*(true|yes|on)[[:space:]]*(#.*)?$' "$CONFIG"; then
    die "config enables route setup; pass --allow-route-changes only after reviewing it"
  fi
fi

if [[ -z "$TOKEN" ]]; then
  TOKEN="$(/usr/bin/openssl rand -hex 32)"
fi
(( ${#TOKEN} >= 32 )) || die "control token must contain at least 32 bytes"

WORK_DIR="$(mktemp -d /tmp/skyhook-tun-matrix.XXXXXX)"
CORE_LOG="${WORK_DIR}/supercore.log"
DISABLED_CONFIG="${WORK_DIR}/disabled.yaml"
ENABLED_CONFIG="${WORK_DIR}/enabled.yaml"
PID=""

cleanup() {
  if (( CLEANUP_DONE == 1 )); then
    return
  fi
  CLEANUP_DONE=1
  trap - EXIT INT TERM
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    stop_core "$PID" TERM
  fi
  PID=""
  if (( KEEP_ARTIFACTS == 0 )); then
    rm -rf "$WORK_DIR"
  else
    echo "matrix artifacts: $WORK_DIR"
  fi
}
on_signal() {
  local status="$1"
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

toggle_tun() {
  local source="$1" target="$2" value="$3"
  python3 - "$source" "$target" "$value" <<'PY'
import pathlib
import re
import sys

source, target, value = sys.argv[1:]
lines = pathlib.Path(source).read_text(encoding="utf-8").splitlines(keepends=True)
inside = False
tun_indent = None
changed = False
output = []
for line in lines:
    match = re.match(r"^(\s*)tun:\s*(?:#.*)?$", line.rstrip("\n"))
    if match:
        inside = True
        tun_indent = len(match.group(1).replace("\t", "    "))
        output.append(line)
        continue
    if inside and line.strip() and not line.lstrip().startswith("#"):
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= tun_indent:
            inside = False
    if inside and re.match(r"^\s+enabled:\s*", line):
        newline = "true" if value == "true" else "false"
        ending = "\n" if line.endswith("\n") else ""
        comment = ""
        if "#" in line:
            comment = "  " + line.split("#", 1)[1].rstrip("\n").strip()
            comment = " # " + comment
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        output.append(f"{indent}enabled: {newline}{comment}{ending}")
        changed = True
    else:
        output.append(line)
if not changed:
    raise SystemExit("could not find tun.enabled in config")
pathlib.Path(target).write_text("".join(output), encoding="utf-8")
PY
}

snapshot() {
  local label="$1"
  {
    echo "=== ${label} $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
    echo "-- interfaces --"
    /sbin/ifconfig -l || true
    echo "-- default route --"
    /sbin/route -n get default 2>&1 || true
    echo "-- IPv4 routes --"
    /usr/sbin/netstat -rn -f inet 2>&1 || true
    echo "-- DNS --"
    /usr/sbin/scutil --dns 2>&1 || true
    echo "-- system proxy --"
    /usr/sbin/scutil --proxy 2>&1 || true
  } >"${WORK_DIR}/${label}.snapshot"
}

interfaces() { /sbin/ifconfig -l | tr ' ' '\n' | sed '/^$/d' | sort; }
tun_interfaces() { interfaces | awk '/^(utun|tun)[0-9]+$/' || true; }

terminate_process_tree() {
  local pid="$1" signal="$2" child
  for child in $(pgrep -P "$pid" 2>/dev/null || true); do
    terminate_process_tree "$child" "$signal"
  done
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
  local pid="$1" signal="${2:-TERM}"
  kill -0 "$pid" 2>/dev/null || return 0
  if [[ "$signal" == "KILL" ]]; then
    terminate_process_tree "$pid" KILL
    if ! wait_for_process_exit "$pid" 30; then
      echo "ERROR: core pid ${pid} did not exit after SIGKILL" >&2
      return 1
    fi
  else
    terminate_process_tree "$pid" TERM
    if ! wait_for_process_exit "$pid" 40; then
      terminate_process_tree "$pid" KILL
      if ! wait_for_process_exit "$pid" 30; then
        echo "ERROR: core pid ${pid} did not exit after SIGTERM/SIGKILL" >&2
        return 1
      fi
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

api_get() {
  curl --noproxy '*' --fail --silent --show-error --max-time 5 \
    -H "Authorization: Bearer ${TOKEN}" "${CONTROL_URL%/}$1"
}

api_reload() {
  local yaml="$1"
  python3 - "$yaml" <<'PY' | curl --noproxy '*' --fail --silent --show-error --max-time 10 \
      -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" \
      -X POST -d @- "${CONTROL_URL%/}/v1/config/reload" >/dev/null
import json
import pathlib
import sys
print(json.dumps({"yaml": pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")}))
PY
}

wait_state() {
  local expected="$1"
  for _ in {1..120}; do
    local body state
    body="$(api_get /v1/tun 2>/dev/null || true)"
    state="$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("runtime",{}).get("state", ""))' 2>/dev/null || true)"
    if [[ "$state" == "$expected" ]]; then
      printf '%s\n' "$body"
      return 0
    fi
    if [[ "$state" == "failed" ]]; then
      echo "$body" >&2
      return 1
    fi
    sleep 0.25
  done
  echo "timed out waiting for TUN state=${expected}" >&2
  api_get /v1/tun >&2 || true
  return 1
}

start_core() {
  if (( ROOT_MODE == 1 )); then
    ( cd "$WORK_DIR" && exec sudo -n -E env SKYHOOK_CONTROL_TOKEN="$TOKEN" RUST_LOG=supercore=info,info \
      "$CORE" run -c "$1" ) >"$CORE_LOG" 2>&1 &
  else
    ( cd "$WORK_DIR" && exec env SKYHOOK_CONTROL_TOKEN="$TOKEN" RUST_LOG=supercore=info,info \
      "$CORE" run -c "$1" ) >"$CORE_LOG" 2>&1 &
  fi
  PID=$!
  for _ in {1..60}; do
    kill -0 "$PID" 2>/dev/null || { cat "$CORE_LOG" >&2; return 1; }
    if curl --noproxy '*' --fail --silent --max-time 2 "${CONTROL_URL%/}/health" >/dev/null &&
      api_get /v1/tun >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  cat "$CORE_LOG" >&2
  return 1
}

toggle_tun "$CONFIG" "$DISABLED_CONFIG" false
toggle_tun "$CONFIG" "$ENABLED_CONFIG" true

isolate_ports() {
  local path="$1"
  python3 - "$path" "$CONTROL_URL" "$MIXED_PORT" <<'PY'
from pathlib import Path
import sys
from urllib.parse import urlparse

path, control_url, mixed_port = sys.argv[1:]
parsed = urlparse(control_url)
control_port = parsed.port
if control_port is None:
    raise SystemExit(f"control URL must include a port: {control_url}")
lines = Path(path).read_text(encoding="utf-8").splitlines(keepends=True)
output = []
mixed_changed = False
control_changed = False
for line in lines:
    if line.lstrip().startswith("mixed_listen:"):
        indent = line[: len(line) - len(line.lstrip())]
        output.append(f"{indent}mixed_listen: 127.0.0.1:{mixed_port}\n")
        mixed_changed = True
    elif line.lstrip().startswith("control_listen:"):
        indent = line[: len(line) - len(line.lstrip())]
        output.append(f"{indent}control_listen: 127.0.0.1:{control_port}\n")
        control_changed = True
    else:
        output.append(line)
if not mixed_changed or not control_changed:
    raise SystemExit("config is missing mixed_listen or control_listen")
Path(path).write_text("".join(output), encoding="utf-8")
PY
}

isolate_ports "$DISABLED_CONFIG"
isolate_ports "$ENABLED_CONFIG"
"$CORE" check -c "$DISABLED_CONFIG" >/dev/null
"$CORE" check -c "$ENABLED_CONFIG" >/dev/null

snapshot before
BASE_TUN="$(tun_interfaces)"
start_core "$DISABLED_CONFIG"
initial="$(api_get /v1/tun)"
initial_state="$(printf '%s' "$initial" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("runtime",{}).get("state", ""))')"
[[ "$initial_state" == "disabled" ]] || die "core did not start with TUN disabled: $initial"

api_reload "$ENABLED_CONFIG"
running="$(wait_state running)"
NEW_TUN="$(comm -13 <(printf '%s\n' "$BASE_TUN") <(tun_interfaces))"
[[ -n "$NEW_TUN" ]] || die "TUN reported running but no new utun/tun interface appeared"
echo "dynamic_start=ok interfaces=${NEW_TUN//$'\n'/,}"

api_reload "$DISABLED_CONFIG"
wait_state disabled >/dev/null
sleep 1
if [[ -n "$(comm -13 <(printf '%s\n' "$BASE_TUN") <(tun_interfaces))" ]]; then
  die "TUN interface remained after dynamic stop"
fi
echo "dynamic_stop=ok"

stop_core "$PID" TERM
PID=""
echo "normal_exit=ok"

start_core "$DISABLED_CONFIG"
api_reload "$ENABLED_CONFIG"
wait_state running >/dev/null
stop_core "$PID" KILL
PID=""
sleep 2
if [[ -n "$(comm -13 <(printf '%s\n' "$BASE_TUN") <(tun_interfaces))" ]]; then
  die "TUN interface remained after forced core termination"
fi
echo "forced_exit_cleanup=ok"

snapshot after
echo "TUN macOS matrix passed"
