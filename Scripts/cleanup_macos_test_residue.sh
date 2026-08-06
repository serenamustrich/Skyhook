#!/usr/bin/env bash
set -euo pipefail

# This command only targets the operator's temporary Skyhook TUN test tree.
# It never prompts for a password; a missing sudo cache is an intentional skip.
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: this cleanup command is only supported on macOS" >&2
  exit 1
fi

if ! sudo -n true 2>/dev/null; then
  echo "SKIP: sudo authorization is not cached; no test process was touched" >&2
  exit 77
fi

find_test_pids() {
  /bin/ps -axo user=,pid=,command= | /usr/bin/awk '
    $1 == "root" &&
    ($0 ~ /\/tmp\/skyhook-tun-matrix-trace\.sh/ ||
     $0 ~ /\/tmp\/skyhook-supercore-matrix( |$)/) { print $2 }
  '
}

wait_for_exit() {
  local pid="$1"
  for _ in {1..40}; do
    sudo -n /bin/kill -0 "$pid" 2>/dev/null || return 0
    /bin/sleep 0.1
  done
  return 1
}

pids="$(find_test_pids)"
if [[ -z "$pids" ]]; then
  echo "no Skyhook TUN test residue found"
  exit 0
fi

echo "stopping Skyhook TUN test residue: $(tr '\n' ' ' <<<"$pids")"
# Do not use a shell-expanded untrusted command string; each PID is numeric
# output from ps and is passed as an individual sudo argument.
while read -r pid; do
  [[ "$pid" =~ ^[0-9]+$ ]] || continue
  sudo -n /bin/kill -TERM "$pid" 2>/dev/null || true
done <<<"$pids"

for pid in $pids; do
  if ! wait_for_exit "$pid"; then
    sudo -n /bin/kill -KILL "$pid" 2>/dev/null || true
  fi
done

remaining="$(find_test_pids)"
if [[ -n "$remaining" ]]; then
  echo "ERROR: Skyhook TUN test residue remains: $(tr '\n' ' ' <<<"$remaining")" >&2
  exit 1
fi
echo "Skyhook TUN test residue cleanup passed"
