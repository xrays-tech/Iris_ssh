#!/usr/bin/env bash
# case_halfopen_lost.sh — A1 half-open (half-closed) backend-loss injection via
# the real machine. macOS has no iptables, so this REQUIRES the Linux test backend
# (SSH_GW_BACKEND_TARGET set) where scripts/halfopen_inject.sh DROPs the
# gateway->backend SSH packets WITHOUT RST — a true half-open: the gateway keeps
# the socket but its keepalives are never answered, and russh declares the
# backend lost after ~ keepalive_interval x (keepalive_max_miss + 1).
#
# Acceptance (plan §4.1 A1): `sshgw_backend_lost_total` 0->1 AND
# `sshgw_disconnect_reason_total{reason="11"}` appear within
#   keepalive_interval x (keepalive_max_miss + 1)   (NOT fixed 25s/15s),
# the client receives a goodbye (not a reset), the gateway stays alive, and after
# recover a fresh session reconnects. Repeated >= 2x (HALFOPEN_REPEAT).
#
# Local capability probe: with no SSH_GW_BACKEND_TARGET (local mode) or without
# iptables on the backend, the case SKIPs (never a fake pass).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

[ -n "${SSH_GW_BACKEND_TARGET:-}" ] || skip_case "real-machine halfopen needs SSH_GW_BACKEND_TARGET (Linux backend); local mode uses case_backend_lost"
[ -n "${SSH_GW_ASSET_DIR:-}" ]     || skip_case "halfopen injection needs SSH_GW_ASSET_DIR (backend key for the real machine)"

BK="${SSH_GW_BACKEND_TARGET}"
BK_LOGIN="${BK%@*}"                       # user@host
BK_REST="${BK#*@}"
BACKEND_PORT="${BK_REST##*:}"; case "$BK_REST" in *:*) : ;; *) BACKEND_PORT="22" ;; esac
KEY="$SSH_GW_ASSET_DIR/backend_ed25519"
HOLD="${HALFOPEN_HOLD_SECS:-70}"
INJECT="$HERE/../../scripts/halfopen_inject.sh"

# Config knobs for the acceptance formula. Override via HALFOPEN_KEEPALIVE_* to
# match the gateway under test; defaults are the documented pool defaults.
KA_INTERVAL="${HALFOPEN_KEEPALIVE_INTERVAL:-15}"
KA_MAX="${HALFOPEN_KEEPALIVE_MAX_MISS:-2}"
BUDGET=$(( KA_INTERVAL * (KA_MAX + 1) + 15 ))   # plan §4.1 formula + safety slack

remote_ssh() {  # remote_ssh <remote-shell-command>
  ssh -p "$BACKEND_PORT" -i "$KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR "$BK_LOGIN" "$1"
}

mval() { python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:${GW_METRICS_PORT}/metrics',timeout=4).read().decode())" 2>/dev/null | grep -E "$1"; }
mnum() { v="$(mval "$1" | awk '{print $2}')"; printf '%s' "${v:-0}"; }

# clean any stale rule from a previous aborted run (only our tagged chain)
bash "$INJECT" clean -t "$BK" -i "$KEY" >/dev/null 2>&1 || true
# capability probe: does the backend have iptables?
if ! remote_ssh 'command -v iptables >/dev/null && echo yes' 2>/dev/null | grep -q yes; then
  skip_case "backend '$BK' has no iptables (not the Linux test machine)"
fi

REPEAT="${HALFOPEN_REPEAT:-2}"
run_once() {  # run_once <n>
  local b0 b1 dr cm msg rc
  b0="$(mnum sshgw_backend_lost_total)"
  # live session through the gateway to the real backend.
  ssh "${SSH_OPTS[@]}" "$TARGET" 'sleep 300' >"$IT_WORK_DIR/ho.$1.out" 2>"$IT_WORK_DIR/ho.$1.err" &
  local c=$!
  sleep 3
  kill -0 "$c" 2>/dev/null || { tail_log "$IT_WORK_DIR/ho.$1.err" 20; fail "(run $1) session did not establish"; }

  log "(run $1) injecting half-open (DROP, hold ${HOLD}s) on backend SSH port ${BACKEND_PORT}"
  bash "$HERE/../../scripts/halfopen_inject.sh" inject -t "$BK" -i "$KEY" --dport "$BACKEND_PORT" --hold "$HOLD" >"$IT_WORK_DIR/ho.inj.$1.log" 2>&1 || { tail_log "$IT_WORK_DIR/ho.inj.$1.log" 20; fail "(run $1) inject failed"; }

  # wait for detection within the keepalive budget.
  local det=0 el=0
  while [ "$el" -lt "$BUDGET" ]; do
    b1="$(mnum sshgw_backend_lost_total)"
    [ "$b1" -gt "$b0" ] && { det=1; break; }
    sleep 1; el=$((el+1))
  done
  # bounded wait for the client to receive the goodbye.
  for _ in $(seq 1 30); do kill -0 "$c" 2>/dev/null || break; sleep 0.2; done
  if kill -0 "$c" 2>/dev/null; then kill -9 "$c" 2>/dev/null; msg="(client HUNG)"; else wait "$c" 2>/dev/null; rc=$?; fi

  b1="$(mnum sshgw_backend_lost_total)"
  [ "$det" = "1" ] || { tail_log "$IT_WORK_DIR/ho.$1.err" 20; fail "(run $1) backend-lost NOT detected within ${BUDGET}s budget (interval=${KA_INTERVAL}s max=${KA_MAX})"; }
  pass "(run $1) half-open detected in <=${el}s (budget ${BUDGET}s); backend_lost_total $b0->$b1"
  dr="$(mval 'sshgw_disconnect_reason_total\{reason="11"\}')"
  case "$dr" in *'"11"'*) pass "(run $1) disconnect_reason{11} present: $dr" ;; *) fail "(run $1) disconnect_reason{11} missing: [${dr:-<none>}]" ;; esac
  assert_contains "$(cat "$IT_WORK_DIR/ho.$1.err" 2>/dev/null)" "backend connection lost" "(run $1) client goodbye (not a reset)"
  pid_alive "$GW_PID" && pass "(run $1) gateway alive after half-open" || fail "(run $1) gateway died"

  # recover, then prove reconnectics.
  bash "$HERE/../../scripts/halfopen_inject.sh" recover -t "$BK" -i "$KEY" >/dev/null 2>&1 || true
  r=0; ssh "${SSH_OPTS[@]}" "$TARGET" 'printf RECONNECT_OK' >/dev/null 2>&1 || r=$?
  [ "$r" -eq 0 ] && pass "(run $1) gateway rebuilt a session after recover" || fail "(run $1) gateway could not reconnect after recover (rc=$r)"
}

n=1
while [ "$n" -le "$REPEAT" ]; do run_once "$n"; n=$((n+1)); done
echo "OK: case_halfopen_lost"
