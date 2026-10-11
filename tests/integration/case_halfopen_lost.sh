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
BK_USER="${BK%@*}"
BK_REST="${BK#*@}"
BK_HOST="${BK_REST%:*}"
BACKEND_PORT="${BK_REST##*:}"; case "$BK_REST" in *:*) : ;; *) BACKEND_PORT="22" ;; esac
BK_LOGIN="${BK_USER}@${BK_HOST}"
KEY="$SSH_GW_ASSET_DIR/backend_ed25519"
INJECT="$HERE/../../scripts/halfopen_inject.sh"

# Config knobs for the acceptance formula (mirrors the gateway's [pool] keepalive
# the orchestrator wrote from the same env). Strip a trailing unit (e.g. 5s->5).
KA_INTERVAL="${HALFOPEN_KEEPALIVE_INTERVAL:-15s}"; KA_INTERVAL="${KA_INTERVAL%s}"
KA_MAX="${HALFOPEN_KEEPALIVE_MAX_MISS:-2}"
BUDGET=$(( KA_INTERVAL * (KA_MAX + 1) + 15 ))   # plan §4.1 formula + safety slack
# The DROP blocks ALL inbound :22 (incl. the management link), so it must persist
# past detection but self-clear soon after; the case waits for the self-clear
# before reconnecting. Default = detection window + 20s; override HALFOPEN_HOLD_SECS.
HOLD="${HALFOPEN_HOLD_SECS:-$((KA_INTERVAL * (KA_MAX + 1) + 20))}"

RS_OUT=""; RS_RC=0
remote_ssh() {  # remote_ssh <remote-shell-command> -> sets RS_OUT / RS_RC (never swallows errors)
  RS_RC=0
  RS_OUT="$(ssh -p "$BACKEND_PORT" -i "$KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
    "$BK_LOGIN" "$1" 2>&1)" || RS_RC=$?
}

mval() { python3 -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:${GW_METRICS_PORT}/metrics',timeout=4).read().decode())" 2>/dev/null | grep -E "$1"; }
mnum() { v="$(mval "$1" | awk '{print $2}')"; printf '%s' "${v:-0}"; }

# clean any stale rule from a previous aborted run (only our tagged chain)
bash "$INJECT" clean -t "$BK" -i "$KEY" >/dev/null 2>&1 || true

# (1) reachability/auth: an unreachable backend or unauthorized key is a real
#     harness/config error -> FAIL with the ssh error (never swallowed/skipped).
remote_ssh 'echo REACHED'
if [ "$RS_RC" -ne 0 ]; then
  printf '%s\n' "$RS_OUT" >&2
  fail "cannot ssh backend ${BK_LOGIN}:${BACKEND_PORT} with $KEY (rc=$RS_RC) — is the host reachable and $KEY in its authorized_keys?"
fi
# (2) capability: only a genuinely missing iptables is a SKIP.
remote_ssh 'command -v iptables >/dev/null 2>&1 && echo HAVE_IPTABLES'
printf '%s' "$RS_OUT" | grep -q HAVE_IPTABLES || skip_case "backend '${BK_LOGIN}' reachable but has no iptables (not the Linux test machine)"

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
  crc=0
  if kill -0 "$c" 2>/dev/null; then kill -9 "$c" 2>/dev/null || true; else wait "$c" 2>/dev/null || crc=$?; fi

  b1="$(mnum sshgw_backend_lost_total)"
  [ "$det" = "1" ] || { tail_log "$IT_WORK_DIR/ho.$1.err" 20; fail "(run $1) backend-lost NOT detected within ${BUDGET}s budget (interval=${KA_INTERVAL}s max=${KA_MAX})"; }
  pass "(run $1) half-open detected in <=${el}s (budget ${BUDGET}s); backend_lost_total $b0->$b1"
  dr="$(mval 'sshgw_disconnect_reason_total\{reason="11"\}')"
  case "$dr" in *'"11"'*) pass "(run $1) disconnect_reason{11} present: $dr" ;; *) fail "(run $1) disconnect_reason{11} missing: [${dr:-<none>}]" ;; esac
  assert_contains "$(cat "$IT_WORK_DIR/ho.$1.err" 2>/dev/null)" "backend connection lost" "(run $1) client goodbye (not a reset)"
  pid_alive "$GW_PID" && pass "(run $1) gateway alive after half-open" || fail "(run $1) gateway died"

  # Recover + reconnect. The DROP blocks ALL inbound :22 (incl. this management
  # link), so an explicit `recover` ssh cannot reach the backend while it is
  # active; we rely on the inject's scheduled self-clear (HOLD). Poll the backend
  # directly until the DROP lifts, then reconnect through the gateway.
  bash "$INJECT" recover -t "$BK" -i "$KEY" >/dev/null 2>&1 || true   # best-effort
  reach=0
  for _ in $(seq 1 $(( HOLD + 30 ))); do
    if remote_ssh 'true' >/dev/null 2>&1; then reach=1; break; fi
    sleep 1
  done
  [ "$reach" = "1" ] || { tail_log "$IT_WORK_DIR/ho.$1.err" 10; fail "(run $1) backend DROP did not self-clear within $((HOLD+30))s"; }
  log "(run $1) backend DROP self-cleared; reconnecting through the gateway"
  r=0
  ssh "${SSH_OPTS[@]}" "$TARGET" 'printf RECONNECT_OK' >"$IT_WORK_DIR/ho.$1.reconnect" 2>&1 || r=$?
  if [ "$r" -eq 0 ] && grep -q RECONNECT_OK "$IT_WORK_DIR/ho.$1.reconnect"; then
    pass "(run $1) gateway rebuilt a session after recover"
  else
    tail_log "$IT_WORK_DIR/ho.$1.reconnect" 12
    fail "(run $1) gateway could not reconnect after recover (rc=$r)"
  fi
}

n=1
while [ "$n" -le "$REPEAT" ]; do run_once "$n"; n=$((n+1)); done
echo "OK: case_halfopen_lost"
