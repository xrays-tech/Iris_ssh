#!/usr/bin/env bash
# case_backend_lost.sh — backend-death injection (plan M2-U2/U5). Self-contained:
# it spins its OWN local backend sshd + mock control plane + gateway (subtopo.sh),
# opens a live session THROUGH the gateway to that backend, then kills the backend
# (lsof-scoped, privilege-free — the macOS/iOS substitute for iptables DROP). The
# gateway must detect the lost backend connection and (§3.8) send the client a
# protocol-level SSH_MSG_DISCONNECT with reason 11 and text
# "backend connection lost, please retry", NOT silently hang the client.
#
# Asserts: client receives the goodbye message / clean close (no hang),
# `sshgw_backend_lost_total` increments, `sshgw_disconnect_reason_total{reason=11}`
# appears, and the gateway stays alive. Because the sub-topology is throwaway and
# self-contained, this runs in LOCAL *and* REMOTE modes; it never touches the
# shared backend or SSH_GW_ASSET_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"

trap subtopo_stop EXIT INT TERM

subtopo_start

mval() { subtopo_metric "$1" | awk '{print $2}'; }
b0="$(mval 'sshgw_backend_lost_total')"; b0="${b0:-0}"

# Open a long-lived session (channel open keeps the down-pump reading the backend).
subtopo_ssh 'sleep 60' </dev/null >"$IT_WORK_DIR/bl.out" 2>"$IT_WORK_DIR/bl.err" &
C=$!
# Wait for the gateway->backend connection to be established on our backend port.
est=0
for _ in $(seq 1 50); do
  if lsof -nP -iTCP:"$ST_SSHD_PORT" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $1 ~ /sshd/ {found=1} END{exit !found}'; then
    est=1; break
  fi
  kill -0 "$C" 2>/dev/null || break
  sleep 0.2
done
sleep 0.5
if [ "$est" != "1" ] || ! kill -0 "$C" 2>/dev/null; then
  kill "$C" 2>/dev/null || true
  fail "gateway->backend session did not establish before injection"
fi
pass "live gateway->backend session established (client pid $C)"

# --- INJECT: drop the backend connection (privilege-free DROP substitute) ---
log "injecting backend loss: killing sub-topology backend (port $ST_SSHD_PORT)..."
subtopo_kill_backend

# Poll (bounded) for the gateway to detect it.
det=0
for _ in $(seq 1 100); do
  v="$(mval 'sshgw_backend_lost_total')"; v="${v:-0}"
  if [ "$v" -ge 1 ]; then det=1; break; fi
  kill -0 "$C" 2>/dev/null || break
  sleep 0.2
done

# The client must exit (no hang), bounded wait.
crc="NA"; alive=0
for _ in $(seq 1 50); do
  if ! kill -0 "$C" 2>/dev/null; then break; fi
  sleep 0.2
done
if kill -0 "$C" 2>/dev/null; then
  alive=1; kill -9 "$C" 2>/dev/null || true
else
  wait "$C" 2>/dev/null || crc=$?
fi

# --- Assertions ---
b1="$(mval 'sshgw_backend_lost_total')"; b1="${b1:-0}"
if [ "$det" = "1" ] || [ "$b1" -ge $((b0 + 1)) ]; then
  pass "gateway detected backend loss (sshgw_backend_lost_total: $b0 -> $b1)"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "gateway did NOT increment backend_lost_total (still $b1)"
fi

dr="$(subtopo_metric 'sshgw_disconnect_reason_total\{reason="11"\}')"
case "${dr:-}" in
  *'"11"'*) pass "disconnect_reason{reason=11} present: $dr" ;;
  *) fail "expected disconnect_reason{reason=11}, got: [${dr:-<none>}]" ;;
esac

if [ "$alive" = "1" ]; then
  fail "client HUNG (no clean close) after backend loss — expected a DISCONNECT"
fi
combined="$(cat "$IT_WORK_DIR/bl.err" 2>/dev/null)$(cat "$IT_WORK_DIR/bl.out" 2>/dev/null)"
assert_contains "$combined" "backend connection lost" "client received goodbye message"
log "client goodbye line: $(grep -im1 'backend connection lost' "$IT_WORK_DIR/bl.err" 2>/dev/null || echo '(in output)') ; client rc=$crc"

if pid_alive "$ST_GW_PID"; then pass "gateway process alive after backend loss ($ST_GW_PID)"; else fail "gateway process died"; fi
echo "OK: case_backend_lost"
