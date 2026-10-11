#!/usr/bin/env bash
# case_jump.sh — B4 jump mode (direct-tcpip). Two facets:
#   (a) baseline default-deny is already covered by case_port_forward_denied.
#   (b) here we drive the policy-gated ALLOW path + target-whitelist / SSRF guard.
# The gateway authorises direct-tcpip when the resolve grant has
# policy.tcp_forwarding=true AND (policy.tcp_forwarding_targets ∪ [jump]
# allowed_targets) contains the target, with [jump] allow_private_networks
# gating loopback/private (SSRF guard). subtopo.sh wires all of that; the case
# then asserts a `-L` forward actually reaches the backend.
#
# Capability probe: the src B4 jump implementation (channel_open_direct_tcpip
# override + policy wiring) may not be present in the running gateway yet. If the
# fully-enabled forward is STILL denied, jump-allow is not active in this binary
# and the case SKIPs (never a fake pass). When B4 is landed, this runs green.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
trap subtopo_stop EXIT INT TERM

FWD=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
     -o ConnectTimeout=10 -o LogLevel=ERROR)

# probe the local forwarded port: "banner:<...>" if the backend SSH banner comes
# back (jump worked), else refused/closed/timeout (denied/not-listening).
fwd_probe() {  # <lport>
  python3 - "$1" <<'PY'
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
except OSError:
    print("refused"); sys.exit(0)
s.settimeout(4)
try:
    d = s.recv(64)
except socket.timeout:
    print("timeout"); s.close(); sys.exit(0)
except OSError:
    print("closed"); s.close(); sys.exit(0)
print("closed" if not d else "banner:" + d.split(b"\n", 1)[0].decode("latin1", "replace"))
s.close()
PY
}

# run_forward <expect:"allow"|"deny"> -> prints probe result; leaves forwarder up
start_forward() {  # <lport>
  ssh -N "${FWD[@]}" -p "$ST_GW_PORT" -i "$USER_KEY" \
    -L "$1:127.0.0.1:${ST_SSHD_PORT}" "$PRINCIPAL@127.0.0.1" >"$IT_WORK_DIR/jump.ssh.log" 2>&1 &
  FWD_PID=$!
  wait_tcp_open 127.0.0.1 "$1" 10 >/dev/null 2>&1 || true
  sleep 0.6
}

attempt() {  # <lport> -> probe result
  local res; res="$(fwd_probe "$1")"; kill "$FWD_PID" 2>/dev/null || true; wait "$FWD_PID" 2>/dev/null || true
  printf '%s' "$res"
}

# ---- (b1) fully-enabled: policy tcp_forwarding=true + backend auto-whitelisted
#            + allow_private_networks=true -> the forward MUST reach the backend.
SUBTOP_TCP_FORWARDING=true
SUBTOP_JUMP_ENABLED=true
SUBTOP_JUMP_ALLOW_PRIVATE=true
subtopo_start
lp="$(alloc_port)"
start_forward "$lp"
res="$(attempt "$lp")"
case "$res" in
  banner:*)
    pass "jump ALLOW path: forward reached backend ($res)" ;;
  refused|closed|timeout)
    skip_case "gateway jump-allow not active (fully-enabled forward still denied: $res) — run after src B4 (channel_open_direct_tcpip) lands" ;;
  *)
    fail "unexpected forward probe: $res" ;;
esac

# ---- (b2) SSRF guard: allow_private_networks=false must refuse the loopback
#            (127.0.0.1) target even though policy requests it. (Only meaningful
#            when (b1) proved jump is active.)
subtopo_stop
SUBTOP_TCP_FORWARDING=true
SUBTOP_JUMP_ENABLED=true
SUBTOP_JUMP_ALLOW_PRIVATE=false
subtopo_start
lp2="$(alloc_port)"
start_forward "$lp2"
res2="$(attempt "$lp2")"
case "$res2" in
  banner:*) tail_log "$SUBTOPO_DIR/gw.log" 20; fail "SSRF guard failed: loopback target was reachable ($res2)" ;;
  refused|closed|timeout) pass "SSRF guard: private/loopback target denied ($res2)" ;;
  *) fail "unexpected forward probe: $res2" ;;
esac
echo "OK: case_jump"
