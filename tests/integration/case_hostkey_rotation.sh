#!/usr/bin/env bash
# case_hostkey_rotation.sh — A4 host-key rotation degradation rehearsal. russh has
# no hostkeys-00 hook, so a gateway host-key rotation CANNOT be seamless; the
# degraded path is the control plane distributing a fresh known_hosts. We prove it
# end-to-end on a fixed gateway port (its own gateway instance, reusing the shared
# control plane + backend):
#   1. start gateway with host key A; client pins A (accept-new) and reconnects OK.
#   2. rotate: restart the SAME-port gateway with host key B.
#      - client with pinned A -> refused (no seamless rotation; expected).
#      - control plane distributes fresh known_hosts (client re-pins B) -> OK.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
trap 'rot_gw_stop' EXIT INT TERM

# resolve the gateway binary the same way the orchestrator/subtopo do
if [ -n "${SSH_GW_BIN:-}" ]; then GW_BIN="$SSH_GW_BIN"
elif [ -n "${CARGO_TARGET_DIR:-}" ]; then GW_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
else GW_BIN="$HERE/../../target/debug/ssh-gw"; fi
[ -x "$GW_BIN" ] || skip_case "gateway binary not found ($GW_BIN)"

GW_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
MET_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
CP_URL="http://${CP_ADDR:-127.0.0.1}:${CP_PORT}/api/v1/resolve"

keyA="$IT_WORK_DIR/hkA"; keyB="$IT_WORK_DIR/hkB"
ssh-keygen -q -t ed25519 -N "" -C rotA -f "$keyA"
ssh-keygen -q -t ed25519 -N "" -C rotB -f "$keyB"

rot_gw_start() {  # <hostkey_path>
  cat > "$IT_WORK_DIR/rot.toml" <<EOF
[listen]
addr = "127.0.0.1:${GW_PORT}"
[host_keys]
keys = [ { path = "$1", state = "active" } ]
[backend]
private_key = "$IT_ASSET_DIR/backend_ed25519"
host_key_policy = "accept-new"
[control_plane]
url = "${CP_URL}"
[metrics]
addr = "127.0.0.1:${MET_PORT}"
[ca]
trusted_ca_keys = ["$IT_ASSET_DIR/user_ed25519.pub"]
EOF
  "$GW_BIN" --config "$IT_WORK_DIR/rot.toml" >"$IT_WORK_DIR/rot.gw.log" 2>&1 &
  ROT_GW_PID=$!
  wait_http_ok "http://127.0.0.1:${MET_PORT}/healthz" 20 \
    || { tail_log "$IT_WORK_DIR/rot.gw.log" 30; return 1; }
}
rot_gw_stop() { [ -n "${ROT_GW_PID:-}" ] && kill -9 "$ROT_GW_PID" 2>/dev/null || true; ROT_GW_PID=""; }

rot_ssh() {  # rot_ssh <strict|accept-new> <known_hosts>
  ssh -p "$GW_PORT" -i "$USER_KEY" \
    -o StrictHostKeyChecking="$1" -o UserKnownHostsFile="$2" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
    "$PRINCIPAL@127.0.0.1" 'printf OK'
}

# (1) key A: pin + reconnect.
rot_gw_start "$keyA" || fail "gateway (keyA) failed to start"
khA="$IT_WORK_DIR/kh.rotA"
r=0; out="$(rot_ssh accept-new "$khA")" || r=$?
assert_eq "$r" "0" "initial connect+pins host key A"
r=0; out="$(rot_ssh yes "$khA")" || r=$?
assert_eq "$out" "OK" "reconnect with pinned key A trusted"

# (2) rotate to key B on the SAME port.
rot_gw_stop
rot_gw_start "$keyB" || fail "gateway (keyB) failed to start (same port $GW_PORT)"
r=0; out="$(rot_ssh yes "$khA" 2>&1)" || r=$?
if [ "$r" -eq 0 ]; then
  tail_log "$IT_WORK_DIR/rot.gw.log" 30
  fail "expected refusal after host-key change (seamless rotation is NOT russh-supported), but connect succeeded"
fi
pass "old-key client refused after rotation (no seamless hostkeys-00 rotation)"

# (3) degraded path: control plane distributes fresh known_hosts -> re-pin + OK.
khB="$IT_WORK_DIR/kh.rotB"
r=0; out="$(rot_ssh accept-new "$khB")" || r=$?
assert_eq "$r" "0" "control-plane-distributed known_hosts (B) accepted"
r=0; out="$(rot_ssh yes "$khB")" || r=$?
assert_eq "$out" "OK" "reconnect with distributed known_hosts (B) trusted"

rot_gw_stop
log "rotation conclusion: russh has no hostkeys-00; seamless rotation unavailable; degraded path (distribute known_hosts) verified."
echo "OK: case_hostkey_rotation"
