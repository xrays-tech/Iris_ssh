#!/usr/bin/env bash
# case_agent_target_scope.sh — C3: what the agent signature is *for*, and what
# agent mode does not do.
#
# Three properties, on the same agent-key-only backend as case_agent_auth:
#
#   1. the signature reaches the backend for the target the control plane
#      resolved, and only that one (the audit record names it);
#   2. the agent is never used for anything but that target's authentication —
#      an agent-mode session is a single-channel, single-target thing;
#   3. jump forwarding (`direct-tcpip`) is refused in agent mode: there is no
#      second channel to pivot a forwarded connection through, and inventing one
#      would widen the surface the agent signature protects.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/agent-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"
agent_topo_start "$KEYDIR/authorized_keys"

subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# (1) The authorized target is reachable with the agent signature.
run_capture subtopo_ssh_A 'printf AGENT_SCOPE_OK; hostname'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q AGENT_SCOPE_OK; then
  pass "agent-mode session reached the control-plane-authorized target"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "agent-mode session could not reach the authorized target (rc=$RUN_RC out=[$RUN_OUT])"
fi

# The audit record must name that same target — the signature is scoped to it.
agent_topo_wait_for_audit "auth_kind" || {
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no agent audit record"
}
audit="$(agent_topo_audit_json)"
assert_contains "$audit" '"auth_kind":"agent"' "audit record reports auth_kind=agent"
assert_contains "$audit" '"target_host":"127.0.0.1"' "audit names the resolved host"
assert_contains "$audit" "\"target_port\":${ST_SSHD_PORT}" "audit names the resolved port"

# (3) Jump forwarding is unavailable in agent mode and is counted.
FWD_PORT="$(alloc_port)"
ssh -p "$ST_GW_PORT" -i "$USER_KEY" -A -N \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
  -o ExitOnForwardFailure=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
  -L "127.0.0.1:${FWD_PORT}:127.0.0.1:${ST_SSHD_PORT}" \
  "$PRINCIPAL@127.0.0.1" >/dev/null 2>&1 &
FWD_PID=$!
cleanup_fwd() { kill -9 "$FWD_PID" 2>/dev/null || true; }
trap 'cleanup_fwd; subtopo_agent_stop; subtopo_stop' EXIT INT TERM
sleep 1

if python3 - "$FWD_PORT" <<'PY'
import socket, sys, time

# `ssh -L` always binds its local listener, so a successful TCP connect only
# proves the forward exists locally. What matters is whether the far end answers
# the SSH protocol: a refused channel closes the connection without a banner,
# an accepted one forwards the backend's `SSH-` greeting through.
port = int(sys.argv[1])
for _ in range(20):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
            sock.settimeout(2)
            try:
                banner = sock.recv(256)
            except OSError:
                banner = b""
            # A TCP connect is itself a decision: either the far end greets us
            # (the jump leaked through) or it closed (the gateway refused).
            sys.exit(0 if banner.startswith(b"SSH-") else 1)
    except OSError:
        # Listener not up yet; ssh -L is still starting.
        time.sleep(0.25)
sys.exit(1)
PY
then
  cleanup_fwd
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "agent mode accepted a direct-tcpip jump — the agent signature must not \
be reachable through a second channel"
else
  cleanup_fwd
  pass "agent mode refused the direct-tcpip jump"
fi

denied="$(agent_topo_metric_value sshgw_agent_channel_denied_total)"
# The probe retries until the refusal lands, so it can trip more than once.
[ "${denied:-0}" -ge 1 ] || fail "expected at least one denied channel in agent mode, got [${denied:-}]"
pass "sshgw_agent_channel_denied_total=$denied"

# (2) The successful dial still happened exactly once: the jump was refused
# before it could consume a second signature.
ok_total="$(agent_topo_metric_value sshgw_agent_backend_auth_ok_total)"
sig_total="$(agent_topo_metric_value sshgw_agent_signatures_total)"
[ "${ok_total:-0}" = "1" ] || fail "expected 1 successful agent dial, got [${ok_total:-}]"
[ "${sig_total:-0}" = "1" ] || fail "expected 1 relayed signature, got [${sig_total:-}]"
pass "exactly one agent dial and one signature for the whole case"

echo "OK: case_agent_target_scope"
