#!/usr/bin/env bash
# case_agent_auth.sh — C3: agent passthrough works end to end (`ssh -A`).
#
# Topology: the backend's authorized_keys holds ONLY the end user's key, so the
# gateway's own backend credential cannot log in. backend_auth="agent" plus the
# instance kill-switch are on, and the control-plane grant allows agent
# forwarding. A real ssh-agent holding the user's key is started locally and
# forwarded with -A.
#
# Asserted: the remote command runs (the signature really came from the agent),
# the agent counters move, and the audit record says which credential and which
# identity were used.
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

# The agent must actually be holding the key the control plane will authorize,
# or the next assertion would be testing a different failure.
user_fp="$(ssh-keygen -lf "$IT_ASSET_DIR/user_ed25519.pub" | awk '{print $2}')"
run_capture ssh-add -l
assert_contains "$RUN_OUT" "$user_fp" "agent holds the authorized user key"

# (A) A gateway session that authenticates with the agent's signature.
run_capture subtopo_ssh_A 'printf AGENT_AUTH_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q AGENT_AUTH_OK; then
  pass "agent-mode session executed a command on the agent-key-only backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "agent-mode session failed (rc=$RUN_RC out=[$RUN_OUT]) — the gateway could \
not have authenticated without the agent, so either passthrough is broken or the \
gateway fell back to a credential it should never use"
fi

# (B) Observability: exactly one agent dial, exactly one signature.
ok_total="$(agent_topo_metric_value sshgw_agent_backend_auth_ok_total)"
sig_total="$(agent_topo_metric_value sshgw_agent_signatures_total)"
fail_total="$(agent_topo_metric_value sshgw_agent_backend_auth_fail_total)"
[ "${ok_total:-0}" = "1" ] || fail "expected 1 successful agent dial, got [${ok_total:-}]"
[ "${sig_total:-0}" = "1" ] || fail "expected 1 relayed signature, got [${sig_total:-}]"
[ "${fail_total:-0}" = "0" ] || fail "expected no failed agent dial, got [${fail_total:-}]"
pass "agent metrics: ok=$ok_total signatures=$sig_total fail=$fail_total"

# (C) The audit record names the credential and the identity that signed.
if agent_topo_wait_for_audit "auth_kind"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" '"auth_kind":"agent"' "audit record reports auth_kind=agent"
  assert_contains "$audit" "\"agent_identity\":\"$user_fp\"" "audit record carries the signing identity"
  assert_contains "$audit" '"agent_signatures":1' "audit record counts the signature"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record in the gateway log"
fi

echo "OK: case_agent_auth"
