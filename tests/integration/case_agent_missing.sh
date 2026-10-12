#!/usr/bin/env bash
# case_agent_missing.sh — C3: no agent means no session, and never a fallback.
#
# Same agent-key-only backend as case_agent_auth (the gateway's own key is
# useless there), but the client connects *without* -A, so it never sends
# auth-agent-req@openssh.com. With no agent there is no signature, and red line 3
# forbids the gateway from quietly presenting its own key instead — so the
# session must die with a protocol-native failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/agent-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"
agent_topo_start "$KEYDIR/authorized_keys"

# No agent at all: the harness may have one in its environment, so pin the
# variable to nothing rather than relying on the ambient shell.
subtopo_agent_stop

run_capture subtopo_ssh 'printf SHOULD_NOT_HAPPEN'
if [ "$RUN_RC" -eq 0 ]; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "a session without agent forwarding succeeded on an agent-key-only backend — \
this is exactly the silent credential downgrade red line 3 forbids"
fi
assert_not_contains "$RUN_OUT" "SHOULD_NOT_HAPPEN" "no remote command ran"
pass "agent-mode session refused when the client never requested forwarding (rc=$RUN_RC)"

# The failure must be *counted*, so an operator can tell "agent is broken" from
# "nobody is using agent" without reading logs.
fail_total="$(agent_topo_metric_value sshgw_agent_backend_auth_fail_total)"
ok_total="$(agent_topo_metric_value sshgw_agent_backend_auth_ok_total)"
[ "${fail_total:-0}" = "1" ] || fail "expected 1 failed agent dial, got [${fail_total:-}]"
[ "${ok_total:-0}" = "0" ] || fail "expected no successful agent dial, got [${ok_total:-}]"
pass "agent metrics record the failure: fail=$fail_total ok=$ok_total"

# And the log must say *why*, not just that something failed.
if grep -q "client never requested agent forwarding" "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
  pass "gateway log states the reason (no agent-forwarding request)"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "gateway log does not explain the refusal"
fi

echo "OK: case_agent_missing"
