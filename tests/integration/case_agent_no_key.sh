#!/usr/bin/env bash
# case_agent_no_key.sh — C3: an agent that lacks the authorized identity is not
# a reason to use a different one.
#
# The client asks for agent forwarding and the agent answers, but it only holds
# a throwaway key. The control plane authorized this session on the fingerprint
# of the user's real key, so red line 4 (minimal signing surface) says the only
# identity the gateway may offer the backend is that one — and if the agent
# cannot produce it, the session must fail rather than reach for another
# credential.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/agent-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"
agent_topo_start "$KEYDIR/authorized_keys"

# An agent holding a key the control plane never authorized.
OTHER_KEY="$IT_WORK_DIR/other_key_ed25519"
if [ ! -f "$OTHER_KEY" ]; then
  ssh-keygen -q -t ed25519 -N "" -C "sshgw-unauthorized-agent" -f "$OTHER_KEY" >/dev/null
fi
subtopo_agent_start "$OTHER_KEY"

# Sanity: the agent is up, it just has the wrong key.
run_capture ssh-add -l
assert_not_contains "$RUN_OUT" "$(ssh-keygen -lf "$IT_ASSET_DIR/user_ed25519.pub" | awk '{print $2}')" \
  "the agent does not hold the authorized identity"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_HAPPEN'
if [ "$RUN_RC" -eq 0 ]; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "a session whose agent lacks the authorized key succeeded — the gateway \
must not substitute another identity or another credential"
fi
assert_not_contains "$RUN_OUT" "SHOULD_NOT_HAPPEN" "no remote command ran"
pass "agent-mode session refused when no agent identity matches the grant (rc=$RUN_RC)"

fail_total="$(agent_topo_metric_value sshgw_agent_backend_auth_fail_total)"
ok_total="$(agent_topo_metric_value sshgw_agent_backend_auth_ok_total)"
[ "${fail_total:-0}" = "1" ] || fail "expected 1 failed agent dial, got [${fail_total:-}]"
[ "${ok_total:-0}" = "0" ] || fail "expected no successful agent dial, got [${ok_total:-}]"
pass "agent metrics record the failure: fail=$fail_total ok=$ok_total"

if grep -q "no agent identity matches the authorized fingerprint" "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
  pass "gateway log names the fingerprint mismatch as the reason"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "gateway log does not name the fingerprint mismatch"
fi

echo "OK: case_agent_no_key"
