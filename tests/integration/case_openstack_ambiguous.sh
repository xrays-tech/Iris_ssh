#!/usr/bin/env bash
# case_openstack_ambiguous.sh — plan-openstack §3.3: two equally-good addresses
# are refused when `on_ambiguous = "reject"` (the configured default).
#
# The instance advertises two IPv4 addresses on two different networks. There
# is no basis on which to pick one, and dialing the wrong one would be a silent
# misroute to a machine that is not the caller's instance — so the gateway
# refuses instead, fail-closed.
#
# Asserted: the session is refused after exactly one Nova lookup, the refusal
# is counted as an OpenStack resolve error, and no session audit record exists.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_ambiguous.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440002": {
      "addresses": {
        "private": [{"addr": "10.0.0.7", "version": 4, "OS-EXT-IPS:type": "fixed"}],
        "mgmt":    [{"addr": "10.9.9.7", "version": 4, "OS-EXT-IPS:type": "fixed"}]
      },
      "metadata": {},
      "name": "ambiguous",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

PRINCIPAL="550e8400-e29b-41d4-a716-446655440002"
SUBTOP_OS_ON_AMBIGUOUS="reject"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an ambiguous instance authenticated (out=[$RUN_OUT])"
fi
pass "two-address instance was refused (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup before the refusal"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova found the instance — the refusal is ambiguity, not a 404"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "0" \
  "resolution must not be counted as successful"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_ambiguous"
