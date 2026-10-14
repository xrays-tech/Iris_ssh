#!/usr/bin/env bash
# case_openstack_no_address.sh — plan-openstack §3.3: an instance that exists
# but advertises no usable address is refused rather than guessed at.
#
# The mock returns a 200 with an empty `addresses` map and no accessIPv4/6
# fallback (the gateway configures no `network` filter here, so the legacy
# fields *would* have been consulted — they are simply absent). A gateway that
# fell back to any other target, or to the control plane, would let this login
# through.
#
# Asserted: the session is refused after exactly one Nova lookup; the failure is
# counted as an OpenStack resolve error (so it is distinguishable from a
# backend-side refusal); no session audit record exists.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_noaddr.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440001": {
      "addresses": {},
      "metadata": {},
      "name": "no-address",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

PRINCIPAL="550e8400-e29b-41d4-a716-446655440001"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an addressless instance authenticated (out=[$RUN_OUT])"
fi
pass "instance with no address was refused (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup before the refusal"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova found the instance — the refusal is address selection, not a 404"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
ok_total="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
assert_eq "${ok_total:-0}" "0" "resolution must not be counted as successful"
pass "sshgw_openstack_resolve_err_total=$err_total"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_no_address"
