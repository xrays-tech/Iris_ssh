#!/usr/bin/env bash
# case_openstack_no_floating_rejected.sh — plan-openstack appendix D.
#
# `address_kind = "floating"` is a strict filter with no fallback. An instance
# that advertises *only* fixed addresses is refused rather than dialed on the
# fixed one: a floating-only deployment cannot reach a VXLAN/private address,
# so the fallback would trade a refusal for a hang.
#
# The mock answers 200 and the instance has a perfectly good address — the
# refusal is a *policy* decision made after a successful lookup, which is what
# distinguishes it from `no_address`.
#
# Asserted: the session is refused after one successful Nova lookup; the log
# carries `reason="no_floating"` (the operator-facing token naming the kind that
# was demanded); it is counted as an OpenStack resolve error; no audit record.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys-nofloat"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_nofloat.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440088": {
      "addresses": {
        "TEST-NET01": [
          {"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}
        ]
      },
      "metadata": {},
      "name": "flt-fixed-only",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

SUBTOP_OS_EXTRA=$'network = "TEST-NET01"\naddress_kind = "floating"'
PRINCIPAL="550e8400-e29b-41d4-a716-446655440088"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "a fixed-only instance authenticated under address_kind=floating (out=[$RUN_OUT])"
fi
pass "fixed-only instance refused under address_kind=floating (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup before the refusal"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova found the instance — the refusal is the kind filter, not a 404"

# The reason token is the whole point of appendix D's distinct error: it names
# the kind the deployment demanded, which `no_address` would have hidden. The
# gateway logs structured JSON, so the token appears as `"reason":"no_floating"`.
if ! grep -q '"reason":"no_floating"' "$SUBTOPO_DIR/gw.log"; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail 'expected "reason":"no_floating" in the gateway log'
fi
pass 'gateway log names reason="no_floating"'

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
ok_total="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
assert_eq "${ok_total:-0}" "0" "resolution must not be counted as successful"
pass "sshgw_openstack_resolve_err_total=$err_total"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_no_floating_rejected"
