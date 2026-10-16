#!/usr/bin/env bash
# case_openstack_address_kind_default.sh — plan-openstack appendix D.
#
# `address_kind` defaults to `any`, which must be byte-for-byte the behaviour
# before the knob existed. A fixed-only instance therefore still connects: only
# an explicitly configured `"floating"` refuses it (see
# case_openstack_no_floating_rejected). This is the zero-regression guard for
# every existing deployment that never writes the line.
#
# Asserted: the session is established against the fixed address; one Nova
# lookup; no address-kind refusal appears in the log; resolve_ok=1.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys-anydefault"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_anydefault.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440099": {
      "addresses": {
        "TEST-NET01": [
          {"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}
        ]
      },
      "metadata": {},
      "name": "flt-fixed-only-default",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

# SUBTOP_OS_EXTRA carries only the network filter: no address_kind at all, so
# the gateway runs with the `any` default — exactly what an operator who never
# heard of appendix D gets.
SUBTOP_OS_EXTRA=$'network = "TEST-NET01"'
PRINCIPAL="550e8400-e29b-41d4-a716-446655440099"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf ANY_DEFAULT_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q ANY_DEFAULT_OK; then
  pass "fixed-only instance connected under the address_kind=any default"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  fail "the default address_kind refused a fixed address (rc=$RUN_RC out=[$RUN_OUT]) — \
appendix D must be opt-in, not a behaviour change"
fi

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova found the instance"

if grep -qE '"reason":"no_(floating|fixed)"' "$SUBTOPO_DIR/gw.log"; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail 'an address-kind refusal appeared although address_kind was never set'
fi
pass "no address-kind refusal in the log (default is any)"

assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "1" \
  "the lookup resolved successfully"

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" "\"target_host\":\"127.0.0.1\"" "audit names the dialed target"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the default-kind session"
fi

echo "OK: case_openstack_address_kind_default"
