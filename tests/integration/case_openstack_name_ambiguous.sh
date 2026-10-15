#!/usr/bin/env bash
# case_openstack_name_ambiguous.sh — plan-openstack appendix A.3: name routing
# must refuse to guess.
#
# Two instances share the name "twin". Nova's substring filter returns both;
# the gateway's local exact-match narrowing finds two identical hits, and two
# machines with the same name are indistinguishable — so the login is refused,
# exactly like a 404 for the client (red line: failures are uniform).
#
# Asserted: the session is refused after exactly one *successful* list lookup
# (200, not 404 — the refusal is ambiguity, not absence), the resolve error
# counter moved, and no session audit record exists.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_name_ambiguous.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440011": {
      "addresses": {"private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]},
      "metadata": {},
      "name": "twin",
      "image": {"id": "img-1"}
    },
    "550e8400-e29b-41d4-a716-446655440012": {
      "addresses": {"private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]},
      "metadata": {},
      "name": "twin",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

SUBTOP_OS_ROUTE_BY="uuid name"
PRINCIPAL="twin"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an ambiguous name authenticated (out=[$RUN_OUT])"
fi
pass "two instances sharing a name were refused (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET '/v2.1/servers?name=')" "1" \
  "exactly one name lookup before the refusal"
assert_eq "$(subtopo_os_statuses GET '/v2.1/servers?name=')" "200" \
  "Nova found candidates — the refusal is ambiguity, not a 404"
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "0" \
  "an ambiguous name must not fall back to show-by-id"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "0" \
  "resolution must not be counted as successful"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_name_ambiguous"
