#!/usr/bin/env bash
# case_openstack_cross_project_name_ambiguous.sh — appendix C + A.3: two
# instances in *different* projects share the exact name. Under
# scope="cross_project" (all_tenants) the gateway sees both and must refuse
# rather than guess which machine to dial. Client sees the plain homogeneous
# refusal; the log carries the distinct ambiguous_name_cross_project token.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

cat > "$IT_WORK_DIR/os_rules_crossdup.json" <<EOF
{"servers":{
  "ccccdddd-eeee-4fff-8000-111122223333":{"addresses":{"private":[{"addr":"127.0.0.1","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{"iris_ssh_user":"${BACKEND_USER}"},"name":"dup","image":{"id":"img-1"},"cross_tenant":true},
  "dddddddd-eeee-4fff-8000-222233334444":{"addresses":{"private":[{"addr":"127.0.0.1","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{"iris_ssh_user":"${BACKEND_USER}"},"name":"dup","image":{"id":"img-1"},"cross_tenant":true}
},"default":{"status":404}}
EOF
SUBTOP_OPENSTACK_RULES="$IT_WORK_DIR/os_rules_crossdup.json"
SUBTOP_OS_SCOPE="cross_project"
SUBTOP_OS_ROUTE_BY="uuid name"
PRINCIPAL="dup"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -ne 0 ]; then
  pass "cross-project ambiguous name refused (rc=$RUN_RC)"
else
  fail "expected refusal for a name shared across projects"
fi

# It must refuse at the list, never guess with a show-by-id.
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "0" "no show-by-id for an ambiguous name"
err="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err:-0}" -ge 1 ] || fail "expected a resolve error counter, got [${err:-}]"
tail_log "$SUBTOPO_DIR/gw.log" 8
assert_contains "$(cat "$SUBTOPO_DIR/gw.log")" "ambiguous_name_cross_project" "distinct cross-project reason token in the log"

echo "OK: case_openstack_cross_project_name_ambiguous"
