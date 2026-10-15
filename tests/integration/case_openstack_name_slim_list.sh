#!/usr/bin/env bash
# case_openstack_name_slim_list.sh — plan-openstack appendix A.2, with a real-
# cloud refinement: some clouds answer the `?name=` list with a *directory
# entry only* (`id`/`links`/`name`, no `addresses`). Caught against T_3741's
# Nova, where the list answered `addresses: null` and the name route dialed
# nothing while a show-by-id had a perfectly good address.
#
# The gateway must therefore refine a *unique* name match with one show-by-id
# instead of trusting the directory entry to carry the addresses.
#
# Asserted: the session runs; exactly one list lookup followed by exactly one
# show-by-id refinement; the audit record names the resolved target.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_slim.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440023": {
      "slim_list": true,
      "addresses": {
        "private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]
      },
      "metadata": {},
      "name": "slim_dir_instance",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

SUBTOP_OS_ROUTE_BY="uuid name"
PRINCIPAL="slim_dir_instance"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SLIM_LIST_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q SLIM_LIST_OK; then
  pass "slim directory entry refined into a working session"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  fail "slim list entry did not resolve (rc=$RUN_RC out=[$RUN_OUT]) — \
the list is a directory; the addresses live behind show-by-id"
fi

assert_eq "$(subtopo_os_count GET '/v2.1/servers?name=')" "1" \
  "one list lookup through the directory endpoint"
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "a unique name match must be refined with exactly one show-by-id"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "the refinement answered 200"

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" "\"target_host\":\"127.0.0.1\"" "audit names the refined target"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the slim-list session"
fi

echo "OK: case_openstack_name_slim_list"
