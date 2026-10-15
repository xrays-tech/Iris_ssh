#!/usr/bin/env bash
# case_openstack_cross_project_uuid.sh — plan-openstack appendix C: with
# `scope="cross_project"` the gateway resolves an instance UUID that lives in a
# *different* project (visible only because the query carries all_tenants=1)
# and reaches the backend. The mock marks the instance `cross_tenant`; a
# single-scoped request must not even see it (the negative leg is
# case_openstack_cross_project_disabled_default).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

UUID="aaaabbbb-cccc-4ddd-8eee-ffff00001111"
cat > "$IT_WORK_DIR/os_rules_cross.json" <<EOF
{"servers":{"${UUID}":{"addresses":{"private":[{"addr":"127.0.0.1","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{"iris_ssh_user":"${BACKEND_USER}"},"name":"inst-cross","image":{"id":"img-1"},"cross_tenant":true}},"default":{"status":404}}
EOF
SUBTOP_OPENSTACK_RULES="$IT_WORK_DIR/os_rules_cross.json"
SUBTOP_OS_SCOPE="cross_project"
PRINCIPAL="$UUID"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf CROSS_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q CROSS_OK; then
  pass "cross-project UUID (other tenant) reached the backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40; tail_log "$SUBTOPO_DIR/sshd.log" 20
  fail "cross-project UUID did not resolve (rc=$RUN_RC out=[$RUN_OUT])"
fi

# Exactly one show-by-id lookup against Nova (the query carried all_tenants=1,
# which is what made the cross-tenant instance visible at all).
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" "one show-by-id lookup"

echo "OK: case_openstack_cross_project_uuid"
