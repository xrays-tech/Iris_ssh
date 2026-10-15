#!/usr/bin/env bash
# case_openstack_cross_project_name_unique.sh — appendix C + A: instance-name
# routing under scope="cross_project"; the name lives in another project and is
# the *only* exact match, so the gateway resolves it through the list endpoint
# (all_tenants on) and reaches the backend.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

UUID="bbbbcccc-dddd-4eee-8fff-000011112222"
cat > "$IT_WORK_DIR/os_rules_crossname.json" <<EOF
{"servers":{"${UUID}":{"addresses":{"private":[{"addr":"127.0.0.1","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{"iris_ssh_user":"${BACKEND_USER}"},"name":"cross-1","image":{"id":"img-1"},"cross_tenant":true}},"default":{"status":404}}
EOF
SUBTOP_OPENSTACK_RULES="$IT_WORK_DIR/os_rules_crossname.json"
SUBTOP_OS_SCOPE="cross_project"
SUBTOP_OS_ROUTE_BY="uuid name"
PRINCIPAL="cross-1"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf NAME_CROSS_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q NAME_CROSS_OK; then
  pass "cross-project name (unique) reached the backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40; tail_log "$SUBTOPO_DIR/sshd.log" 20
  fail "cross-project name did not resolve (rc=$RUN_RC out=[$RUN_OUT])"
fi

assert_eq "$(subtopo_os_count GET '/v2.1/servers?name=')" "1" "one list lookup for the name"

echo "OK: case_openstack_cross_project_name_unique"
