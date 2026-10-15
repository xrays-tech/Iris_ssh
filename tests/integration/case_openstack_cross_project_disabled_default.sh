#!/usr/bin/env bash
# case_openstack_cross_project_disabled_default.sh — the zero-regression leg:
# with the default scope (single_project) a cross_tenant instance in "another
# project" is invisible (Nova 404), so the UUID is refused exactly like an
# unknown one — the default is unchanged, and no all_tenants is ever sent.
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
# No SUBTOP_OS_SCOPE: the default single_project world must stay byte-identical.
SUBTOP_OPENSTACK_RULES="$IT_WORK_DIR/os_rules_cross.json"
PRINCIPAL="$UUID"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -ne 0 ]; then
  pass "cross-tenant instance refused under the default single_project scope (rc=$RUN_RC)"
else
  fail "cross-tenant instance should be invisible to a single-project token"
fi
err="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err:-0}" -ge 1 ] || fail "expected a resolve error, got [${err:-}]"

echo "OK: case_openstack_cross_project_disabled_default"
