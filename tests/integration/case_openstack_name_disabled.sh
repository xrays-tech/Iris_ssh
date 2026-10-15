#!/usr/bin/env bash
# case_openstack_name_disabled.sh — plan-openstack appendix A.1: the
# instance-name route is opt-in and off by default.
#
# The default instance table names its instance "inst-1"; the client logs in
# as that name with the stock `route_by = ["uuid"]` configuration. The
# principal is a syntactically valid instance name, but the route is off, so
# the gateway must refuse *before any network traffic* — MUST1 for names:
# not one byte to Keystone, not one byte to Nova.
#
# Asserted: the session is refused; the mock saw zero requests of any kind;
# no OpenStack resolve *succeeded*; no session audit record exists. (The
# refusal is counted as an OpenStack resolve error — a declined principal
# belongs to that source's counters — but it never left the process.)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

# No SUBTOP_OS_ROUTE_BY: this is the default configuration every deployment
# outside this suite runs with.
PRINCIPAL="inst-1"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "a name authenticated while the name route was off (out=[$RUN_OUT])"
fi
pass "name principal refused with the default route_by (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET /v2.1/servers)" "0" \
  "no list and no show-by-id lookup for a name while the route is off"
assert_eq "$(subtopo_os_count POST /v3/auth/tokens)" "0" \
  "not even a token fetch: the refusal happens before any request"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "0" \
  "no OpenStack resolve was attempted"
[ "$(agent_topo_metric_value sshgw_openstack_resolve_err_total)" -ge 1 ] || \
  fail "the declined principal should count as an OpenStack resolve error"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_name_disabled"
