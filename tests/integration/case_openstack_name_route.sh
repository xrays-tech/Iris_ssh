#!/usr/bin/env bash
# case_openstack_name_route.sh — plan-openstack appendix A.2/A.3: with
# `route_by = ["uuid","name"]` a non-UUID principal that satisfies the
# instance-name bound is resolved through the Nova *list* endpoint
# (`GET /v2.1/servers?name=…`) and reaches the backend.
#
# The default instance table names its instance "inst-1"; the client logs in
# as that name, never as the UUID. Nova's filter is a substring search, so
# the gateway's local exact-match narrowing is part of what is being proven
# (the mock would happily return a longer name too).
#
# Asserted: the session runs; exactly one list lookup and zero show-by-id
# lookups; the audit record names the resolved target; the by-name route
# counter moved while the by-uuid one did not.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

SUBTOP_OS_ROUTE_BY="uuid name"
PRINCIPAL="inst-1"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf NAME_ROUTE_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q NAME_ROUTE_OK; then
  pass "name principal reached the backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "name route did not resolve (rc=$RUN_RC out=[$RUN_OUT])"
fi

# The lookup is the list endpoint, and the name is a query value — never path
# material, never a show-by-id fallback.
assert_eq "$(subtopo_os_count GET '/v2.1/servers?name=')" "1" \
  "exactly one name lookup through the list endpoint"
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "0" \
  "a name must never fall back to show-by-id"

by_name="$(agent_topo_metric_value sshgw_openstack_resolve_by_name_total)"
by_uuid="$(agent_topo_metric_value sshgw_openstack_resolve_by_uuid_total)"
[ "${by_name:-0}" -ge 1 ] || fail "expected the by-name counter to move, got [${by_name:-}]"
assert_eq "${by_uuid:-0}" "0" "the by-uuid route counter did not"
pass "sshgw_openstack_resolve_by_name_total=$by_name by_uuid_total=0"

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" "\"target_host\":\"127.0.0.1\"" "audit names the resolved target"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the name-routed session"
fi

echo "OK: case_openstack_name_route"
