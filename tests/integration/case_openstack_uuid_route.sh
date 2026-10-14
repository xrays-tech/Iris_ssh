#!/usr/bin/env bash
# case_openstack_uuid_route.sh — plan-openstack §4.2 / MUST2: the instance UUID
# *is* the route.
#
# The SSH username is a canonical Nova server UUID. The gateway resolves it
# through the mock Nova, dials the address Nova reported, and authenticates to a
# backend whose authorized_keys holds nothing but the end user's agent key — so
# the session can only run if the whole UUID → IP → agent-signature chain held.
#
# Asserted: the session runs; the config that served it carried **no**
# [control_plane] section at all (pure mode boots, MUST2); exactly one Nova
# lookup (the instance cache coalesces) and one Keystone token fetch; the
# OpenStack resolve counters moved; and the audit record names `openstack` as
# the source that produced the grant (MUST3).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

PRINCIPAL="$SUBTOP_OPENSTACK_UUID"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# (MUST2) Pure mode means exactly that: no [control_plane] section was rendered,
# so nothing in the config could have resolved this principal the old way.
if grep -q '^\[control_plane\]' "$SUBTOPO_DIR/gw.toml"; then
  fail "the OpenStack topology still renders a [control_plane] section"
fi
pass "pure mode: gw.toml carries no [control_plane] section"

# (A) The UUID resolved to a live target and the session ran.
run_capture subtopo_ssh_A 'printf OS_ROUTE_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q OS_ROUTE_OK; then
  pass "instance UUID resolved and the session ran on the agent-key-only backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "UUID-routed session failed (rc=$RUN_RC out=[$RUN_OUT])"
fi

# (B) One instance lookup and one token for the whole session: the resolver
# cache must absorb every repeat authorize instead of re-hitting Nova.
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova instance lookup for the session"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova answered 200 with the instance document"
assert_eq "$(subtopo_os_count POST /v3/auth/tokens)" "1" \
  "exactly one Keystone token fetch for the session"

# (C) Observability.
ok_total="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${ok_total:-0}" -ge 1 ] || fail "expected at least one successful OpenStack resolve, got [${ok_total:-}]"
assert_eq "${err_total:-0}" "0" "no OpenStack resolve errors"
pass "sshgw_openstack_resolve_ok_total=$ok_total"

# (D) The audit record must name the source that produced the grant.
if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" '"resolve_source":"openstack"' "audit names the OpenStack source"
  assert_contains "$audit" '"target_host":"127.0.0.1"' "audit names the host Nova returned"
  assert_contains "$audit" "\"target_port\":${ST_SSHD_PORT}" "audit names the port from [openstack] ssh_port"
  assert_contains "$audit" "\"target_user\":\"$BACKEND_USER\"" "audit names the backend login user"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record in the gateway log"
fi

echo "OK: case_openstack_uuid_route"
