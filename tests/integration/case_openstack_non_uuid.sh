#!/usr/bin/env bash
# case_openstack_non_uuid.sh — plan-openstack §3.1 / MUST2: `routing =
# "openstack_only"` has exactly one shape of principal and no fallback.
#
# A non-UUID username must be refused *before any I/O*: no Nova lookup, no
# Keystone token, and — critically — no fall-back to the control plane, which
# in this topology is the difference between "the route table decided" and
# "somebody silently resolved it the old way".
#
# Asserted: the login is refused; the mock Nova and the mock control plane both
# report zero requests; the OpenStack resolve error counter moved with the
# `unrouted` reason in the log; no session audit record exists.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

# The orchestrator's normal principal: a valid control-plane name, and not a UUID.
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "a non-UUID principal authenticated in openstack_only mode (out=[$RUN_OUT])"
fi
pass "non-UUID principal was refused (rc=$RUN_RC)"

# Zero on both sides of the route table.
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "0" "no Nova lookup for a non-UUID"
assert_eq "$(subtopo_os_count POST /v3/auth/tokens)" "0" "no Keystone token for a non-UUID"

cp_resolves="$(curl -fsS --max-time 4 "http://127.0.0.1:${ST_CP_PORT}/__log" 2>/dev/null |
  python3 -c 'import json, sys
try:
    data = json.load(sys.stdin).get("requests", [])
except Exception:
    data = []
print(sum(1 for r in data if str(r.get("path", "")).startswith("/api/v1/resolve")))')"
assert_eq "$cp_resolves" "0" "openstack_only must not fall back to the control plane"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "0" \
  "the refusal must not be counted as a successful resolve"

if grep -q 'unrouted' "$SUBTOPO_DIR/gw.log"; then
  pass "the refusal is logged with reason=unrouted"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no 'unrouted' reason in the gateway log"
fi

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_non_uuid"
