#!/usr/bin/env bash
# case_openstack_upstream_down.sh — plan-openstack §3.5 / red line: when Nova is
# unreachable the gateway fails closed and tells the client nothing about why.
#
# The mock OpenStack is killed mid-flight, then the same instance UUID that
# worked a moment ago is presented again. Every outcome other than a plain
# authentication failure is a leak: no control-plane fallback, no target served
# past the cache TTL (fail_open is off, and red line 5 requires an explicit
# opt-in *and* a pinned host-key policy to ever serve a stale address), no
# upstream detail in the client's output, and the gateway itself stays up.
#
# The instance cache is authoritative *within* its TTL — that is what a cache
# is, on the control-plane route too — so the case deliberately waits for the
# 1s TTL below to lapse before expecting a refusal.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

PRINCIPAL="$SUBTOP_OPENSTACK_UUID"
SUBTOP_OS_CACHE_TTL="1s"   # so the warm entry expires inside this case
openstack_topo_start "$KEYDIR/authorized_keys"
assert_contains "$(cat "$SUBTOPO_DIR/gw.toml")" 'fail_open = false' \
  "the OpenStack route is configured fail-closed"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# Baseline: the route works while Nova is up.
run_capture subtopo_ssh_A 'printf UPSTREAM_UP_OK'
[ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q UPSTREAM_UP_OK || {
  tail_log "$SUBTOPO_DIR/gw.log" 40; tail_log "$SUBTOPO_DIR/os.log" 25
  fail "baseline session failed (rc=$RUN_RC out=[$RUN_OUT])"
}
pass "baseline session succeeded with Nova up"

# The baseline session leaves exactly one audit record; the refused attempt
# below must not add a second.
agent_topo_wait_for_audit "auth_kind" || {
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the baseline session"
}
before_audits="$(grep -c '"message":"session audit"' "$SUBTOPO_DIR/gw.log" || true)"

subtopo_kill_os
# Let the positive TTL lapse; before that the cache is legitimately the answer.
sleep 2

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "the session succeeded with Nova down (out=[$RUN_OUT])"
fi
pass "session refused with Nova down (rc=$RUN_RC)"

# No upstream detail reaches the client — the failure is a plain auth failure.
# (The gateway's own address is in ssh's message by construction, so the leak
# check is scoped to words only an upstream error could contribute.)
for leak in nova keystone openstack catalog; do
  assert_not_contains "$RUN_OUT" "$leak" "client output must not name the upstream"
done

# Fail-closed, not fail-over: the control plane was never asked.
cp_resolves="$(curl -fsS --max-time 4 "http://127.0.0.1:${ST_CP_PORT}/__log" 2>/dev/null |
  python3 -c 'import json, sys
try:
    data = json.load(sys.stdin).get("requests", [])
except Exception:
    data = []
print(sum(1 for r in data if str(r.get("path", "")).startswith("/api/v1/resolve")))')"
assert_eq "$cp_resolves" "0" "no control-plane fallback while Nova is down"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
pass "sshgw_openstack_resolve_err_total=$err_total"

# The gateway survived: its own health endpoint still answers.
wait_http_ok "http://127.0.0.1:${ST_MET_PORT}/healthz" 10 || {
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "the gateway stopped serving metrics after an OpenStack outage"
}
pass "gateway still serving metrics after the outage"

# A refused login has no session, hence no record: the count must not move.
sleep 1
after_audits="$(grep -c '"message":"session audit"' "$SUBTOPO_DIR/gw.log" || true)"
assert_eq "${after_audits:-0}" "${before_audits:-0}" \
  "the refused login must not add a session audit record"

echo "OK: case_openstack_upstream_down"
