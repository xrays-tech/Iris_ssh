#!/usr/bin/env bash
# case_mapping_route.sh — plan-mapping §6.2: the mapping table is the *sole*
# routing authority.
#
# The SSH username is a key in the local mapping table. The gateway resolves it
# through the table (no control plane, no OpenStack — both are mutually
# exclusive with a live [mapping]), dials the target the table reports, and
# authenticates to a backend whose authorized_keys hold nothing but the end
# user's agent key — so the session can only run if the table → target →
# agent-signature chain held.
#
# Asserted: the session runs; the config that served it carried **no**
# [control_plane] section at all (mapping mode boots without one); a principal
# absent from the table is refused (no fallback route exists); the mapping
# resolve counters moved; and the audit record names `mapping` as the source
# that produced the grant.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/mapping-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

# A made-up principal: not a control-plane user, not an instance UUID, just a
# key in the mapping table. The table maps it to the local sshd backend.
PRINCIPAL="mapped_user"
mapping_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# The mapping topology must not render a [control_plane] section: the table is
# the routing authority and the control plane is never consulted.
if grep -q '^\[control_plane\]' "$SUBTOPO_DIR/gw.toml"; then
  fail "the mapping topology still renders a [control_plane] section"
fi
pass "mapping mode: gw.toml carries no [control_plane] section"

# (A) The principal resolved to a live target and the session ran on the
# agent-key-only backend.
run_capture subtopo_ssh_A 'printf MAPPING_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q MAPPING_OK; then
  pass "mapped principal resolved and the session ran on the agent-key-only backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "mapping-routed session failed (rc=$RUN_RC out=[$RUN_OUT])"
fi

# (B) A principal absent from the table is refused: the table is the sole
# authority, so there is no control plane or OpenStack to fall back to.
PRINCIPAL="ghost_user"
run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an unmapped principal authenticated (out=[$RUN_OUT])"
fi
pass "an unmapped principal was refused (rc=$RUN_RC)"

# (C) Observability: the mapping resolve counters moved (one hit, one miss).
ok_total="$(agent_topo_metric_value sshgw_mapping_resolve_ok_total)"
miss_total="$(agent_topo_metric_value sshgw_mapping_resolve_miss_total)"
[ "${ok_total:-0}" -ge 1 ] || fail "expected at least one successful mapping resolve, got [${ok_total:-}]"
[ "${miss_total:-0}" -ge 1 ] || fail "expected at least one mapping miss, got [${miss_total:-}]"
pass "sshgw_mapping_resolve_ok_total=$ok_total sshgw_mapping_resolve_miss_total=$miss_total"

# (D) The audit record must name the source that produced the grant.
if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" '"resolve_source":"mapping"' "audit names the mapping source"
  assert_contains "$audit" '"target_host":"127.0.0.1"' "audit names the host from the table"
  assert_contains "$audit" "\"target_port\":${ST_SSHD_PORT}" "audit names the port from the table"
  assert_contains "$audit" "\"target_user\":\"$BACKEND_USER\"" "audit names the backend login user"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record in the gateway log"
fi

echo "OK: case_mapping_route"
