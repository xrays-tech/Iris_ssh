#!/usr/bin/env bash
# case_openstack_envelope_variants.sh — plan-openstack appendix B.1/B.6: the
# classic v2 wire format (`{"server": {…}}`) resolves exactly like the flat
# v2.1 document.
#
# Caught the hard way on a real cloud (project T_3746): the gateway used to
# read an envelope as a bare server, come back with empty `addresses`, and
# refuse with the misleading `reason="no_network"` while curl showed a
# perfectly good address. This case keeps both wire shapes honest end to end:
# the mock answers the show-by-id with the resource wrapped in a `server` key,
# and the session must still run.
#
# Asserted: the session runs; exactly one show-by-id answered 200 with the
# enveloped body; the resolve counters moved; the audit record names the
# resolved target.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_envelope.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440021": {
      "envelope": true,
      "addresses": {
        "private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]
      },
      "metadata": {},
      "name": "enveloped",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

PRINCIPAL="550e8400-e29b-41d4-a716-446655440021"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf ENVELOPE_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q ENVELOPE_OK; then
  pass "classic v2 envelope resolved and the session ran"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  fail "enveloped instance did not resolve (rc=$RUN_RC out=[$RUN_OUT]) — \
this is the T_3746 shape: a `server` wrapper must not cost the addresses"
fi

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova instance lookup for the session"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova answered 200 with the enveloped document"

ok_total="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
[ "${ok_total:-0}" -ge 1 ] || fail "expected a successful OpenStack resolve, got [${ok_total:-}]"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_err_total)" "0" \
  "an envelope is a wire format, not a failure"

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" '"resolve_source":"openstack"' "audit names the OpenStack source"
  assert_contains "$audit" '"target_host":"127.0.0.1"' "audit names the host the envelope advertised"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the enveloped session"
fi

echo "OK: case_openstack_envelope_variants"
