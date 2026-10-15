#!/usr/bin/env bash
# case_openstack_unparseable_loud.sh — plan-openstack appendix B.3/B.4/B.7:
# a 200 body whose `addresses` cannot be read is refused loudly and homogeneously.
#
# The instance document is well-formed JSON with an `addresses` key that is a
# *string* instead of a map — the shape that used to be silently emptied and
# mis-reported as `no_network` (the 2963e76 / 0f30b01 incident class). The
# gateway must refuse like any unknown instance (red line B.7.3: identical to
# the client), while the *log* names the real cause.
#
# Asserted: the session is refused after exactly one 200 show-by-id; the
# refusal counts as an OpenStack resolve error; the gateway log carries the
# `unparseable` reason; and the body's data — the instance label, the string
# that broke the shape — never appears in the log (red line B.7.5).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_unparseable.json"
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440022": {
      "addresses": "not-a-map",
      "metadata": {"sentinel": "must-never-be-logged"},
      "name": "sentinel-instance-label",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

PRINCIPAL="550e8400-e29b-41d4-a716-446655440022"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an instance with unreadable addresses authenticated (out=[$RUN_OUT])"
fi
pass "instance with a string `addresses` was refused (rc=$RUN_RC)"

assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup before the refusal"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "Nova answered 200 — the refusal is the gateway refusing an unreadable body"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
assert_eq "$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)" "0" \
  "the lookup must not be counted as successful"
pass "resolve counters: err=${err_total:-0} ok=0"

# The log must say *why* — `unparseable`, not the misleading `no_network`…
if ! grep -q '"reason":"unparseable"' "$SUBTOPO_DIR/gw.log"; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "gateway log does not carry reason=unparseable"
fi
pass "gateway log names reason=unparseable"
if grep -q '"reason":"no_network"' "$SUBTOPO_DIR/gw.log"; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "an unreadable body must not be reported as no_network"
fi
pass "no misleading no_network in the log"

# …but never the body itself (red line B.7.5).
for sentinel in must-never-be-logged sentinel-instance-label not-a-map; do
  if grep -q "$sentinel" "$SUBTOPO_DIR/gw.log"; then
    tail_log "$SUBTOPO_DIR/gw.log" 40
    fail "gateway log leaked body content: $sentinel"
  fi
done
pass "no body content in the log (structural summary only)"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_unparseable_loud"
