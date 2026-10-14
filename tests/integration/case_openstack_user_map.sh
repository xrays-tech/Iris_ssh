#!/usr/bin/env bash
# case_openstack_user_map.sh — plan-openstack §3.4: where the backend login user
# comes from.
#
# Two instances, one gateway:
#
#   A carries the `iris_ssh_user` metadata key and MUST log in as that user.
#   B carries no metadata and MUST fall back to `default_backend_user`.
#
# The configured default is deliberately a user that does not exist, which turns
# both rules into end-to-end assertions: A only succeeds if the metadata key was
# honoured, and B only fails if the default was applied (and its resolution must
# still count as a *successful* OpenStack resolve — the failure is downstream at
# the backend, not in the lookup).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_usermap.json"
cat > "$RULES" <<EOF
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440003": {
      "addresses": {"private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]},
      "metadata": {"iris_ssh_user": "$BACKEND_USER"},
      "name": "mapped",
      "image": {"id": "img-1"}
    },
    "550e8400-e29b-41d4-a716-446655440004": {
      "addresses": {"private": [{"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"}]},
      "metadata": {},
      "name": "default-user",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

# No legitimate backend account goes by this name: a session that reaches the
# command must therefore have used the metadata mapping, not the default.
SUBTOP_OS_DEFAULT_USER="sshgw-no-such-user"
PRINCIPAL="550e8400-e29b-41d4-a716-446655440003"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# (A) metadata wins: the session runs, as $BACKEND_USER.
run_capture subtopo_ssh_A 'printf USER_MAP_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q USER_MAP_OK; then
  pass "metadata-mapped user reached the backend"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "metadata mapping did not apply (rc=$RUN_RC out=[$RUN_OUT]) — the dial must \
have used default_backend_user=$SUBTOP_OS_DEFAULT_USER, which cannot log in"
fi

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" "\"target_user\":\"$BACKEND_USER\"" "audit names the metadata-mapped user"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the mapped session"
fi

# (B) no metadata => default_backend_user, and that is a *backend* refusal, not
# a lookup failure: the resolve counters must show a successful resolve.
PRINCIPAL="550e8400-e29b-41d4-a716-446655440004"
before_ok="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
before_err="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "the default-user instance authenticated as an unknown user (out=[$RUN_OUT])"
fi
pass "instance without metadata was refused (rc=$RUN_RC)"

after_ok="$(agent_topo_metric_value sshgw_openstack_resolve_ok_total)"
after_err="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${after_ok:-0}" -gt "${before_ok:-0}" ] || \
  fail "the default-user lookup should have succeeded (ok ${before_ok:-} -> ${after_ok:-})"
assert_eq "${after_err:-0}" "${before_err:-0}" \
  "the refusal is at the backend, so the resolve error counter must not move"
pass "resolve counters: ok ${before_ok:-}->${after_ok:-} err ${before_err:-}->${after_err:-}"

echo "OK: case_openstack_user_map"
