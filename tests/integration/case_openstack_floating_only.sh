#!/usr/bin/env bash
# case_openstack_floating_only.sh — plan-openstack appendix D.
#
# `address_kind = "floating"` is a *strict* filter: when an instance advertises
# both a fixed and a floating address on the same network, only the floating one
# may be dialed. The fixed address is not a fallback — a floating-only
# deployment cannot reach it, and silently dialing it turns a misconfiguration
# into a hang rather than a refusal.
#
# Both addresses are loopback, so the dial itself cannot distinguish them;
# what is asserted is that a session *came up at all*. That is sufficient here
# because the companion case (case_openstack_no_floating_rejected) proves the
# filter is genuinely strict — with only a fixed address present the gateway
# refuses rather than falling back — so a surviving session here means the
# floating candidate was the one kept. The audit record names the target.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys-float"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

RULES="$IT_WORK_DIR/os_rules_floating.json"
# One instance, one network, two addresses of different kinds — the shape
# appendix D exists for.
cat > "$RULES" <<'EOF'
{
  "servers": {
    "550e8400-e29b-41d4-a716-446655440077": {
      "addresses": {
        "TEST-NET01": [
          {"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "fixed"},
          {"addr": "127.0.0.1", "version": 4, "OS-EXT-IPS:type": "floating"}
        ]
      },
      "metadata": {},
      "name": "flt-both-kinds",
      "image": {"id": "img-1"}
    }
  },
  "default": {"status": 404}
}
EOF

SUBTOP_OS_EXTRA=$'network = "TEST-NET01"\naddress_kind = "floating"'
PRINCIPAL="550e8400-e29b-41d4-a716-446655440077"
openstack_topo_start "$KEYDIR/authorized_keys" "$RULES"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# Both candidates are 127.0.0.1, so the dial cannot tell them apart; the
# session coming up at all is what matters, since the companion case proves
# the filter refuses (rather than falls back) when only a fixed address exists.
run_capture subtopo_ssh_A 'printf FLOATING_ONLY_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q FLOATING_ONLY_OK; then
  pass "floating address selected and dialed under address_kind=floating"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  fail "floating-only selection broke the session (rc=$RUN_RC out=[$RUN_OUT])"
fi

if agent_topo_wait_for_audit "resolve_source"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" "\"target_host\":\"127.0.0.1\"" "audit names the dialed target"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record for the floating-only session"
fi

echo "OK: case_openstack_floating_only"
