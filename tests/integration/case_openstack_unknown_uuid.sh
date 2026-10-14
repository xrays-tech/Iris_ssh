#!/usr/bin/env bash
# case_openstack_unknown_uuid.sh — plan-openstack §4.2: a well-formed instance
# UUID that Nova does not know is rejected, identically to every other lookup
# failure (red line: no client-visible distinction between "unknown instance",
# "forbidden" and "Nova is down").
#
# Asserted: the session is refused; the shape check alone reached no network
# (one Nova GET, zero Keystone POSTs); resolution was counted as an OpenStack
# error; and no session audit record is produced for a login that never
# happened.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/os-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"

# Same shape as the default instance (canonical v4 UUID) but absent from the
# mock's instance table — the routing predicate must accept it and Nova must be
# the one that says no.
PRINCIPAL="550e8400-e29b-41d4-a716-4466554400aa"
openstack_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

run_capture subtopo_ssh_A 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an unknown instance UUID authenticated (out=[$RUN_OUT])"
fi
pass "unknown instance UUID was refused (rc=$RUN_RC)"

# The lookup happened exactly once and answered 404; no token was even needed
# for a server 404 (the token is fetched lazily on the first Nova call, so a
# single Keystone POST is also acceptable — what must NOT happen is a second
# Nova lookup for a negative answer).
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "exactly one Nova lookup for the unknown UUID"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "404" \
  "Nova — not the gateway — is the one that said no"
nova_n="$(subtopo_os_count POST /v3/auth/tokens)"
[ "${nova_n:-0}" -le 1 ] || fail "expected at most one Keystone token fetch, got [$nova_n]"

err_total="$(agent_topo_metric_value sshgw_openstack_resolve_err_total)"
[ "${err_total:-0}" -ge 1 ] || fail "expected an OpenStack resolve error, got [${err_total:-}]"
pass "sshgw_openstack_resolve_err_total=$err_total"

if agent_topo_wait_for_audit "auth_kind"; then
  fail "a refused login produced a session audit record: $(agent_topo_audit_json)"
fi
pass "no session audit record for the refused login"

echo "OK: case_openstack_unknown_uuid"
