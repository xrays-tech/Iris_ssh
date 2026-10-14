#!/usr/bin/env bash
# case_openstack_preauth_no_lookup.sh — plan-openstack MUST1: the
# pre-authentication `publickey` probe must never touch the network.
#
# The gateway answers `SSH2_MSG_USERAUTH_PK_OK` for a key whose *shape* is
# acceptable before any signature exists. In OpenStack routing the principal is
# an instance UUID, so a lookup at that point would (a) leak a Nova request for
# an unauthenticated peer and (b) make the probe as expensive as a login. The
# red line: `auth_publickey_offered` runs only the pure routing predicate.
#
# The client here holds an **encrypted** key under `BatchMode=yes`: it can offer
# the public key but can never sign, so the session is guaranteed to die after
# the probe. What must be true then is:
#
#   1. zero Nova and zero Keystone requests were made;
#   2. the probe really happened (`sshgw_auth_offered_total` moved), so the
#      zero above is not an idle no-op;
#   3. the very same topology, retried with a signable key, *does* look the
#      instance up — proving the mock was reachable all along.
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

# A key the client can offer but never sign: BatchMode forbids the passphrase
# prompt, so authentication is doomed the moment a signature is required.
ENC="$KEYDIR/preauth_ed25519"
ssh-keygen -q -t ed25519 -N 'preauth-probe' -C 'preauth-probe' -f "$ENC"

run_capture ssh -p "$ST_GW_PORT" -i "$ENC" -A \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
  "$PRINCIPAL@127.0.0.1" 'printf SHOULD_NOT_RUN'
if [ "$RUN_RC" -eq 0 ]; then
  fail "an unsigned probe alone authenticated (out=[$RUN_OUT])"
fi
pass "probe-only client could not authenticate (rc=$RUN_RC)"

# (1) No lookup: the routing predicate is pure, so nothing was dialed.
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "0" \
  "the pre-auth probe must not reach Nova"
assert_eq "$(subtopo_os_count POST /v3/auth/tokens)" "0" \
  "the pre-auth probe must not fetch a Keystone token"

# (2) The probe did happen, and the gateway is alive.
offered="$(agent_topo_metric_value sshgw_auth_offered_total)"
[ "${offered:-0}" -ge 1 ] || \
  fail "expected sshgw_auth_offered_total >= 1, got [${offered:-}] — the zero above \
would be meaningless if no probe was ever offered"
pass "sshgw_auth_offered_total=$offered (probe served, zero lookups)"

# (3) Control run: the same principal on the same topology, with a signable
# key, must now produce exactly one Nova lookup.
run_capture subtopo_ssh_A 'printf PREAUTH_CONTROL_OK'
if [ "$RUN_RC" -eq 0 ] && printf '%s' "$RUN_OUT" | grep -q PREAUTH_CONTROL_OK; then
  pass "control session with a signable key succeeded"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/os.log" 25
  fail "control session failed (rc=$RUN_RC out=[$RUN_OUT]) — the mock was never reachable"
fi
assert_eq "$(subtopo_os_count GET /v2.1/servers/)" "1" \
  "the signed attempt performed the lookup the probe must not"
assert_eq "$(subtopo_os_statuses GET /v2.1/servers/)" "200" \
  "and the lookup succeeded, so the mock was reachable all along"

echo "OK: case_openstack_preauth_no_lookup"
