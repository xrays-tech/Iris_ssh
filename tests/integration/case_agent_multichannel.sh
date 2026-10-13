#!/usr/bin/env bash
# case_agent_multichannel.sh — D2: one client connection carrying several
# session channels all ride the same agent supervisor.
#
# Topology: identical to case_agent_auth — the backend's authorized_keys holds
# ONLY the end user's key, backend_auth="agent" with the instance kill-switch
# on, and the control-plane grant allows agent forwarding.
#
# The client opens one SSH connection with OpenSSH's ControlMaster (`ssh -M`),
# whose master runs a long-lived remote command on session channel #1 with -A.
# Two later `ssh -S <sock> ...` slaves multiplex over that *same* connection,
# so the gateway sees channel #2 and #3 on a session that has already handed
# channel #1 to the supervisor. Before D2 the second channel fell back to the
# inline path, which cannot dial an agent-only backend; after D2 it must be
# served by the same supervisor.
#
# Asserted: both slave commands return the right output, there is exactly ONE
# backend dial and ONE agent signature for the whole connection (channels share
# one backend session — they do not re-authenticate per channel), and no agent
# channel is denied.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/agent-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"
agent_topo_start "$KEYDIR/authorized_keys"

subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

MC_SOCK="$IT_WORK_DIR/mc.sock"
MC_TARGET="$PRINCIPAL@127.0.0.1"

# gw_ssh [ssh-options...] <dest> <cmd> — the same connection options subtopo_ssh
# uses, spelled out here because the master needs -M/-S/-f on top of them.
gw_ssh() {
  ssh -p "$ST_GW_PORT" -i "$USER_KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
    "$@"
}
mc_close() { ssh -S "$MC_SOCK" -O exit "$MC_TARGET" </dev/null >/dev/null 2>&1 || true; }
trap 'mc_close; subtopo_agent_stop; subtopo_stop' EXIT INT TERM

# (A) Master: session channel #1, agent forwarded, held open in the background.
if ! gw_ssh -M -S "$MC_SOCK" -f -A "$MC_TARGET" 'sleep 300'; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "could not open the ControlMaster session over the gateway"
fi
pass "ControlMaster session established (channel #1)"

# (B) Two further session channels on the same connection. Deliberately NOT
# preceded by a readiness wait: the slaves are launched as soon as `-f` returns,
# so channel #2 usually lands while the backend handshake is still in flight and
# the supervisor has to accept-and-queue it (plan-agent-only key decision 2).
# Either ordering must work; waiting for the dial first would only ever exercise
# the easy one.
out_one=""
if out_one="$(gw_ssh -S "$MC_SOCK" "$MC_TARGET" 'printf MC_ONE')"; then
  assert_contains "$out_one" "MC_ONE" "channel #2 produced its own output"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "channel #2 (first non-initial channel) failed — the supervisor did not open a \
second backend session channel"
fi
pass "channel #2 executed over the shared backend session"

out_two=""
if out_two="$(gw_ssh -S "$MC_SOCK" "$MC_TARGET" 'printf MC_TWO')"; then
  assert_contains "$out_two" "MC_TWO" "channel #3 produced its own output"
  assert_not_contains "$out_one" "MC_TWO" "channel #3 output did not leak into channel #2"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "channel #3 failed"
fi
pass "channel #3 executed over the shared backend session"

# (C) One connection means one backend dial and one signature: the channels are
# multiplexed onto an already-authenticated backend session, not re-dialed.
ok_total=""
for _ in $(seq 1 60); do
  ok_total="$(agent_topo_metric_value sshgw_agent_backend_auth_ok_total)"
  [ "${ok_total:-0}" = "1" ] && break
  sleep 0.25
done
[ "${ok_total:-0}" = "1" ] || fail "backend agent dial never completed (got [${ok_total:-}])"
dial_total="$(agent_topo_metric_value sshgw_backend_dial_ok_total)"
sig_total="$(agent_topo_metric_value sshgw_agent_signatures_total)"
denied_total="$(agent_topo_metric_value sshgw_agent_channel_denied_total)"
fail_total="$(agent_topo_metric_value sshgw_agent_backend_auth_fail_total)"
[ "${ok_total:-0}" = "1" ] || fail "expected 1 agent dial, got [${ok_total:-}]"
[ "${dial_total:-0}" = "1" ] || fail "expected 1 backend dial for 3 channels, got [${dial_total:-}]"
[ "${sig_total:-0}" = "1" ] || fail "expected 1 agent signature for 3 channels, got [${sig_total:-}]"
[ "${denied_total:-0}" = "0" ] || fail "expected no denied agent channel, got [${denied_total:-}]"
[ "${fail_total:-0}" = "0" ] || fail "expected no failed agent dial, got [${fail_total:-}]"
pass "metrics: dial=$dial_total auth_ok=$ok_total sig=$sig_total denied=$denied_total fail=$fail_total"

mc_close

# (D) The audit record still describes the whole connection as one agent session.
if agent_topo_wait_for_audit "auth_kind"; then
  audit="$(agent_topo_audit_json)"
  assert_contains "$audit" '"auth_kind":"agent"' "audit record reports auth_kind=agent"
  assert_contains "$audit" '"agent_signatures":1' "audit record counts a single signature"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "no audit record in the gateway log"
fi

echo "OK: case_agent_multichannel"
