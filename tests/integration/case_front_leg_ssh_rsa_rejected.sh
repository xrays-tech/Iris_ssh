#!/usr/bin/env bash
# case_front_leg_ssh_rsa_rejected.sh — plan-openstack E.3: the front leg
# refuses the legacy SHA-1 `ssh-rsa` algorithm by default (no config knob).
# The gateway strips `Rsa { hash: None }` from russh's default
# `preferred.key`, so neither the KEX host-key offer nor the
# `server-sig-algs` extension carries "ssh-rsa"; rsa-sha2-512/256 stay.
# Independent revertable change (E.6.1-7).
#
# Topology: agent-key-only backend whose end-user key is RSA, plus an RSA
# GATEWAY HOST KEY. The host key matters: OpenSSH couples a client's
# host-key algorithms to PubkeyAcceptedAlgorithms, so a SHA-1-only client
# (PubkeyAcceptedAlgorithms=ssh-rsa) can only be exercised against a server
# that pre-E.3 would offer ssh-rsa at all — without it the pre-E.3 and
# post-E.3 offers would be identical and this test could not pin E.3.
#
# Asserted: the RSA key succeeds under default negotiation (rsa-sha2
# control), while the SHA-1-only client is refused during negotiation and
# the server's offer it quotes contains rsa-sha2-512 but no ssh-rsa.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

KEYDIR="$IT_WORK_DIR/front-sha1-keys"; mkdir -p "$KEYDIR"
ssh-keygen -t rsa -b 3072 -N '' -q -f "$KEYDIR/id_rsa"
ssh-keygen -t rsa -b 3072 -N '' -q -f "$KEYDIR/hostkey_rsa"
# Must be set BEFORE subtopo.sh is sourced (it default-initializes on source).
SUBTOP_HOSTKEY="$KEYDIR/hostkey_rsa"

. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

agent_topo_backend_keys "$KEYDIR/authorized_keys" "$KEYDIR/id_rsa.pub"
agent_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$KEYDIR/id_rsa"

# Mirror subtopo_ssh with the RSA identity instead of $USER_KEY: with
# IdentitiesOnly=yes the agent's (RSA) key is the only identity offered.
run_rsa() {  # run_rsa <remote-command...>
  ssh -p "$ST_GW_PORT" -i "$KEYDIR/id_rsa" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ForwardAgent=yes \
    -o ConnectTimeout=15 -o LogLevel=ERROR \
    "$PRINCIPAL@127.0.0.1" "$@"
}

# (A) Control: the RSA key is legitimate — default negotiation picks
# rsa-sha2-512 (host and user) and the session runs end to end.
rc=0
out="$(run_rsa 'printf RSA_SHA2_OK' 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q RSA_SHA2_OK; then
  pass "RSA client key authenticates via rsa-sha2 (setup control)"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "RSA control session failed (rc=$rc out=[$out]) — without this the \
sha1 rejection below would prove nothing about the algorithm policy"
fi

# (B) Negative: a SHA-1-only client — the profile of a pre-7.8 OpenSSH that
# knows only ssh-rsa for host keys AND user signatures. Two knobs together:
#   PubkeyAcceptedAlgorithms=ssh-rsa  pins userauth (and, via OpenSSH's
#                                     hostkeyalgs ∩ pubkey_accepted coupling,
#                                     host keys) to ssh-rsa;
#   HostKeyAlgorithms=+ssh-rsa        re-adds ssh-rsa to the host-key side,
#                                     which modern defaults removed — without
#                                     it the client's host-key set is empty
#                                     and it would fail at KEX even against
#                                     an unfiltered gateway (making this case
#                                     blind to E.3).
# Pre-E.3 the gateway offers ssh-rsa everywhere, so this client completes a
# session (that is exactly what the case must catch). Post-E.3 the offer
# carries rsa-sha2 only and negotiation must refuse.
# LogLevel=DEBUG1 comes FIRST on purpose: the "Unable to negotiate ...
# Their offer:" line is only emitted at debug verbosity, and the first
# -o LogLevel wins.
rc=0
out="$(ssh -o LogLevel=DEBUG1 -p "$ST_GW_PORT" -i "$KEYDIR/id_rsa" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=15 \
  -o PubkeyAcceptedAlgorithms=ssh-rsa -o HostKeyAlgorithms=+ssh-rsa \
  "$PRINCIPAL@127.0.0.1" 'printf SHA1_OK' 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] || printf '%s' "$out" | grep -q SHA1_OK; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "front leg completed a session for a sha1-only client (rc=$rc) — E.3 tightening missing"
fi
pass "sha1-only client refused (rc=$rc)"

# (C) The refusal is the E.3 algorithm policy, not a generic error: the
# negotiation failure must quote the server's offer, which carries rsa-sha2
# but no ssh-rsa (pre-E.3 it would still list ssh-rsa and this case fails).
if ! printf '%s' "$out" | grep -q "no matching host key type"; then
  fail "expected a host-key negotiation refusal, got: [$(printf '%s' "$out" | tail -5)]"
fi
offer="$(printf '%s' "$out" | grep "Their offer:" | tail -1)"
if printf '%s' "$offer" | grep -q "ssh-rsa"; then
  fail "server still offers ssh-rsa — E.3 tightening missing: [$offer]"
fi
if ! printf '%s' "$offer" | grep -q "rsa-sha2-512"; then
  fail "rsa-sha2-512 must still be offered: [$offer]"
fi
pass "server offer has rsa-sha2-512 but no ssh-rsa: $(printf '%s' "$offer" | sed 's/.*Their offer: //')"

echo "OK: case_front_leg_ssh_rsa_rejected"
