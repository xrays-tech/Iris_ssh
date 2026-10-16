#!/usr/bin/env bash
# case_backend_rsa_signer.sh — plan-openstack E.4: the gateway signs the
# backend publickey authentication with the forwarded agent's RSA key using
# rsa-sha2-512 (E.1's default) and never with SHA-1 ssh-rsa (red line 1:
# no fallback path exists).
#
# Topology: agent-key-only backend where the end user's key is RSA — the
# same shape appendix E starts from the real-machine failure with. Three
# gates, in the order the plan lists them:
#   (0) the backend sshd refuses ssh-rsa (otherwise a SHA-1 signature would
#       still be accepted and this case could not see the regression, R27);
#   (1) the session runs end to end through the gateway's agent signature;
#   (2) the gateway's debug log records hash_alg=Some(Sha512) for the
#       backend publickey auth (RUST_LOG=backend=debug below).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/backend-rsa-signer-keys"; mkdir -p "$KEYDIR"
ssh-keygen -t rsa -b 3072 -N '' -q -f "$KEYDIR/id_rsa"

# Emit the backend-leg decision line (plan-openstack E.1 debug log).
export RUST_LOG="backend=debug,info"

agent_topo_backend_keys "$KEYDIR/authorized_keys" "$KEYDIR/id_rsa.pub"
agent_topo_start "$KEYDIR/authorized_keys"
subtopo_agent_start "$KEYDIR/id_rsa"

# (0) Precondition: modern sshd posture — no ssh-rsa among the accepted
# publickey signature algorithms. Without this the case would pass even if
# the gateway signed with SHA-1 (R27: silent vacuousness).
accepted="$(/usr/sbin/sshd -T -f "$SUBTOPO_DIR/sshd.cfg" | grep -i '^pubkeyacceptedalgorithms ' || true)"
if [ -z "$accepted" ]; then
  fail "could not read pubkeyacceptedalgorithms from the backend sshd config"
fi
case "$accepted" in
  *ssh-rsa*)
    tail_log "$SUBTOPO_DIR/sshd.log" 20
    fail "backend sshd accepts ssh-rsa, so sha1 signatures would pass unnoticed: [$accepted]" ;;
esac
printf '%s' "$accepted" | grep -q "rsa-sha2-512" \
  || fail "backend sshd must accept rsa-sha2-512: [$accepted]"
pass "backend sshd posture: ${accepted#pubkeyacceptedalgorithms }"

# (1) End to end: client authenticates to the front leg with the RSA key,
# the agent (holding the same RSA key) signs the backend leg through the
# gateway, and the modern backend sshd accepts it — only possible if that
# signature was rsa-sha2, not ssh-rsa.
rc=0
out="$(ssh -p "$ST_GW_PORT" -i "$KEYDIR/id_rsa" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -o ForwardAgent=yes \
  -o ConnectTimeout=15 -o LogLevel=ERROR \
  "$PRINCIPAL@127.0.0.1" 'printf RSA_BACKEND_OK' 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q RSA_BACKEND_OK; then
  pass "RSA agent key signed the backend auth and the session ran"
else
  tail_log "$SUBTOPO_DIR/gw.log" 40
  tail_log "$SUBTOPO_DIR/sshd.log" 25
  fail "RSA backend session failed (rc=$rc out=[$out]) — either the gateway signed \
ssh-rsa (rejected by the modern sshd) or agent passthrough is broken"
fi

# (2) Observability: the gateway's backend-leg log names the hash it asked
# the agent to sign with. Some(Sha512) is E.1's default for RSA.
for _ in $(seq 1 40); do
  if grep -q '"hash_alg":"Some(Sha512)"' "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
    break
  fi
  sleep 0.25
done
if ! grep -q '"hash_alg":"Some(Sha512)"' "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
  tail_log "$SUBTOPO_DIR/gw.log" 60
  fail "gateway never logged hash_alg=Some(Sha512) for the backend publickey auth"
fi
pass "gateway debug log records hash_alg=Some(Sha512)"
if grep -q '"hash_alg":"Some(Sha256)"' "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
  fail "backend auth asked for sha256 — the default posture must be sha512"
fi

echo "OK: case_backend_rsa_signer"
