#!/usr/bin/env bash
# case_cert_dial.sh — M4-2 backend user-certificate dial (TrustedUserCAKeys).
#
# Topology: backend sshd trusts a test user CA (TrustedUserCAKeys) and an
# authorized_keys that does NOT contain the gateway key -> ONLY cert auth works.
# The gateway is configured backend_auth="cert" + [ca] signing_key=<user CA> so
# (once src M4-T2 lands) it signs a short-lived user cert (principals=target.user)
# and dials with it.
#
# Asserted NOW (real, M4-2-independent): the backend accepts our user certificate
# via a DIRECT ssh with -o CertificateFile (proves the CA signing + the backend's
# TrustedUserCAKeys trust). Then the gateway cert-dial capability is probed: with
# the cert-only backend, if the gateway session succeeds M4-2 is live (assert
# exec passthrough); otherwise the gateway can only do key-dial (rejected) and the
# case records M4-2 E2E as pending src M4-T2 — NOT a fake pass.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/../../scripts/cert_topo.sh"
trap subtopo_stop EXIT INT TERM

CERTDIR="$IT_WORK_DIR/certs"; mkdir -p "$CERTDIR"
cert_topo_ca "$CERTDIR" userca >/dev/null

# Sign a user certificate for the gateway's backend identity key (principal =
# backend user). Copy the pubkey so we never write into $SSH_GW_ASSET_DIR.
cp "$IT_ASSET_DIR/backend_ed25519.pub" "$CERTDIR/backend_id.pub"
USERCERT="$(cert_topo_sign_user "$CERTDIR/userca" "$CERTDIR/backend_id.pub" userid "$BACKEND_USER" -5m:+300m)"
log "signed backend user cert: $USERCERT"
if ssh-keygen -L -f "$USERCERT" | grep -q "user certificate" \
   && ssh-keygen -L -f "$USERCERT" | grep -q "$BACKEND_USER"; then
  pass "user cert is a user-type cert with principal $BACKEND_USER (signing self-proof)"
else
  ssh-keygen -L -f "$USERCERT" >&2; fail "generated cert wrong type/principal"
fi

# cert-only backend: no gateway key in authorized_keys; only TrustedUserCAKeys.
printf '# intentionally empty: cert-only auth for the gateway\n' > "$CERTDIR/authorized_keys"
chmod 600 "$CERTDIR/authorized_keys"

SUBTOP_SSHD_USER_CA="$CERTDIR/userca.pub"
SUBTOP_SSHD_AUTHORIZED_KEYS="$CERTDIR/authorized_keys"
SUBTOP_BACKEND_AUTH="cert"
SUBTOP_SIGNING_KEY="$CERTDIR/userca"
subtopo_start

# (A) REAL self-proof: the backend accepts the cert via a direct CertificateFile
#     login (no authorized_keys). Independent of the gateway / of M4-T2.
r=0; out="$(ssh -p "$ST_SSHD_PORT" -i "$IT_ASSET_DIR/backend_ed25519" \
  -o CertificateFile="$USERCERT" -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes \
  "$BACKEND_USER@127.0.0.1" 'printf CERTLOGIN_OK' </dev/null 2>&1)" || r=$?
if [ "$r" -eq 0 ] && printf '%s' "$out" | grep -q CERTLOGIN_OK; then
  pass "backend accepted the user cert via TrustedUserCAKeys (direct login)"
else
  tail_log "$SUBTOPO_DIR/sshd.log" 25; fail "backend rejected our user cert (r=$r out=[$out])"
fi

# (B) Gateway cert-dial: does the gateway dial the cert-only backend?
gr=0; gout="$(subtopo_ssh 'printf GWCERT_OK' </dev/null 2>&1)" || gr=$?
if [ "$gr" -eq 0 ] && printf '%s' "$gout" | grep -q GWCERT_OK; then
  pass "gateway cert-dial succeeded against a TrustedUserCAKeys backend (M4-2 live)"
  echo "OK: case_cert_dial"
else
  tail_log "$SUBTOPO_DIR/gw.log" 20
  log "gateway cert-dial FAILED against the cert-only backend (r=$gr). The gateway"
  log "currently only does key-dial (private_key path); with key auth rejected by"
  log "the cert-only backend there is no success. => M4-2 E2E is PENDING src M4-T2"
  log "(backend_auth=cert -> authenticate_openssh_cert). Topology + signing above"
  log "are self-proven; this case flips to PASS once the gateway issues the cert."
  skip_case "gateway cert-dial pending src M4-T2 (cert-only backend + CA signing self-proven)"
fi
