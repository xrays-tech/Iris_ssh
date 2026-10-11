#!/usr/bin/env bash
# case_host_cert_authority.sh — M4-1 backend host certificate (@cert-authority
# readiness). Stands up a backend sshd that PRESENTS a host certificate
# (`HostCertificate`), signed by a test CA with `ssh-keygen -s ... -h`, and points
# the gateway's `[ca] trusted_ca_keys` at that CA.
#
# Asserted NOW (real, M4-independent): the host-cert topology works and the
# gateway's client leg consumes a certificate during KEX — an exec through the
# gateway to a host-cert backend returns cleanly. This is the enabler for the
# M4-1 @cert-authority four-step verification chain.
#
# M4-1 rejection negatives (untrusted CA / expired / principals-without-host) are
# only meaningful once the gateway verifies certs against trusted_ca_keys
# (src M4-T1). Today the gateway trusts by inner-key fingerprint (accept-new), so
# those negatives are detected-and-deferred (NOT faked). The signing recipe is
# ready via scripts/cert_topo.sh for M4-V to enable verbatim.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/../../scripts/cert_topo.sh"
trap subtopo_stop EXIT INT TERM

CERTDIR="$IT_WORK_DIR/certs"; mkdir -p "$CERTDIR"
cert_topo_ca "$CERTDIR" hostca >/dev/null      # the CA the gateway should trust (M4-1)
cert_topo_ca "$CERTDIR" evilca >/dev/null      # untrusted CA, for the M4-1 negatives

# sshd requires the cert next to a host key of the same basename; copy the shared
# host key into CERTDIR so we never write into $SSH_GW_ASSET_DIR.
cp "$IT_ASSET_DIR/sshd_host_ed25519"     "$CERTDIR/sshd_host_ed25519"
cp "$IT_ASSET_DIR/sshd_host_ed25519.pub" "$CERTDIR/sshd_host_ed25519.pub"
HCERT="$(cert_topo_sign_host "$CERTDIR/hostca" "$CERTDIR/sshd_host_ed25519.pub" hostid 127.0.0.1,localhost -5m:+300m)"
log "signed backend host cert: $HCERT"
if ssh-keygen -L -f "$HCERT" | grep -q "host certificate" \
   && ssh-keygen -L -f "$HCERT" | grep -q "127.0.0.1"; then
  pass "host cert is a host-type cert for 127..0.1 (topology self-proof)"
else
  ssh-keygen -L -f "$HCERT" >&2; fail "generated cert is not a valid host cert for 127.0.0.1"
fi
[ -f "$HCERT" ] || fail "host cert missing"

# gateway_rejects_untrusted: serve an evil-CA cert and report whether the gateway
# refuses to reach the backend (a live M4-1 chain does; accept-new does not).
gateway_rejects_untrusted() {
  local evil; evil="$(cert_topo_sign_host "$CERTDIR/evilca" "$CERTDIR/sshd_host_ed25519.pub" evil 127.0.0.1 -5m:+300m 2>/dev/null)"
  [ -n "$evil" ] && [ -f "$evil" ] || return 1
  SUBTOP_SSHD_HOST_CERT="$evil"; subtopo_start 2>/dev/null || { subtopo_stop; return 1; }
  local out rc=0; out="$(subtopo_ssh 'printf REACHED' </dev/null 2>&1)" || rc=$?
  subtopo_stop
  SUBTOP_SSHD_HOST_CERT="$HCERT"; subtopo_start 2>/dev/null || true
  case "$out" in *REACHED*) return 1 ;; *) return 0 ;; esac   # no reach => rejected
}

SUBTOP_SSHD_HOSTKEY="$CERTDIR/sshd_host_ed25519"
SUBTOP_SSHD_HOST_CERT="$HCERT"
SUBTOP_TRUSTED_CA_KEYS="$CERTDIR/hostca.pub"
subtopo_start

# REAL positive: KEX over a host-cert backend succeeds through the gateway.
r=0; out="$(subtopo_ssh 'printf CONNECT_OK' </dev/null 2>&1)" || r=$?
if [ "$r" -eq 0 ] && printf '%s' "$out" | grep -q CONNECT_OK; then
  pass "gateway connected + exec over a host-cert backend (cert consumed during KEX)"
else
  tail_log "$SUBTOPO_DIR/gw.log" 30; tail_log "$SUBTOPO_DIR/sshd.log" 20
  fail "gateway could not connect to a host-cert backend (r=$r out=[$out])"
fi

# M4-1 rejection negatives: the gateway performs CA-based verification (M4-T1
# landed), so an untrusted-CA host cert MUST be refused — hard assertion, no
# defer. This is a once-live regression guard: if someone later breaks the cert
# branch or has_trusted_ca() wiring, this case FAILs loudly instead of silently
# degrading to "pending".
if gateway_rejects_untrusted; then
  pass "gateway performs @cert-authority rejection (untrusted CA refused)"
else
  tail_log "$SUBTOPO_DIR/gw.log" 30; tail_log "$SUBTOPO_DIR/sshd.log" 20
  fail "gateway TRUSTED an untrusted-CA host cert — @cert-authority chain not enforced"
fi
echo "OK: case_host_cert_authority"
