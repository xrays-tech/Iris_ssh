#!/usr/bin/env bash
# scripts/cert_topo.sh — certificate-topology helpers for the M4 backend tests
# (source-only). Generates test CAs and signs host/user certificates with
# `ssh-keygen`, so the integration cases can stand up:
#   * M4-1  backend host certificate (ssh HostCertificate) + gateway is pointed
#           at the CA for its @cert-authority four-step verification chain;
#   * M4-2  backend TrustedUserCAKeys user certificate (gateway cert-dial).
# Everything is created under a caller-provided dir (idempotent); no system
# sshd / no $SSH_GW_ASSET_DIR is touched. macOS ssh-keygen supports the flags
# used here (`-s -h -n -V -I`).
#
# Sourced lib of functions:
#   cert_topo_ca <dir> <name>
#   cert_topo_sign_host <ca_priv> <key_pub_path(.pub)> <id> <principals_csv> <validity>
#   cert_topo_sign_user <ca_priv> <key_pub_path(.pub)> <id> <principals_csv> <validity>
# sign_* echo the resulting <...>-cert.pub path.
set -uo pipefail

# cert_topo_ca <dir> <name> -> generates <dir>/<name> (CA private) + .pub
cert_topo_ca() {
  local dir="$1" name="$2"
  [ -n "$dir" ] && [ -n "$name" ] || { echo "cert_topo_ca: need <dir> <name>" >&2; return 1; }
  mkdir -p "$dir"
  [ -f "$dir/$name" ] || ssh-keygen -q -t ed25519 -N "" -C "${name}" -f "$dir/$name"
  chmod 600 "$dir/$name" 2>/dev/null || true
  echo "$dir/$name"
}

# _cert_sign <h|u> <ca_priv> <key_pub> <id> <principals_csv> <validity>
# Writes <key_base>-cert.pub next to <key_pub>; echoes the cert path.
_cert_sign() {
  local mode="$1" ca="$2" keypub="$3" id="$4" princ="$5" valid="$6"
  local base="${keypub%.pub}"
  # -h for host cert; combine with the key .pub. ssh-keygen writes <base>-cert.pub.
  ssh-keygen -q -s "$ca" "-$mode" -I "$id" -n "$princ" -V "$valid" "$keypub" >/dev/null 2>&1 || {
    echo "ssh-keygen cert signing failed (mode=$mode ca=$ca key=$keypub)" >&2; return 1; }
  echo "${base}-cert.pub"
}
cert_topo_sign_host() { _cert_sign h "$@"; }
cert_topo_sign_user() { _cert_sign u "$@"; }

# Standalone self-proof: `cert_topo.sh selftest <dir>` signs a host + user cert
# and prints `ssh-keygen -L` verification.
if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
  cmd="${1:-selftest}"; dir="${2:-${TMPDIR:-/tmp}/cert-topo.$$}"
  case "$cmd" in
    selftest)
      cert_topo_ca "$dir" hostca >/dev/null
      cert_topo_ca "$dir" userca >/dev/null
      ssh-keygen -q -t ed25519 -N "" -C h -f "$dir/host" 
      ssh-keygen -q -t ed25519 -N "" -C u -f "$dir/u"
      hc="$(cert_topo_sign_host "$dir/hostca" "$dir/host.pub" hostid 127.0.0.1,localhost -5m:+300m)"
      uc="$(cert_topo_sign_user "$dir/userca" "$dir/u.pub" userid alex -5m:+300m)"
      echo "== host cert ($hc) =="; ssh-keygen -L -f "$hc" | sed -n '1,6p'
      echo "== user cert ($uc) =="; ssh-keygen -L -f "$uc" | sed -n '1,6p'
      echo "selftest ok: $dir" ;;
    *) echo "usage: cert_topo.sh selftest [dir]" >&2 ;;
  esac
fi
