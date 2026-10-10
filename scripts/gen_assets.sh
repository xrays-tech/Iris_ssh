#!/usr/bin/env bash
# scripts/gen_assets.sh — generate the SSH key material + authorized_keys for a
# fresh integration run. Idempotent (safe to re-source). Callers must `set -u`.
#
# Produces, inside $1 (the asset dir):
#   hostkey_ed25519{,.pub}      gateway -> client host key (server leg)
#   backend_ed25519{,.pub}      gateway -> backend private key (client leg)
#   user_ed25519{,.pub}         client (test harness) -> gateway user key
#   sshd_host_ed25519{,.pub}    backend sshd host key (distinct from gateway's)
#   authorized_keys             contains backend_ed25519.pub (gateway may log in)
#
# All private keys are unencrypted ed25519 in OpenSSH format (mode 0600), which
# russh-keys can load directly and which satisfies the gateway's own 0600
# credential validation (plan M1-T2).
set -euo pipefail

gen_assets() {
  local dir="$1"
  [ -n "$dir" ] || { echo "gen_assets: missing dir" >&2; return 1; }
  mkdir -p "$dir"
  chmod 700 "$dir"

  local name
  for name in hostkey_ed25519 backend_ed25519 user_ed25519 sshd_host_ed25519; do
    if [ ! -f "$dir/$name" ]; then
      ssh-keygen -q -t ed25519 -N "" -C "sshgw-${name%_ed25519}" -f "$dir/$name" \
        >/dev/null
    fi
    chmod 600 "$dir/$name"
  done

  # authorized_keys for the backend login user == the gateway's backend pubkey.
  if [ ! -f "$dir/authorized_keys" ]; then
    cp "$dir/backend_ed25519.pub" "$dir/authorized_keys"
  fi
  chmod 600 "$dir/authorized_keys"
}

# Allow standalone execution for manual inspection / debugging.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  target="${1:-${TMPDIR:-/tmp}/sshgw-assets.$$}"
  gen_assets "$target"
  echo "assets written to: $target" >&2
fi
