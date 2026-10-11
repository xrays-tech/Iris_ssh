#!/usr/bin/env bash
# case_client_matrix.sh — A4 client-compatibility matrix (spike S3). Real Windows
# clients (PuTTY / WinSCP / Windows OpenSSH) are not present in this CI host, so
# we simulate each one's most-restrictive algorithm set with OpenSSH `-o`
# overrides that force the negotiated KEX/host-key/cipher/MAC to a set those
# clients commonly use. A successful connect+exec then proves the GATEWAY (russh
# leg) negotiates that combination. Each list includes a curve25519 fallback the
# client and gateway share, so a failure means a genuine negotiation gap.
#
# Limitation: this validates the GATEWAY's algorithm acceptance, not the real
# clients' full stack (auth UI, key formats, banners). See docs/client-matrix.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

try_profile() {  # try_profile <label> [ssh -o opts...]
  local label="$1"; shift
  local rc=0 out
  out="$(ssh "${SSH_OPTS[@]}" "$@" "$TARGET" 'printf CONNECT_OK' 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q CONNECT_OK; then
    pass "profile $label: connected + exec (algorithms negotiated)"
  else
    fail "profile $label: connect/exec failed rc=$rc out=[$out]"
  fi
}

# OpenSSH 8.x-ish: curve25519, aes256-ctr, hmac-sha2-256.
try_profile "openssh8" \
  -o KexAlgorithms=curve25519-sha256 \
  -o Ciphers=aes256-ctr \
  -o MACs=hmac-sha2-256

# OpenSSH 9.x-ish: default chacha20 + ETM mac (sntrup offered, curve25519 fallback).
try_profile "openssh9" \
  -o KexAlgorithms=sntrup761x25519-sha512@openssh.com,curve25519-sha256 \
  -o Ciphers=chacha20-poly1305@openssh.com \
  -o MACs=hmac-sha2-256-etm@openssh.com

# PuTTY curl: ecdh-nistp256 or curve25519, ed25519/rsa host key, aes*-ctr, hmac-sha2-256.
try_profile "putty" \
  -o KexAlgorithms=ecdh-sha2-nistp256,curve25519-sha256 \
  -o HostKeyAlgorithms=ssh-ed25519,rsa-sha2-512 \
  -o Ciphers=aes128-ctr,aes256-ctr \
  -o MACs=hmac-sha2-256

# WinSCP default-ish: ecdh/curve25519, aes256-ctr, hmac-sha2-256.
try_profile "winscp" \
  -o KexAlgorithms=ecdh-sha2-nistp256,curve25519-sha256 \
  -o Ciphers=aes256-ctr \
  -o MACs=hmac-sha2-256

echo "OK: case_client_matrix"
