#!/usr/bin/env bash
# case_scp.sh — scp over the gateway. OpenSSH >=9 defaults scp to the SFTP
# subsystem, so this exercises the same subsystem path as sftp (new code path),
# not the legacy scp-1 text protocol.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

local_file="$IT_WORK_DIR/scp_payload.local"
remote_file="$IT_WORK_DIR/scp_payload.remote"
down_file="$IT_WORK_DIR/scp_payload.down"

head -c 20000 /dev/urandom > "$local_file"

# upload
assert_rc0 scp "${SCP_OPTS[@]}" -q "$local_file" "$TARGET:$remote_file"
# download
assert_rc0 scp "${SCP_OPTS[@]}" -q "$TARGET:$remote_file" "$down_file"

if cmp -s "$local_file" "$down_file"; then
  pass "scp round-trip byte-identical ($(wc -c < "$local_file" | tr -d ' ') bytes)"
else
  fail "scp round-trip mismatch: local vs downloaded differ"
fi
# tidy the remote copy (also lives under IT_WORK_DIR so orchestrator cleans it).
ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f '$remote_file'" >/dev/null 2>&1 || true
echo "OK: case_scp"
