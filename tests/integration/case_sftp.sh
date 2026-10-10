#!/usr/bin/env bash
# case_sftp.sh — sftp subsystem passthrough (propose §3.7). Put a small binary
# file through the gateway and fetch it back; bytes must round-trip intact.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

local_file="$IT_WORK_DIR/sftp_payload.local"
remote_file="$IT_WORK_DIR/sftp_payload.remote"
down_file="$IT_WORK_DIR/sftp_payload.down"
sftp_log="$IT_WORK_DIR/sftp.log"

# 16 KiB of random bytes so any corruption is caught by content compare.
head -c 16384 /dev/urandom > "$local_file"

rc=0
sftp "${SFTP_OPTS[@]}" -b - "$TARGET" >"$sftp_log" 2>&1 <<BATCH || rc=$?
put $local_file $remote_file
get $remote_file $down_file
rm $remote_file
BATCH

assert_eq "$rc" "0" "sftp batch rc (see $sftp_log)"
if cmp -s "$local_file" "$down_file"; then
  pass "sftp round-trip byte-identical ($(wc -c < "$local_file" | tr -d ' ') bytes)"
else
  fail "sftp round-trip mismatch: local vs downloaded differ"
fi
echo "OK: case_sftp"
