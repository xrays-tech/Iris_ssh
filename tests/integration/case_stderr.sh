#!/usr/bin/env bash
# case_stderr.sh — stderr must be separated from stdout (extended data) and the
# failing exit code must survive (I4: no faked success).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

miss="/nonexistent_sshgw_dir_$$"
outfile="$IT_WORK_DIR/stderr.out"
errfile="$IT_WORK_DIR/stderr.err"
rc=0
ssh "${SSH_OPTS[@]}" "$TARGET" "LC_ALL=C ls $miss" >"$outfile" 2>"$errfile" || rc=$?
# exit code must be non-zero (ls returns 1 on macOS/Linux for a missing file).
if [ "$rc" -ne 0 ]; then pass "stderr-case rc=$rc (non-zero)"; else
  fail "expected non-zero rc from 'ls $miss', got 0"; fi
# stdout must be empty (nothing printed to stdout), stderr carries the message.
stdout_bytes="$(wc -c < "$outfile" | tr -d ' ')"
assert_eq "$stdout_bytes" "0" "stdout empty on error"
assert_contains "$(cat "$errfile")" "No such file" "stderr message"
echo "OK: case_stderr"
