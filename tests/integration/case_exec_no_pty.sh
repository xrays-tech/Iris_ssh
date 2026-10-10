#!/usr/bin/env bash
# case_exec_no_pty.sh — bare exec (no pty), stdout must round-trip cleanly.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

rc=0
out="$(ssh "${SSH_OPTS[@]}" "$TARGET" 'echo ok' 2>/dev/null)" || rc=$?
assert_eq "$(decr "$out")" "ok" "bare-exec stdout"
# also confirm rc==0 explicitly (not just output presence).
rc=0; ssh "${SSH_OPTS[@]}" "$TARGET" 'true' >/dev/null 2>&1 || rc=$?
assert_eq "$rc" "0" "bare-exec rc"
echo "OK: case_exec_no_pty"
