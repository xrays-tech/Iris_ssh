#!/usr/bin/env bash
# case_pty_shell.sh — interactive shell: force a pty (-tt) which exercises the
# pty-req -> shell/exec ordering over the relay. Verifies lines arrive in order
# and a CRLF-ised pty stream is handled (propose timing matrix: pty->shell, -tt).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

out_raw="$IT_WORK_DIR/pty_shell.raw"
out_clean="$IT_WORK_DIR/pty_shell.clean"
rc=0
ssh -tt "${SSH_OPTS[@]}" "$TARGET" 'echo one; echo two; echo three' \
  >"$out_raw" 2>&1 || rc=$?
assert_eq "$rc" "0" "pty -tt exec rc"
tr -d '\r' < "$out_raw" > "$out_clean"
assert_ordered "pty->shell ordering" "$out_clean" one two three
# a shell (not exec) path too: read commands from stdin under a forced pty.
sh_raw="$IT_WORK_DIR/pty_sh_shell.raw"
rc=0
printf 'echo alpha\necho beta\nexit\n' | ssh -tt "${SSH_OPTS[@]}" "$TARGET" \
  >"$sh_raw" 2>&1 || rc=$?
assert_eq "$rc" "0" "pty -tt interactive shell rc"
tr -d '\r' < "$sh_raw" > "$sh_raw.clean"
assert_ordered "pty->shell interactive ordering" "$IT_WORK_DIR/pty_sh_shell.raw.clean" alpha beta
echo "OK: case_pty_shell"
