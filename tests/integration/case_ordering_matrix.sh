#!/usr/bin/env bash
# case_ordering_matrix.sh — timing-matrix coverage (plan §7/§6). Exercises four
# client request shapes and asserts the relayed OUTPUT ORDER is preserved, since
# the gateway does not reorder:
#   1. pty -> shell        (interactive: commands fed on stdin under -tt)
#   2. pty -> exec         (-tt forces a pty on an exec command)
#   3. bare exec           (no pty)
#   4. env -> pty -> shell (SendEnv sends an env request; pty + a command)
#
# "Packet-level compare" substitute evidence & limitations: a full decode of the
# SSH message stream (pty-req/env/shell/exec frames + their order) is NOT done
# (costly, fragile). Instead we assert the client-visible ordering is intact:
# the backend executes multi-command payloads in the exact order supplied and the
# output returns ordered. Because the gateway forwards in arrival order (I1),
# preserved output order over a multi-frame command is decisive evidence the
# relay did not reorder within a channel. This does NOT verify cross-channel or
# cross-session global ordering, nor the literal wire order of the control frames
# themselves — only single-channel payload ordering.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

TMP="$IT_WORK_DIR/ordering.$RANDOM"

# 1. pty -> shell (interactive session; commands via stdin)
r=0
printf 'echo ORD_A\necho ORD_B\necho ORD_C\nexit\n' | ssh -tt "${SSH_OPTS[@]}" "$TARGET" >"$TMP.raw" 2>&1 || r=$?
assert_eq "$r" "0" "pty->shell rc"
tr -d '\r' <"$TMP.raw" > "$TMP"           # pty carries CRLF
assert_ordered "pty->shell interactive" "$TMP" ORD_A ORD_B ORD_C

# 2. pty -> exec (-tt forces pty on an exec command)
r=0
ssh -tt "${SSH_OPTS[@]}" "$TARGET" 'echo ORD_D; echo ORD_E; echo ORD_F' >"$TMP" 2>&1 || r=$?
assert_eq "$r" "0" "pty->exec rc"
assert_ordered "pty->exec" "$TMP" ORD_D ORD_E ORD_F

# 3. bare exec
r=0
ssh "${SSH_OPTS[@]}" "$TARGET" 'echo ORD_G; echo ORD_H; echo ORD_I' >"$TMP" 2>&1 || r=$?
assert_eq "$r" "0" "bare-exec rc"
assert_ordered "bare-exec" "$TMP" ORD_G ORD_H ORD_I

# 4. env -> pty -> shell. The env request is exercised (SendEnv) but its value is
#    not asserted pass/fail (env forwarding semantics are a separate concern);
#    the ordering assertion proves the env frame did not corrupt stream ordering.
r=0
INNERVAR=zulu ssh -tt "${SSH_OPTS[@]}" -o SendEnv=INNERVAR "$TARGET" \
  'echo ORD_J; echo got=$INNERVAR; echo ORD_K' >"$TMP" 2>&1 || r=$?
assert_eq "$r" "0" "env->pty->shell rc"
assert_ordered "env->pty->shell" "$TMP" ORD_J ORD_K
log "env->pty->shell observed middle line: $(grep -m1 'got=' "$TMP" || echo '(n/a)')"

rm -f "$TMP" "$TMP.raw"
echo "OK: case_ordering_matrix"
