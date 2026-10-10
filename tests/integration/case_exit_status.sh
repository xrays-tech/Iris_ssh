#!/usr/bin/env bash
# case_exit_status.sh — exit-status must be propagated (propose D2/I4: no faking).
# `ssh gw 'exit 42'` must yield client rc 42 exactly.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

expect_rc 42 ssh "${SSH_OPTS[@]}" "$TARGET" 'exit 42'
# a couple more distinct codes to catch off-by-one / hard-coded pass-through.
expect_rc 0  ssh "${SSH_OPTS[@]}" "$TARGET" 'exit 0'
expect_rc 7  ssh "${SSH_OPTS[@]}" "$TARGET" 'exit 7'
echo "OK: case_exit_status"
