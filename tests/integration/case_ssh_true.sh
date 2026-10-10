#!/usr/bin/env bash
# case_ssh_true.sh — protocol sanity: `ssh gw true` exits 0 through the relay.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

assert_rc0 ssh "${SSH_OPTS[@]}" "$TARGET" 'true'
pass "ssh $TARGET 'true' -> rc 0"
echo "OK: case_ssh_true"
