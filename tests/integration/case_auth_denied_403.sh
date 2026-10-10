#!/usr/bin/env bash
# case_auth_denied_403.sh — authorization boundary (propose §3.2 / task negative).
# A validly-signed user key, but a principal the mock control plane answers with
# HTTP 403 (bob), must be refused. The gateway verifies the signature (auth ok)
# but the control plane denies authorization -> connection must fail and the
# remote command must NOT run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

denied_target="${DENIED_PRINCIPAL}@${GW_ADDR}"
rc=0
out="$(ssh "${SSH_OPTS[@]}" "$denied_target" 'echo SHOULD_NOT_RUN' 2>&1)" || rc=$?

if [ "$rc" -ne 0 ]; then pass "denied principal -> non-zero rc ($rc)"; else
  fail "principal '$DENIED_PRINCIPAL' should be denied (gateway returned rc 0)"; fi
assert_not_contains "$out" "SHOULD_NOT_RUN" "no command execution under 403"

# Also cover unknown principal (mock default -> 404). Must also be denied.
nf_target="${NOTFOUND_PRINCIPAL}@${GW_ADDR}"
rc2=0
out2="$(ssh "${SSH_OPTS[@]}" "$nf_target" 'echo SHOULD_NOT_RUN2' 2>&1)" || rc2=$?
if [ "$rc2" -ne 0 ]; then pass "unknown principal -> non-zero rc ($rc2)"; else
  fail "unknown principal '$NOTFOUND_PRINCIPAL' should be denied (rc 0)"; fi
assert_not_contains "$out2" "SHOULD_NOT_RUN2" "no command execution under 404"
echo "OK: case_auth_denied_403"
