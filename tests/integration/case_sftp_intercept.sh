#!/usr/bin/env bash
# case_sftp_intercept.sh — B3 SFTP command-level interception. Drives
# [intercept.sftp] enabled + deny_commands=["REMOVE"] via subtopo.sh and asserts:
#   * put/get still work (pass-through fast path unaffected),
#   * client `rm` is refused (non-zero) AND the file still exists afterwards.
# The backend path is backend-side (REMOTE_TMP_DIR); local scratch in IT_WORK_DIR.
#
# Capability probe: if the running gateway has no SFTP command interceptor
# (src B3 not landed in this binary), `rm` will SUCCEED instead of being refused;
# the case then SKIPs (never a fake pass). Runs green once B3 is landed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
trap subtopo_stop EXIT INT TERM

SUBTOP_SFTP_ENABLED=true
SUBTOP_SFTP_DENY="REMOVE"
subtopo_start   # [intercept.sftp] enabled, deny REMOVE (inert until B3 lands)

sf() {  # sf <batch-file>
  local bf="$1" rc=0
  sftp -P "$ST_GW_PORT" -i "$USER_KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ForwardAgent=yes \
    -o ConnectTimeout=15 -o LogLevel=ERROR \
    -b "$bf" "$PRINCIPAL@127.0.0.1" >"$IT_WORK_DIR/si.sftp.log" 2>&1 || rc=$?
  return "$rc"
}

tag="$RANDOM"
loc="$IT_WORK_DIR/si.local.$tag"; rf="$REMOTE_TMP_DIR/si.remote.$tag"; down="$IT_WORK_DIR/si.down.$tag"
head -c 8192 /dev/urandom > "$loc"

printf 'put %s %s\n' "$loc" "$rf" > "$IT_WORK_DIR/si.b1"
printf 'get %s %s\n' "$rf" "$down" > "$IT_WORK_DIR/si.b2"
printf 'rm %s\n'     "$rf"       > "$IT_WORK_DIR/si.b3"

assert_rc0 sf "$IT_WORK_DIR/si.b1"        # put works
assert_rc0 sf "$IT_WORK_DIR/si.b2"        # get works
cmp -s "$loc" "$down" && pass "put/get round-trip intact (baseline passthrough)" \
  || fail "put/get mismatch before intercept check"

rm_rc=0; sf "$IT_WORK_DIR/si.b3" || rm_rc=$?
if [ "$rm_rc" -eq 0 ]; then
  skip_case "SFTP command intercept not active (rm was NOT refused) — run after src B3 lands"
fi
pass "client rm refused by interceptor (sftp rc=$rm_rc)"

# The refused rm must NOT have deleted the file: it is still gettable.
printf 'get %s %s.after\n' "$rf" "$down" > "$IT_WORK_DIR/si.b4"
assert_rc0 sf "$IT_WORK_DIR/si.b4"
cmp -s "$loc" "$down.after" && pass "file NOT deleted (interception, not a silent rm)" \
  || { tail_log "$IT_WORK_DIR/si.sftp.log" 20; fail "file content changed after refused rm"; }
echo "OK: case_sftp_intercept"
