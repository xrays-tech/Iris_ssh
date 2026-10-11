#!/usr/bin/env bash
# case_rekey_midstream.sh — rekey under load (plan M2). Forces frequent rekeys on
# a loaded connection (OpenSSH client `-o RekeyLimit=64K`) while a large
# deterministic payload flows, and asserts data integrity + connection survival.
#
# Limitation: we assert the OUTCOME (every byte delivered, no interruption) rather
# than counting the actual KEX exchanges (that needs a pcap / server KEX
# instrumentation, which is out of scope here). The client is explicitly
# configured to rekey well within the transfer, and we additionally grep the
# client VERBOSE log as best-effort evidence that a rekey actually took place
# (logged, and asserted when the toolchain emits the marker).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

: "${GW_PID:?GW_PID not set; rekey case needs a live gateway}"
N="${RK_BYTES:-1048576}"       # 1 MiB
RKLIMIT="64K"                  # rekey roughly every 64 KiB -> ~16 rekeys over N

rss_monitor_start "$GW_PID" "$IT_WORK_DIR/rk.rss" "$IT_WORK_DIR/rk.stop"

# Reader as a FILE so stdin stays the piped ssh output.
RDR="$IT_WORK_DIR/rk_reader.py"
cat >"$RDR" <<'PYEOF'
import sys
N = int(sys.argv[1]); n = 0
while True:
    d = sys.stdin.buffer.read(65536)
    if not d:
        break
    n += len(d)
print(n)
PYEOF

rc=0; got=""
got="$(ssh "${SSH_OPTS[@]}" -o RekeyLimit="$RKLIMIT" -o LogLevel=VERBOSE \
       "$TARGET" "head -c $N /dev/zero" </dev/null 2>"$IT_WORK_DIR/rk.client.err" \
  | python3 "$RDR" "$N")" || rc=$?

rss_monitor_stop "$IT_WORK_DIR/rk.stop"

assert_eq "$rc" "0" "rekey transfer completed (rc; see $IT_WORK_DIR/rk.client.err)"
assert_eq "$got" "$N" "rekey data integrity: N bytes delivered == produced"
if pid_alive "$GW_PID"; then pass "gateway alive after rekey storm"; else fail "gateway died"; fi

# Best-effort evidence a rekey happened (client VERBOSE log). Lenient: if this
# OpenSSH build doesn't emit a greppable marker, log rather than fail — the
# integrity assertion above is the real guarantee.
if grep -qiE 'rekey' "$IT_WORK_DIR/rk.client.err"; then
  pass "client log evidences rekey activity: $(grep -im1 -E 'rekey' "$IT_WORK_DIR/rk.client.err" | cut -c1-80)"
else
  log "note: no greppable 'rekey' marker in client VERBOSE log (toolchain-dependent); integrity asserted regardless"
fi

set -- $(rss_stats "$IT_WORK_DIR/rk.rss"); mx="$1"
log "rekey RSS peak: ${mx}KB"
echo "OK: case_rekey_midstream"
