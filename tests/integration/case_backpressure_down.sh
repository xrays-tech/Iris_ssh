#!/usr/bin/env bash
# case_backpressure_down.sh — DOWNSTREAM flood counter-example (plan §6.1).
# Fast backend producer (head -c N /dev/zero -> N deterministic zero bytes) vs a
# SLOW client reader (~30 MB/s), so downstream back-pressure must bound the
# gateway's memory. Asserts: data integrity (all N zero bytes arrive, none lost),
# gateway RSS peak bounded, gateway alive at end. Upstream case_backpressure is
# the mirror image (fast client -> slow backend). Env overrides: BP_BYTES,
# BP_MAX_RSS_KB.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

: "${GW_PID:?GW_PID not set; backpressure_down needs a live gateway}"
N="${BP_BYTES:-200000000}"
CEIL="${BP_MAX_RSS_KB:-153600}"          # 150 MiB; runaway buffering would blow past this
sf="$IT_WORK_DIR/bpd.rss"; stop="$IT_WORK_DIR/bpd.stop"

rss_monitor_start "$GW_PID" "$sf" "$stop"

# Reader is a FILE (not `python3 - <<heredoc`): a heredoc would capture stdin as
# the script and starve the reader of the piped ssh output.
RDR="$IT_WORK_DIR/bpd_reader.py"
cat >"$RDR" <<'PYEOF'
import sys, time
N = int(sys.argv[1]); got = 0; t0 = time.time(); rate = 30 * 1024 * 1024
while got < N:
    d = sys.stdin.buffer.read(65536)
    if not d:
        break
    if d.count(0) != len(d):
        sys.stderr.write("NONZERO_BYTE\n"); sys.exit(3)
    got += len(d)
    exp = got / float(rate); el = time.time() - t0
    if exp > el:
        time.sleep(min(exp - el, 0.05))
print(got)
PYEOF

rc=0; got=""
got="$(ssh "${SSH_OPTS[@]}" "$TARGET" "head -c $N /dev/zero" </dev/null 2>"$IT_WORK_DIR/bpd.err" \
  | python3 "$RDR" "$N")" || rc=$?

rss_monitor_stop "$stop"

assert_eq "$rc" "0" "downstream flood completed (rc; see $IT_WORK_DIR/bpd.err)"
assert_eq "$got" "$N" "downstream integrity: N zero bytes delivered == produced"
if pid_alive "$GW_PID"; then pass "gateway alive after downstream flood"; else fail "gateway died"; fi

set -- $(rss_stats "$sf"); mx="$1"; mn="$2"; cnt="$3"
log "downstream RSS: max=${mx}KB min=${mn}KB samples=${cnt} ceiling=${CEIL}KB"
[ "$cnt" -ge 2 ] || fail "RSS sampler produced too few samples ($cnt)"
[ "$mx" -le "$CEIL" ] || { tail_log "$sf" 20; fail "gateway RSS ${mx}KB exceeded ceiling ${CEIL}KB"; }
pass "gateway RSS bounded under downstream flood: ${mx}KB <= ${CEIL}KB"
echo "OK: case_backpressure_down"
