#!/usr/bin/env bash
# case_slow_link.sh — constrained-link counter-example (plan §6.1, "netem" slot).
#
# macOS has no `tc/netem` and no privilege for `pf`, so a real link shaper is NOT
# used. APPROXIMATION (+ limitation): we model a thin link with (a) the smallest
# legal relay window — a self-contained gateway with `window_size=256KB` via
# subtopo.sh — and (b) a controlled slow consumer (~1 MB/s). Under that sustained
# slow drain we assert: data integrity (all N zero bytes), the gateway RSS stays
# FLAT across the run (low variance), and the gateway stays alive. Complements
# case_backpressure_down (which models a burst flood and asserts a bounded peak).
# Env overrides: SL_BYTES, SL_MAX_RSS_KB, SL_RSS_SPREAD_KB.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"

trap subtopo_stop EXIT INT TERM

SUBTOP_WINDOW="256KB"     # smallest legal window (config validates [256KB, 8MB])
subtopo_start

N="${SL_BYTES:-8388608}"                 # 8 MiB
CEIL="${SL_MAX_RSS_KB:-153600}"          # 150 MiB absolute bound
SPREAD_KB="${SL_RSS_SPREAD_KB:-40960}"   # flatness: max-min across samples
sf="$IT_WORK_DIR/sl.rss"; stop="$IT_WORK_DIR/sl.stop"

rss_monitor_start "$ST_GW_PID" "$sf" "$stop"

# Reader as a FILE so stdin stays the piped ssh output (a `python3 - <<heredoc`
# would consume stdin as the script and starve the reader).
RDR="$IT_WORK_DIR/sl_reader.py"
cat >"$RDR" <<'PYEOF'
import sys, time
N = int(sys.argv[1]); got = 0; t0 = time.time(); rate = 1 * 1024 * 1024  # ~1 MB/s
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
got="$(subtopo_ssh "head -c $N /dev/zero" </dev/null 2>"$IT_WORK_DIR/sl.err" \
  | python3 "$RDR" "$N")" || rc=$?

rss_monitor_stop "$stop"

assert_eq "$rc" "0" "slow-link transfer completed (rc; see $IT_WORK_DIR/sl.err)"
assert_eq "$got" "$N" "slow-link integrity: N zero bytes delivered == produced"
if pid_alive "$ST_GW_PID"; then pass "sub-topology gateway alive after slow-link drain"; else fail "gateway died"; fi

set -- $(rss_stats "$sf"); mx="$1"; mn="$2"; cnt="$3"
spread=$((mx - mn))
log "slow-link RSS: max=${mx}KB min=${mn}KB spread=${spread}KB samples=${cnt} (window=256KB, ~1MB/s)"
[ "$cnt" -ge 2 ] || fail "RSS sampler produced too few samples ($cnt)"
[ "$mx" -le "$CEIL" ] || { tail_log "$sf" 20; fail "RSS ${mx}KB exceeded ceiling ${CEIL}KB"; }
[ "$spread" -le "$SPREAD_KB" ] || { tail_log "$sf" 20; fail "RSS not flat: spread ${spread}KB > ${SPREAD_KB}KB"; }
pass "gateway RSS flat + bounded over sustained slow drain: ${mx}KB<=${CEIL}KB, spread=${spread}KB<=${SPREAD_KB}KB"
echo "OK: case_slow_link"
