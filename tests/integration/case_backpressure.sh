#!/usr/bin/env bash
# case_backpressure.sh — proposE §3.6 counter-example. Fan a large stream from a
# fast producer through the gateway into a slow backend consumer and assert the
# gateway process RSS stays bounded (no unbounded buffering / OOM).
#
# client:  yes | head -c VOL   (fast producer -> ssh stdin)
# gateway: must apply back-pressure rather than buffering VOL bytes
# backend: a throttled python reader draining stdin at ~40 MB/s
#
# Tunables:
#   BP_BYTES      total bytes to push   (default 200000000, the plan's value)
#   BP_MAX_RSS_KB gateway RSS ceiling in KB (default 153600 = 150 MiB)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

: "${GW_PID:?GW_PID not set; backpressure case requires a live gateway}"
vol="${BP_BYTES:-200000000}"
maxrss_kb="${BP_MAX_RSS_KB:-153600}"

sample_file="$IT_WORK_DIR/bp_rss_samples.txt"
stop_flag="$IT_WORK_DIR/bp_rss.stop"
rm -f "$stop_flag" "$sample_file"

# --- RSS sampler: sample the gateway every 0.5s until stop_flag appears. ---
(
  while [ ! -f "$stop_flag" ]; do
    printf '%s %s\n' "$(date +%s)" "$(rss_kb "$GW_PID")" >> "$sample_file" 2>/dev/null || true
    sleep 0.5
  done
) &
sampler_pid=$!

# --- Slow backend reader (no quote chars so it survives verbatim over ssh). ---
read -r -d '' READER <<'PY' || true
import os, time
buf = 65536
target = 40 * 1024 * 1024
t0 = time.time()
n = 0
while True:
    d = os.read(0, buf)
    if not d:
        break
    n += len(d)
    expect = n / float(target)
    elapsed = time.time() - t0
    if expect > elapsed:
        time.sleep(min(expect - elapsed, 0.05))
PY

bp_out="$IT_WORK_DIR/bp.out"
rc=0
yes | head -c "$vol" | run_with_timeout 180 \
  ssh "${SSH_OPTS[@]}" "$TARGET" "$READER" >"$bp_out" 2>&1 || rc=$?

touch "$stop_flag"
wait "$sampler_pid" 2>/dev/null || true

# Sanity: the remote reader must not have errored (proves the command plumbed
# correctly and actually drained the upstream, exercising back-pressure).
assert_not_contains "$(cat "$bp_out" 2>/dev/null)" "Traceback" "backend reader clean"
assert_not_contains "$(cat "$bp_out" 2>/dev/null)" "command not found" "reader present"
# rc==0 means the stream completed cleanly through the gateway.
assert_eq "$rc" "0" "backpressure stream completed (rc)"

# Gateway must still be alive (no OOM-kill / crash).
if pid_alive "$GW_PID"; then pass "gateway still alive after ${vol} bytes"; else
  fail "gateway process ($GW_PID) is gone after backpressure run"; fi

# Peak RSS must stay bounded.
max_kb="$(awk 'NF>=2{v=$2+0; if(v>m)m=v} END{print m+0}' "$sample_file" 2>/dev/null || echo 0)"
samples="$(wc -l < "$sample_file" 2>/dev/null | tr -d ' ')"
log "backpressure: pushed ${vol} bytes; RSS samples=${samples}; peak=${max_kb}KB; ceiling=${maxrss_kb}KB"
if [ "$samples" -lt 2 ]; then
  fail "RSS sampler produced too few samples (${samples}); backpressure not observed"
fi
if [ "$max_kb" -gt "$maxrss_kb" ]; then
  tail_log "$sample_file" 20
  fail "gateway RSS ${max_kb}KB exceeded ceiling ${maxrss_kb}KB (unbounded buffering?)"
fi
pass "gateway RSS bounded: peak ${max_kb}KB <= ${maxrss_kb}KB"
echo "OK: case_backpressure"
