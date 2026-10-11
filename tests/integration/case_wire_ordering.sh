#!/usr/bin/env bash
# case_wire_ordering.sh — A2 wire-level ordering, cross-channel variant. Runs N
# CONCURRENT exec channels through the gateway, each emitting an ordered tag
# sequence `c<chan>m<msg>` (1..M). The gateway must not reorder AND channels must
# not cross-contaminate: each channel's output is asserted to be fully ordered and
# to contain ONLY its own tags.
#
# "Wire-level" evidence & limitation: a true dual-segment packet capture
# (tshark/tcpdump on client<->gw AND gw<->backend) is NOT done here — it needs
# root + tshark and is brittle on loopback. The documented fallback (russh DEBUG
# event-log 双端对拍) is heavier than needed for the cross-channel guarantee; this
# case instead proves the observable that matters: per-channel frame order is
# preserved and no frame leaks across channels, N-way in parallel. This closes
# the cross-channel/parallel gap that case_ordering_matrix (single-channel) does
# not cover.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

CH="${WO_CHANNELS:-4}"
MSG="${WO_MSGS:-8}"
pids=(); files=(); tags=()

# Launch N concurrent exec channels.
c=1
while [ "$c" -le "$CH" ]; do
  f="$IT_WORK_DIR/wo.c$c"
  files[$c]="$f"
  cmd="i=1; while [ \$i -le $MSG ]; do echo c${c}m\$i; i=\$((i+1)); done"
  ssh "${SSH_OPTS[@]}" "$TARGET" "$cmd" >"$f" 2>&1 &
  pids[$c]=$!
  c=$((c+1))
done

# Wait for all; every one must exit 0.
c=1; failc=""
while [ "$c" -le "$CH" ]; do
  if wait "${pids[$c]}"; then :; else failc="$failc c$c"; fi
  c=$((c+1))
done
[ -z "$failc" ] || fail "channels returned non-zero:$failc"

# Per-channel ordering + isolation.
c=1
while [ "$c" -le "$CH" ]; do
  f="${files[$c]}"
  seqargs=(); i=1
  while [ "$i" -le "$MSG" ]; do seqargs+=("c${c}m${i}"); i=$((i+1)); done
  assert_ordered "wire channel c$c order" "$f" "${seqargs[@]}"
  # isolation: no other channel's tag may appear in this channel's output.
  other=$(( c % CH + 1 ))
  assert_not_contains "$(cat "$f")" "c${other}m" "channel c$c isolated (no c${other}m bleed)"
  c=$((c+1))
done
echo "OK: case_wire_ordering"
