#!/usr/bin/env bash
# scripts/netem_ctl.sh — real-machine tc/netem link shaping for the gateway->backend
# path (M3 A3). macOS has no `tc`, so this runs against the Linux test backend
# (SSH_GW_BACKEND_TARGET, root). It shapes the default egress with netem
# (e.g. 1mbit + delay/jitter) so a large transfer THROUGH the gateway is paced,
# and the gateway's memory behaviour is exercised over a genuinely lossy/slow
# link. A backgrounded self-clear removes the qdisc after HOLD seconds even if
# the management link is disrupted.
#
# Usage:
#   netem_ctl.sh apply -t root@HOST:22 [-i KEY] [--rate 1mbit] [--delay 40ms] \
#                     [--jitter 10ms] [--dev eth0] [--hold 180]
#   netem_ctl.sh clear -t root@HOST:22 [-i KEY] [--dev eth0]
set -euo pipefail

cmd=""; target=""; key=""; rate="1mbit"; delay="40ms"; jitter="10ms"; dev=""; hold="180"

while [ "$#" -gt 0 ]; do
  case "$1" in
    apply|clear) cmd="$1" ;;
    -t|--target) target="$2"; shift ;;
    -i|--key)    key="$2"; shift ;;
    --rate)   rate="$2"; shift ;;
    --delay)  delay="$2"; shift ;;
    --jitter) jitter="$2"; shift ;;
    --dev)    dev="$2"; shift ;;
    --hold)   hold="$2"; shift ;;
    -h|--help) grep '^# ' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$cmd" ] && [ -n "$target" ] || { echo "usage: netem_ctl.sh {apply|clear} -t user@host:port" >&2; exit 2; }

host="${target%@*}"; rest="${target#*@}"; bhost="${rest%:*}"; bport="${rest##*:}"
case "$rest" in *:*) : ;; *) bport="22" ;; esac
sshargs=(-p "$bport" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR)
[ -n "$key" ] && sshargs+=(-i "$key")

case "$cmd" in
  apply)
    # ssh collapses empty positional args (an empty --dev shifts the rest), so we
    # pass an explicit AUTO sentinel for "auto-detect" instead of "".
    devarg="${dev:-AUTO}"
    ssh "${sshargs[@]}" "${host}@${bhost}" bash -s -- "$rate" "$delay" "$jitter" "$devarg" "$hold" <<'REMOTE'
set -e
RATE="$1"; DELAY="$2"; JITTER="$3"; DEVFIX="$4"; HOLD="$5"
[ "$DEVFIX" = "AUTO" ] && DEVFIX=""
DEV="$DEVFIX"
[ -n "$DEV" ] || DEV="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)"
[ -n "$DEV" ] || { echo "cannot determine egress device (set --dev)"; exit 3; }
CUR="$(tc qdisc show dev "$DEV" 2>/dev/null | head -1)"
echo "note: replacing root qdisc on $DEV (was: $CUR)"
tc qdisc replace dev "$DEV" root netem rate "$RATE" delay "$DELAY" "$JITTER" 2>/dev/null \
  || tc qdisc replace dev "$DEV" root netem rate "$RATE" delay "$DELAY"
tc -s qdisc show dev "$DEV" | head -1
setsid bash -c "sleep $HOLD; tc qdisc del dev $DEV root 2>/dev/null; echo cleared" </dev/null >/dev/null 2>&1 &
echo "NETEM_APPLIED dev=$DEV rate=$RATE delay=$DELAY $JITTER hold=${HOLD}s"
REMOTE
    ;;
  clear)
    ssh "${sshargs[@]}" "${host}@${bhost}" bash -s -- "${dev:-AUTO}" <<'REMOTE'
set -e
DEVFIX="$1"
[ "$DEVFIX" = "AUTO" ] && DEVFIX=""
DEV="$DEVFIX"
[ -n "$DEV" ] || DEV="$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)"
[ -n "$DEV" ] || { echo "cannot determine egress device (set --dev)"; exit 3; }
tc qdisc del dev "$DEV" root 2>/dev/null || true
echo "NETEM_CLEARED dev=$DEV"
REMOTE
    ;;
esac
