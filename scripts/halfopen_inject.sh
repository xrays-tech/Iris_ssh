#!/usr/bin/env bash
# scripts/halfopen_inject.sh — real-machine HALF-OPEN (connection-loss) injection
# for the gateway->backend SSH link (M3 A1). macOS has no iptables, so this runs
# against the Linux test backend (SSH_GW_BACKEND_TARGET, root) where iptables is
# available. It DROPs packets to the backend SSH port WITHOUT sending RST, so the
# gateway's established backend connection half-opens: the gateway keeps the
# socket but its keepalives are never answered, and russh then declares the
# backend lost (~ keepalive_interval x (max+1)).
#
# Safety / hygiene:
#   * Only ever touches our OWN tagged chain `SSHGW_HALFOPEN` (created on demand,
#     cleared+deleted by recover/clean). It never edits/drops unrelated rules.
#   * inject arms a backgrounded self-clear after HOLD seconds on the backend, so
#     the rule is removed even if the management link itself is disrupted.
#   * No secrets; key passed via -i or falls back to the ambient agent.
#
# Usage:
#   halfopen_inject.sh inject -t root@HOST:22 [-i KEY] [--dport 22] [--hold 70]
#   halfopen_inject.sh recover -t root@HOST:22 [-i KEY]
#   halfopen_inject.sh clean   -t root@HOST:22 [-i KEY]   # idempotent remove
set -euo pipefail

CHAIN="SSHGW_HALFOPEN"
cmd=""; target=""; key=""; dport="22"; hold="70"

while [ "$#" -gt 0 ]; do
  case "$1" in
    inject|recover|clean) cmd="$1" ;;
    -t|--target) target="$2"; shift ;;
    -i|--key)    key="$2"; shift ;;
    --dport)     dport="$2"; shift ;;
    --hold)      hold="$2"; shift ;;
    -h|--help) grep '^# ' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$cmd" ] && [ -n "$target" ] || { echo "usage: halfopen_inject.sh {inject|recover|clean} -t user@host:port" >&2; exit 2; }

host="${target%@*}"; rest="${target#*@}"; bhost="${rest%:*}"; bport="${rest##*:}"
case "$rest" in *:*) : ;; *) bport="22" ;; esac

sshargs=(-p "$bport" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR)
[ -n "$key" ] && sshargs+=(-i "$key")

# Remote bodies use only our tagged chain. Idempotent guards throughout.
case "$cmd" in
  inject)
    ssh "${sshargs[@]}" "${host}@${bhost}" bash -s -- "$CHAIN" "$dport" "$hold" <<'REMOTE'
set -e
CHAIN="$1"; DPORT="$2"; HOLD="$3"
iptables -N "$CHAIN" 2>/dev/null || true          # create if absent (idempotent)
iptables -F "$CHAIN"                              # start clean
iptables -A "$CHAIN" -p tcp --dport "$DPORT" -j DROP
# hook the chain into INPUT exactly once
iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
# arm auto self-clear so the link recovers even if this mgmt session drops
setsid bash -c "sleep $HOLD; iptables -D INPUT -j $CHAIN 2>/dev/null; iptables -F $CHAIN 2>/dev/null; iptables -X $CHAIN 2>/dev/null" </dev/null >/dev/null 2>&1 &
echo "INJECTED chain=$CHAIN dport=$DPORT hold=${HOLD}s"
REMOTE
    ;;
  recover)
    ssh "${sshargs[@]}" "${host}@${bhost}" bash -s -- "$CHAIN" <<'REMOTE'
set -e
CHAIN="$1"
iptables -D INPUT -j "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN" 2>/dev/null || true
iptables -X "$CHAIN" 2>/dev/null || true
echo "RECOVERED chain=$CHAIN removed"
REMOTE
    ;;
  clean)
    ssh "${sshargs[@]}" "${host}@${bhost}" bash -s -- "$CHAIN" <<'REMOTE'
set -e
CHAIN="$1"
for f in "-D INPUT -j $CHAIN"; do iptables $f 2>/dev/null || true; done
iptables -F "$CHAIN" 2>/dev/null || true
iptables -X "$CHAIN" 2>/dev/null || true
echo "CLEANED chain=$CHAIN (no-op if absent)"
REMOTE
    ;;
esac
