#!/usr/bin/env bash
# case_netem_slow.sh — A3 netem real link impairment. Applies tc/netem shaping on
# the backend egress (scripts/netem_ctl.sh) and transfers a large file from the
# backend THROUGH the gateway to the client (backend->gw leg is the shaped one).
# Asserts byte integrity + gateway RSS stays bounded over the genuinely slow
# link + completion. Complements case_slow_link's window-based approximation with
# a real shaper.
#
# Local capability probe: needs the Linux test backend (SSH_GW_BACKEND_TARGET)
# with `tc`; otherwise the case SKIPs (never a fake pass).
# Env: NETEM_RATE (default 2mbit), NETEM_BYTES (download size, default 3MiB),
# NETEM_MAX_RSS_KB, NETEM_DELAY/JITTER, NETEM_HOLD.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

[ -n "${SSH_GW_BACKEND_TARGET:-}" ] || skip_case "netem needs a Linux test backend (SSH_GW_BACKEND_TARGET); local uses case_slow_link"
[ -n "${SSH_GW_ASSET_DIR:-}" ]     || skip_case "netem needs SSH_GW_ASSET_DIR (backend key)"

BK="${SSH_GW_BACKEND_TARGET}"; BK_REST="${BK#*@}"
BACKEND_PORT="${BK_REST##*:}"; case "$BK_REST" in *:*) : ;; *) BACKEND_PORT="22" ;; esac
KEY="$SSH_GW_ASSET_DIR/backend_ed25519"
NETEM="$HERE/../../scripts/netem_ctl.sh"
RATE="${NETEM_RATE:-2mbit}"; DELAY="${NETEM_DELAY:-40ms}"; JITTER="${NETEM_JITTER:-10ms}"
HOLD="${NETEM_HOLD:-90}"
N="${NETEM_BYTES:-3145728}"
CEIL="${NETEM_MAX_RSS_KB:-153600}"

BK_TARGET_SPEC="$SSH_GW_BACKEND_TARGET"
remote_ssh() {
  ssh -p "$BACKEND_PORT" -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR "$SSH_GW_BACKEND_TARGET" "$1"
}

if ! remote_ssh 'command -v tc >/dev/null && echo yes' 2>/dev/null | grep -q yes; then
  skip_case "backend has no tc/netem (not the Linux test machine)"
fi

# Prepare the backend-side file (upload is not on the shaped egress path).
rf="$REMOTE_TMP_DIR/netem_$RANDOM.bin"
head -c "$N" /dev/urandom > "$IT_WORK_DIR/netem.src"
assert_rc0 scp "${SCP_OPTS[@]}" -q "$IT_WORK_DIR/netem.src" "$TARGET:$rf"

sf="$IT_WORK_DIR/netem.rss"; stop="$IT_WORK_DIR/netem.stop"
rss_monitor_start "$GW_PID" "$sf" "$stop"

bash "$NETEM" apply -t "$BK" -i "$KEY" --rate "$RATE" --delay "$DELAY" --jitter "$JITTER" --hold "$HOLD" \
  >"$IT_WORK_DIR/netem.apply.log" 2>&1 || { tail_log "$IT_WORK_DIR/netem.apply.log" 20; rss_monitor_stop "$stop"; fail "netem apply failed"; }

rc=0; got=0
got="$(scp "${SCP_OPTS[@]}" -q "$TARGET:$rf" "$IT_WORK_DIR/netem.dst" 2>"$IT_WORK_DIR/netem.dl.err" && wc -c < "$IT_WORK_DIR/netem.dst" | tr -d ' ')" || rc=$?
rss_monitor_stop "$stop"
bash "$NETEM" clear -t "$BK" -i "$KEY" >/dev/null 2>&1 || true

assert_eq "$rc" "0" "netem download completed (rc)"
assert_eq "$got" "$N" "netem integrity: bytes delivered == produced"
cmp -s "$IT_WORK_DIR/netem.src" "$IT_WORK_DIR/netem.dst" && pass "netem download byte-identical" || fail "netem content mismatch"
ssh "${SSH_OPTS[@]}" "$TARGET" "rm -f '$rf'" >/dev/null 2>&1 || true
pid_alive "$GW_PID" && pass "gateway alive after netem transfer" || fail "gateway died"
set -- $(rss_stats "$sf"); mx="$1"
log "netem RSS peak: ${mx}KB (ceiling ${CEIL}KB) rate=${RATE}"
[ "$mx" -le "$CEIL" ] || { tail_log "$sf" 20; fail "RSS ${mx}KB exceeded ${CEIL}KB under netem"; }
pass "gateway RSS bounded over real slow link: ${mx}KB <= ${CEIL}KB"
echo "OK: case_netem_slow"
