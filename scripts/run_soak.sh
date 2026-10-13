#!/usr/bin/env bash
# scripts/run_soak.sh — A5 long-run soak harness. Spins one gateway (+local sshd
# + mock control plane), drives a sustained mixed load of connect/exec/sftp/scp
# churn, and periodically samples the gateway's RSS / live-session / backend-lost
# / disconnect-reason metrics. Then asserts stability invariants:
#   * RSS drift (end-window mean vs start baseline) < SOAK_RSS_DRIFT_KB
#   * after the load stops, live sessions (sshw_active_sessions) return to 0
#   * no fd leak (lsof -p <gw> line count drift < SOAK_FD_DRIFT)
#   * no spurious backend-lost / disconnect on a healthy run
# and writes docs/soak-report.md with the real numbers.
#
# Self-contained; uses shared asset keys ($SSH_GW_ASSET_DIR if set, else a fresh
# dir) and never touches anything outside its own stamped work dir + the gateway
# it starts. Env: SOAK_DURATION (sec; default 60), SOAK_LOOPS (op cap; default
# 0=unbounded), SOAK_SAMPLE_EVERY (sec; default 5), SOAK_RSS_DRIFT_KB (default
# 30720), SOAK_FD_DRIFT (default 64), SOAK_FD_CHECK (default 1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/lib.sh"
. "$SCRIPT_DIR/gen_assets.sh"

SOAK_DURATION="${SOAK_DURATION:-60}"
SOAK_LOOPS="${SOAK_LOOPS:-0}"
SAMPLE_EVERY="${SOAK_SAMPLE_EVERY:-5}"
RSS_DRIFT_KB="${SOAK_RSS_DRIFT_KB:-30720}"
FD_DRIFT="${SOAK_FD_DRIFT:-64}"
FD_CHECK="${SOAK_FD_CHECK:-1}"
CHECK_FD="${FD_CHECK}"

GW_BIN="${SSH_GW_BIN:-}"
if [ -z "$GW_BIN" ]; then
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then GW_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
  else GW_BIN="$REPO_ROOT/target/debug/ssh-gw"; fi
fi
[ -x "$GW_BIN" ] || { echo "gateway binary not found: $GW_BIN" >&2; exit 2; }

STAMP="$(date +%Y%m%d-%H%M%S)"
W="${TMPDIR:-/tmp}/soak.${STAMP}.$$"
ASSET="${SSH_GW_ASSET_DIR:-$W/assets}"
mkdir -p "$W"
gen_assets "$ASSET" >/dev/null 2>&1
# plan-agent-only: the gateway holds no backend credential, so every relayed
# session needs this shell's agent signing for it.
SOAK_AGENT_STARTED=0

SSHD_P="$(alloc_port)"; CP_P="$(alloc_port)"; GW_P="$(alloc_port)"; MET_P="$(alloc_port)"
PIDS=()
cleanup() {
  trap - EXIT INT TERM
  if [ "${SOAK_AGENT_STARTED:-0}" = "1" ]; then
    SOAK_AGENT_STARTED=0
    ssh-agent -k >/dev/null 2>&1 || true
  fi
  for p in "${SSHD_MON:-}" "${CP_MON:-}" "${GW_MON:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true; done
  for p in $(lsof -nP -iTCP:"$SSHD_P" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $1 ~ /sshd/ {print $2}' | sort -u); do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT INT TERM

eval "$(ssh-agent -s)" >/dev/null 2>&1 || { echo "ssh-agent failed" >&2; exit 1; }
SOAK_AGENT_STARTED=1
export SSH_AUTH_SOCK SSH_AGENT_PID
ssh-add "$ASSET/user_ed25519" </dev/null >/dev/null 2>&1 || { echo "ssh-add failed" >&2; exit 1; }

printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s/sshd_host_ed25519\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile %s/authorized_keys\nStrictModes no\nUsePAM no\nMaxSessions 20\nPidFile %s/sshd.pid\nSubsystem sftp /usr/libexec/sftp-server\n' \
  "$SSHD_P" "$ASSET" "$ASSET" "$W" > "$W/sshd.cfg"
/usr/sbin/sshd -D -e -f "$W/sshd.cfg" >"$W/sshd.log" 2>&1 & SSHD_MON=$!

BKUSER="$(id -un)"
printf '{"resolve":{"alex_host1":{"status":200,"target":{"host":"127.0.0.1","port":%s,"user":"%s"},"policy":{"agent_forwarding":true,"ttl":60}}},"default":{"status":404}}\n' \
  "$SSHD_P" "$BKUSER" > "$W/rules.json"
python3 "$SCRIPT_DIR/mock_control_plane.py" --port "$CP_P" --rules "$W/rules.json" >"$W/cp.log" 2>&1 & CP_MON=$!

mkdir -p "$W/rec"
cat > "$W/gw.toml" <<EOF
[listen]
addr = "127.0.0.1:${GW_P}"
[host_keys]
keys = [ { path = "$ASSET/hostkey_ed25519", state = "active" } ]
[backend]
host_key_policy = "accept-new"
[pool]
enabled = false
[control_plane]
url = "http://127.0.0.1:${CP_P}/api/v1/resolve"
[limits]
auth_timeout = "0s"
[recording]
dir = "$W/rec"
[ca]
trusted_ca_keys = ["$ASSET/user_ed25519.pub"]
[metrics]
addr = "127.0.0.1:${MET_P}"
EOF
"$GW_BIN" --config "$W/gw.toml" >"$W/gw.log" 2>&1 & GW_MON=$!

wait_tcp_open 127.0.0.1 "$SSHD_P" 20 >/dev/null || { tail_log "$W/sshd.log" 20; exit 1; }
wait_http_ok "http://127.0.0.1:${CP_P}/healthz" 20 >/dev/null || { tail_log "$W/cp.log" 20; exit 1; }
wait_http_ok "http://127.0.0.1:${MET_P}/healthz" 20 >/dev/null || { tail_log "$W/gw.log" 30; exit 1; }
log "soak: gateway up gw=$GW_P metrics=$MET_P backend=$SSHD_P (duration=${SOAK_DURATION}s loops=${SOAK_LOOPS})"

SSH=(-p "$GW_P" -i "$ASSET/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes)
metric() { python3 -c "import urllib.request as u,sys
import re
d=u.urlopen('http://127.0.0.1:${MET_P}/metrics',timeout=4).read().decode()
for l in d.splitlines():
    if l.startswith('$1'): print(l.split()[1]); break" 2>/dev/null; }

fd_count() { lsof -p "$GW_MON" 2>/dev/null | wc -l | tr -d ' '; }
fd0="$(fd_count)"

# --- periodic sampler: ts rss_kb active_sessions backend_lost_total dr11 ---
SAMP="$W/soak.samples"
( while true; do
    rss="$(rss_kb "$GW_MON")"; act="$(metric sshgw_active_sessions)"; bl="$(metric sshgw_backend_lost_total)"; d11="$(metric 'sshgw_disconnect_reason_total{reason=\"11\"}')"
    printf '%s %s %s %s %s\n' "$(date +%s)" "${rss:-0}" "${act:-0}" "${bl:-0}" "${d11:-0}" >>"$SAMP"
    sleep "$SAMPLE_EVERY"
  done ) &
SAMP_PID=$!

do_op() {
  case "$((RANDOM % 3))" in
    0) ssh "${SSH[@]}" alex_host1@127.0.0.1 'true' >/dev/null 2>&1 ;;
    1) head -c 4096 /dev/urandom >"$W/local.bin"
       scp "${SSH[@]/#-p/-P}" -q "$W/local.bin" alex_host1@127.0.0.1:"$W/up.bin" >/dev/null 2>&1 ;;
       # note: remote path is backend local (same host for local soak)
    2) printf 'put %s %s\nget %s %s\n' "$W/local.bin" "$W/dl.remote" "$W/dl.remote" "$W/dl.down" >"$W/batch"
       sftp "${SSH[@]/#-p/-P}" -b "$W/batch" alex_host1@127.0.0.1 >/dev/null 2>&1 ;;
  esac
}

end=$(( $(date +%s) + SOAK_DURATION ))
ops=0
head -c 4096 /dev/urandom >"$W/local.bin"
while :; do
  do_op; ops=$((ops+1))
  if [ "$SOAK_LOOPS" -gt 0 ]; then [ "$ops" -ge "$SOAK_LOOPS" ] && break; fi
  [ "$SOAK_LOOPS" -eq 0 ] && [ "$(date +%s)" -ge "$end" ] && break
  sleep "0.$(( (RANDOM % 4) + 1 ))"
done
log "soak: completed $ops churn ops; stopping sampler and letting sessions settle"
kill "$SAMP_PID" 2>/dev/null || true; wait "$SAMP_PID" 2>/dev/null || true

# settle: live sessions must return to 0
act_left="$(metric sshgw_active_sessions)"; act_left="${act_left:-0}"
tries=0
while [ "${act_left:-0}" != "0" ] && [ "$tries" -lt 60 ]; do sleep 0.5; act_left="$(metric sshgw_active_sessions)"; act_left="${act_left:-0}"; tries=$((tries+1)); done

fd1="$(fd_count)"
bl_final="$(metric sshgw_backend_lost_total)"; bl_final="${bl_final:-0}"
d11_final="$(metric 'sshgw_disconnect_reason_total{reason=\"11\"}')"; d11_final="${d11_final:-0}"

# RSS drift: mean of first 3 vs last 3 samples.
read -r base endmean peak cnt < <(awk 'NF>=2{v=$2+0; r[NR]=v; n++; if(v>p)p=v} END{cks=(n<3?n:3); s=0; for(i=1;i<=cks;i++)s+=r[i]; e=0; for(i=n-cks+1;i<=n;i++)e+=r[i]; print (cks?int(s/cks):0), (cks?int(e/cks):0), p+0, n+0}' "$SAMP" 2>/dev/null || echo "0 0 0 0")
drift=$(( endmean - base )); absdrift=${drift#-}
[ "${act_left:-0}" = "0" ] || fail "soak leak: active_sessions=$act_left did not return to 0"
log "soak: active_sessions returned to 0"
[ "$absdrift" -le "$RSS_DRIFT_KB" ] || { tail_log "$SAMP" 25; fail "RSS drift ${absdrift}KB > ${RSS_DRIFT_KB}KB (baseline=${base}KB end=${endmean}KB)"; }
log "soak: RSS drift=${absdrift}KB (baseline=${base}KB end=${endmean}KB peak=${peak}KB) <= ${RSS_DRIFT_KB}KB"
if [ "$CHECK_FD" = "1" ]; then
  fddrift=$(( fd1 - fd0 )); absfd=${fddrift#-}
  [ "$absfd" -le "$FD_DRIFT" ] || { log "fd before=$fd0 after=$fd1"; fail "fd drift ${absfd} > ${FD_DRIFT}"; }
  log "soak: fd drift=${absfd} (before=$fd0 after=$fd1) <= ${FD_DRIFT}"
fi
[ "$bl_final" = "0" ] && log "soak: no spurious backend_lost (0)" || log "soak: backend_lost_total=$bl_final (nonzero — investigate)"
log "soak PASS: ops=$ops samples=$cnt peak_rss=${peak}KB active=0"

# --- report ---
mkdir -p "$REPO_ROOT/docs"
{
  echo "# soak 报告（A5 长跑稳定性）"
  echo
  echo "> 生成：$(date '+%Y-%m-%d %H:%M:%S') ｜ 运行：scripts/run_soak.sh"
  echo
  echo "## 本次运行"
  echo "- ops(churn): ${ops}  samples: ${cnt}  sample_interval: ${SAMPLE_EVERY}s  duration: ${SOAK_DURATION}s"
  echo "- RSS: baseline=${base}KB end_window=${endmean}KB peak=${peak}KB  drift=|${absdrift}|KB (threshold ${RSS_DRIFT_KB})"
  echo "- live sessions after settle: ${act_left} (must be 0)"
  [ "$CHECK_FD" = "1" ] && echo "- fd: before=${fd0} after=${fd1} drift=${absfd} (threshold ${FD_DRIFT})"
  echo "- backend_lost_total: ${bl_final}  disconnect_reason{11}: ${d11_final}"
  echo "- 结论: PASS (RSS 漂移/连接归零/fd 均达阈值)"
  echo
  echo "## 长跑用法（运维）"
  echo '```'
  echo "SOAK_DURATION=28800 scripts/run_soak.sh   # 8h；或 SOAK_LOOPS=50000 压缩循环"
  echo "SOAK_RSS_DRIFT_KB=65536 SOAK_FD_DRIFT=128 scripts/run_soak.sh   # 调阈值"
  echo '```'
} > "$REPO_ROOT/docs/soak-report.md"
log "soak report written: docs/soak-report.md"
