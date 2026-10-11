#!/usr/bin/env bash
# tests/integration/subtopo.sh — a throwaway LOCAL sub-topology (backend sshd +
# mock control plane + gateway) so a case can drive the FULL lifecycle (kill the
# backend, kill the control plane, set fail_open / small window / short TTL)
# without disturbing the shared suite topology that run_integration.sh owns.
#
# Source-only. The caller MUST register cleanup:
#     trap subtopo_stop EXIT INT TERM
# It uses the SHARED asset keys ($IT_ASSET_DIR) and lib.sh helpers; it never
# touches SSH_GW_ASSET_DIR. On teardown it only kills its own per-run procs and
# lsof-scoped backend sessions on its own unique port.
#
# Tunables (set BEFORE subtopo_start; all optional):
#   SUBTOP_FAIL_OPEN   "true"/"false"  -> [control_plane] fail_open  (default false)
#   SUBTOP_CACHE_TTL   duration string -> control_plane.cache_ttl     (default "30s")
#   SUBTOP_TTL_JITTER  duration string -> control_plane.cache_ttl_jitter (default "3s")
#   SUBTOP_WINDOW      byte string     -> relay.window_size           (default "1MB")
#   SUBTOP_RULES       path to a rules JSON. If unset, a default rule resolves
#                      $PRINCIPAL -> (127.0.0.1:<backend>, $BACKEND_USER).
#
# Manually, sub-unique prefer removing remote grep; probe result vars set by
# subtopo_start: ST_SSHD_PORT ST_CP_PORT ST_GW_PORT ST_MET_PORT ST_GW_PID
# ST_CP_PID ST_SSHD_PID. Helpers: subtopo_metric, subtopo_ssh,
# subtopo_kill_backend, subtopo_kill_cp.
set -uo pipefail

SUBTOPO_DIR="${SUBTOPO_DIR:-}"
ST_SSHD_PORT=""; ST_CP_PORT=""; ST_GW_PORT=""; ST_MET_PORT=""
ST_GW_PID=""; ST_CP_PID=""; ST_SSHD_PID=""
SUBTOP_FAIL_OPEN="${SUBTOP_FAIL_OPEN:-false}"
SUBTOP_CACHE_TTL="${SUBTOP_CACHE_TTL:-30s}"
SUBTOP_TTL_JITTER="${SUBTOP_TTL_JITTER:-3s}"
SUBTOP_WINDOW="${SUBTOP_WINDOW:-1MB}"

# Resolve the gateway binary the same way run_integration.sh does.
SUBTOPO_CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUBTOPO_GW_BIN="${SSH_GW_BIN:-}"
if [ -z "$SUBTOPO_GW_BIN" ]; then
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    SUBTOPO_GW_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
  else
    SUBTOPO_GW_BIN="$SUBTOPO_CASE_DIR/../../target/debug/ssh-gw"
  fi
fi

subtopo_start() {
  SUBTOPO_DIR="$IT_WORK_DIR/subtopo"
  mkdir -p "$SUBTOPO_DIR"
  ST_SSHD_PORT="$(alloc_port)"; ST_CP_PORT="$(alloc_port)"
  ST_GW_PORT="$(alloc_port)";   ST_MET_PORT="$(alloc_port)"

  printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nMaxSessions 10\nPidFile %s/sshd.pid\nSubsystem sftp /usr/libexec/sftp-server\n' \
    "$ST_SSHD_PORT" "$IT_ASSET_DIR/sshd_host_ed25519" "$IT_ASSET_DIR/authorized_keys" "$SUBTOPO_DIR" \
    > "$SUBTOPO_DIR/sshd.cfg"

  if [ -n "${SUBTOP_RULES:-}" ]; then
    cp "$SUBTOP_RULES" "$SUBTOPO_DIR/rules.json"
  else
    printf '{"resolve":{"%s":{"status":200,"target":{"host":"127.0.0.1","port":%s,"user":"%s"},"policy":{"ttl":60}}},"default":{"status":404}}\n' \
      "$PRINCIPAL" "$ST_SSHD_PORT" "$BACKEND_USER" > "$SUBTOPO_DIR/rules.json"
  fi

  printf '[listen]\naddr="127.0.0.1:%s"\n[host_keys]\nkeys=[{path="%s",state="active"}]\n[relay]\nwindow_size="%s"\nmax_packet="32KB"\noutbound_guard=true\n[backend]\nprivate_key="%s"\nhost_key_policy="accept-new"\n[pool]\nenabled=false\n[control_plane]\nurl="http://127.0.0.1:%s/api/v1/resolve"\ncache_ttl="%s"\ntimeout="2s"\nfail_open=%s\ncache_ttl_jitter="%s"\n[limits]\nauth_timeout="0s"\n[metrics]\naddr="127.0.0.1:%s"\n' \
    "$ST_GW_PORT" "$IT_ASSET_DIR/hostkey_ed25519" "$SUBTOP_WINDOW" \
    "$IT_ASSET_DIR/backend_ed25519" "$ST_CP_PORT" "$SUBTOP_CACHE_TTL" \
    "$SUBTOP_FAIL_OPEN" "$SUBTOP_TTL_JITTER" "$ST_MET_PORT" > "$SUBTOPO_DIR/gw.toml"

  /usr/sbin/sshd -t -f "$SUBTOPO_DIR/sshd.cfg" 2>>"$SUBTOPO_DIR/sshd.log" \
    || { tail_log "$SUBTOPO_DIR/sshd.log" 20; return 1; }
  /usr/sbin/sshd -D -e -f "$SUBTOPO_DIR/sshd.cfg" >"$SUBTOPO_DIR/sshd.log" 2>&1 &
  ST_SSHD_PID=$!
  python3 "$SUBTOPO_CASE_DIR/../../scripts/mock_control_plane.py" \
    --port "$ST_CP_PORT" --rules "$SUBTOPO_DIR/rules.json" \
    >"$SUBTOPO_DIR/cp.log" 2>&1 &
  ST_CP_PID=$!
  "$SUBTOPO_GW_BIN" --config "$SUBTOPO_DIR/gw.toml" >"$SUBTOPO_DIR/gw.log" 2>&1 &
  ST_GW_PID=$!

  wait_tcp_open 127.0.0.1 "$ST_SSHD_PORT" 20 || { tail_log "$SUBTOPO_DIR/sshd.log" 20; return 1; }
  wait_http_ok "http://127.0.0.1:${ST_CP_PORT}/healthz"  20 || { tail_log "$SUBTOPO_DIR/cp.log" 20;  return 1; }
  wait_http_ok "http://127.0.0.1:${ST_MET_PORT}/healthz" 20 || { tail_log "$SUBTOPO_DIR/gw.log" 20; return 1; }
  log "subtopo up: gateway=$ST_GW_PORT cp=$ST_CP_PORT backend=$ST_SSHD_PORT"
}

# Kill server-side backend session procs on our port (drops the gateway's backend
# connect) + the master listener. lsof-scoped: never touches the system sshd.
_subtopo_kill_port_sessions() {
  local port="$1" p
  [ -n "$port" ] || return 0
  for p in $(lsof -nP -iTCP:"$port" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $1 ~ /sshd/ {print $2}' | sort -u); do
    kill -9 "$p" 2>/dev/null || true
  done
}

subtopo_kill_backend() {
  _subtopo_kill_port_sessions "$ST_SSHD_PORT"
  [ -n "$ST_SSHD_PID" ] && kill -9 "$ST_SSHD_PID" 2>/dev/null || true
}

subtopo_kill_cp() {
  [ -n "$ST_CP_PID" ] && kill -TERM "$ST_CP_PID" 2>/dev/null || true
  # ensure it is gone
  sleep 0.3
  [ -n "$ST_CP_PID" ] && kill -9 "$ST_CP_PID" 2>/dev/null || true
}

subtopo_metric() {  # subtopo_metric <regex> -> matching /metrics lines
  python3 - "http://127.0.0.1:${ST_MET_PORT}/metrics" "$1" <<'PY' 2>/dev/null
import sys, urllib.request, re
url, pat = sys.argv[1], sys.argv[2]
rx = re.compile(pat)
data = urllib.request.urlopen(url, timeout=4).read().decode()
for line in data.splitlines():
    if rx.search(line):
        print(line)
PY
}

# subtopo_ssh <remote-command...> — ssh as $PRINCIPAL into the sub-topology gateway
subtopo_ssh() {
  ssh -p "$ST_GW_PORT" -i "$USER_KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
    "$PRINCIPAL@127.0.0.1" "$@"
}

subtopo_stop() {
  [ -n "$ST_GW_PID" ]  && kill -9 "$ST_GW_PID"  2>/dev/null || true
  [ -n "$ST_CP_PID" ]  && kill -9 "$ST_CP_PID"  2>/dev/null || true
  _subtopo_kill_port_sessions "$ST_SSHD_PORT"
  [ -n "$ST_SSHD_PID" ] && kill -9 "$ST_SSHD_PID" 2>/dev/null || true
}
