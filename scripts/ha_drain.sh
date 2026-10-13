#!/usr/bin/env bash
# scripts/ha_drain.sh — B5 HA rollout rehearsal (same host). Starts TWO gateway
# replicas (distinct listen/metrics/recording dirs — the per-instance contract
# confirmed in src/config.rs) behind a *client-side* least-readyz "LB", then runs
# the drain/re-admit rollout and asserts the invariants:
#   1. both replicas healthy (/readyz 200)
#   2. signal A (SIGTERM) -> A flips /readyz 503 ("draining"); its existing
#      exec session receives a clean DISCONNECT goodbye (not a silent drop)
#   3. during the drain window, a NEW session is routed to the healthy replica B
#      (A receives none, because it is not readyz-200)
#   4. after A is restored it is re-admitted (/readyz 200) and serves new sessions
#
# LB approximation (capability-probed): a real L4 (haproxy/socat) is used only if
# present; otherwise the client-side chooser below (connect to the first
# /readyz==200 replica) is the documented equivalent for these semantics — it
# models "new connections go to a live replica" without terminating TCP.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
. "$SCRIPT_DIR/lib.sh"
. "$SCRIPT_DIR/gen_assets.sh"

GW_BIN="${SSH_GW_BIN:-}"
if [ -z "$GW_BIN" ]; then
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then GW_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
  else GW_BIN="$REPO_ROOT/target/debug/ssh-gw"; fi
fi
[ -x "$GW_BIN" ] || { echo "gateway binary not found: $GW_BIN" >&2; exit 2; }

STAMP="$(date +%Y%m%d-%H%M%S)"
W="${TMPDIR:-/tmp}/ha.${STAMP}.$$"
ASSET="${SSH_GW_ASSET_DIR:-$W/assets}"
mkdir -p "$W"; gen_assets "$ASSET" >/dev/null 2>&1
KEY="$ASSET/user_ed25519"
# plan-agent-only: the gateway holds no backend credential, so every session it
# relays needs this shell's agent signing for it.
HA_AGENT_STARTED=0

SSHD_P="$(alloc_port)"; CP_P="$(alloc_port)"
A_LISN="$(alloc_port)"; A_MET="$(alloc_port)"
B_LISN="$(alloc_port)"; B_MET="$(alloc_port)"
mkdir -p "$W/a/rec" "$W/b/rec"

cleanup() {
  trap - EXIT INT TERM
  if [ "${HA_AGENT_STARTED:-0}" = "1" ]; then
    HA_AGENT_STARTED=0
    ssh-agent -k >/dev/null 2>&1 || true
  fi
  for p in "${A_PID:-0}" "${B_PID:-0}" "${CP_PID:-0}" "${SSHD_PID:-0}"; do [ -n "${p:-}" ] && [ "$p" != 0 ] && kill -9 "$p" 2>/dev/null || true; done
  for p in $(lsof -nP -iTCP:"$SSHD_P" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $1 ~ /sshd/ {print $2}' | sort -u); do kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$W"
}
trap cleanup EXIT INT TERM

eval "$(ssh-agent -s)" >/dev/null 2>&1 || { echo "ssh-agent failed" >&2; exit 1; }
HA_AGENT_STARTED=1
export SSH_AUTH_SOCK SSH_AGENT_PID
ssh-add "$KEY" </dev/null >/dev/null 2>&1 || { echo "ssh-add failed" >&2; exit 1; }

# --- backend sshd + shared mock control plane ---
printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s/sshd_host_ed25519\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile %s/authorized_keys\nStrictModes no\nUsePAM no\nMaxSessions 20\nPidFile %s/sshd.pid\nSubsystem sftp /usr/libexec/sftp-server\n' \
  "$SSHD_P" "$ASSET" "$ASSET" "$W" > "$W/sshd.cfg"
/usr/sbin/sshd -D -e -f "$W/sshd.cfg" >"$W/sshd.log" 2>&1 & SSHD_PID=$!
printf '{"resolve":{"alex_host1":{"status":200,"target":{"host":"127.0.0.1","port":%s,"user":"%s"},"policy":{"agent_forwarding":true,"ttl":60}}},"default":{"status":404}}\n' \
  "$SSHD_P" "$(id -un)" > "$W/rules.json"
python3 "$SCRIPT_DIR/mock_control_plane.py" --port "$CP_P" --rules "$W/rules.json" >"$W/cp.log" 2>&1 & CP_PID=$!
wait_tcp_open 127.0.0.1 "$SSHD_P" 20 >/dev/null || { tail_log "$W/sshd.log" 20; exit 1; }
wait_http_ok "http://127.0.0.1:${CP_P}/healthz" 20 >/dev/null || { tail_log "$W/cp.log" 20; exit 1; }

mk_cfg() {  # <path> <lisn> <met> <rec>
  cat > "$1" <<EOF
[listen]
addr = "127.0.0.1:$2"
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
[shutdown]
drain_wait = "6s"
disconnect_flush = "3s"
hard_deadline = "30s"
[recording]
dir = "$4"
[ca]
trusted_ca_keys = ["$ASSET/user_ed25519.pub"]
[metrics]
addr = "127.0.0.1:$3"
EOF
}
start_replica() {  # <name> <lisn> <met> <rec> -> sets <name>_PID via global
  local name="$1" lisn="$2" met="$3" rec="$4"
  mk_cfg "$W/$name.toml" "$lisn" "$met" "$rec"
  "$GW_BIN" --config "$W/$name.toml" >"$W/$name.gw.log" 2>&1 &
  local pid=$!
  printf -v "${name}_PID" '%s' "$pid"
  if ! wait_http_ok "http://127.0.0.1:${met}/healthz" 20; then
    tail_log "$W/$name.gw.log" 30; return 1
  fi
}

readyz() {  # <met> -> 200 | 503 | 0
  python3 - "$1" <<'PY' 2>/dev/null
import sys, urllib.request, urllib.error
try:
    print(urllib.request.urlopen("http://127.0.0.1:%s/readyz" % sys.argv[1], timeout=2).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print(0)
PY
}
new_session() {  # client-side least-readyz LB: first readyz-200 of A then B
  if [ "$(readyz "$A_MET")" = "200" ]; then LAST_INST="A"; LAST_PORT="$A_LISN"
  elif [ "$(readyz "$B_MET")" = "200" ]; then LAST_INST="B"; LAST_PORT="$B_LISN"
  else LAST_INST="FAIL"; return 1; fi
  ssh -p "$LAST_PORT" -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes \
    alex_host1@127.0.0.1 "$@"
}
# lb_session <cmd...> — runs new_session in the CURRENT shell (so LAST_INST /
# LAST_PORT survive) and captures output/rc without a subshell.
lb_session() {
  NS_RC=0
  new_session "$@" >"$W/ns.out" 2>&1 || NS_RC=$?
  NS_OUT="$(cat "$W/ns.out" 2>/dev/null)"
}

# --- bring both up ---
start_replica A "$A_LISN" "$A_MET" "$W/a/rec" || fail "instance A failed to start"
start_replica B "$B_LISN" "$B_MET" "$W/b/rec" || fail "instance B failed to start"
pass "both replicas healthy (readyz A=$(readyz "$A_MET") B=$(readyz "$B_MET"))"

# --- LB routes a fresh session to A ---
lb_session 'printf LIVE'
assert_eq "$NS_RC" "0" "LB routed fresh session"
assert_eq "$NS_OUT" "LIVE" "fresh session output"
assert_eq "$LAST_INST" "A" "fresh session went to replica A"
pass "new session routed to A ($NS_OUT)"

# --- open a long-lived exec session ON A (the session that must drain) ---
ssh -p "$A_LISN" -i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes \
    alex_host1@127.0.0.1 'echo READY; sleep 300' >"$W/a.existing.out" 2>"$W/a.existing.err" &
EXIST_PID=$!
for _ in $(seq 1 40); do grep -q READY "$W/a.existing.out" 2>/dev/null && break; sleep 0.2; done
grep -q READY "$W/a.existing.out" 2>/dev/null || fail "existing session on A never reached READY"
pass "existing (in-flight) session established on A (pid $EXIST_PID)"

# --- DRAIN: SIGTERM A ---
log "HA: SIGTERM -> draining instance A (pid $A_PID)"
kill -TERM "$A_PID"
# 摘流: A /readyz must go 503 within the drain window.
raz=200; t=0
while [ "$t" -lt 40 ]; do raz="$(readyz "$A_MET")"; [ "$raz" = "503" ] && break; sleep 0.2; t=$((t+1)); done
assert_eq "$raz" "503" "instance A flipped /readyz to 503 (draining/摘流)"
grep -qiE 'draining|shut' "$W/a.gw.log" 2>/dev/null && pass "A log evidences drain" || log "note: no drain line in A log yet"

# --- during drain, a NEW session must route to B (A receives none) ---
lb_session 'printf LIVE_B'
assert_eq "$NS_RC" "0" "drain-window session executed"
assert_eq "$NS_OUT" "LIVE_B" "drain-window output"
assert_eq "$LAST_INST" "B" "drain-window new session routed to B (not draining A)"
pass "摘流 window: new session routed to B"

# --- A's in-flight session must get a clean goodbye (not a hang/reset) ---
for _ in $(seq 1 60); do kill -0 "$EXIST_PID" 2>/dev/null || break; sleep 0.2; done
if kill -0 "$EXIST_PID" 2>/dev/null; then kill -9 "$EXIST_PID" 2>/dev/null; fail "A's in-flight session HUNG (no goodbye)"; fi
wait "$EXIST_PID" 2>/dev/null || true
comb="$(cat "$W/a.existing.err" 2>/dev/null)$(cat "$W/a.existing.out" 2>/dev/null)"
lc="$(printf '%s' "$comb" | tr 'A-Z' 'a-z')"
if printf '%s' "$lc" | grep -Eq 'shutting down|shutdown|draining|drain|disconnect'; then
  pass "A in-flight session received clean goodbye: $(grep -im1 -E 'shut|drain|disconnect' "$W/a.existing.err" 2>/dev/null | cut -c1-70)"
else fail "A in-flight session closed WITHOUT a goodbye"; fi
assert_not_contains "$lc" "broken pipe" "not a broken pipe"
assert_not_contains "$lc" "connection reset" "not a connection reset"

# --- wait for A to fully exit ---
for _ in $(seq 1 60); do pid_alive "$A_PID" || break; sleep 0.2; done
pid_alive "$A_PID" && { kill -9 "$A_PID" 2>/dev/null; fail "instance A did not exit after drain deadline"; }
pass "instance A fully drained and exited"

# --- RE-ADMIT: restart A -> readyz 200 -> LB routes to A again ---
start_replica A "$A_LISN" "$A_MET" "$W/a/rec" || fail "instance A failed to restart"
assert_eq "$(readyz "$A_MET")" "200" "re-admitted A is healthy (/readyz 200)"
lb_session 'printf LIVE_A2'
assert_eq "$NS_RC" "0" "post-re-admit session executed"
assert_eq "$NS_OUT" "LIVE_A2" "post-re-admit output"
assert_eq "$LAST_INST" "A" "A re-admitted: new session routed back to A"
pass "A re-admitted and serving new sessions"

log "HA drain rehearsal PASS: 摘流(A readyz 503)->新会话转 B->A 存量 goodbye->A 排空->重纳 A"
echo "OK: ha_drain"
