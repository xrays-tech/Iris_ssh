#!/usr/bin/env bash
# scripts/pure_legs.sh — pure-leg (single-direction) throughput probe.
#
# Complements scripts/bench.sh (which measures scp end-to-end = both legs + sftp
# framing). This measures ONE direction at a time through the gateway, with a
# pure pipe on both ends (no disk), byte-verified separately (untimed pass).
#
#   up   : client -> gateway -> backend   (ssh GW 'cat >/dev/null' < f)
#   down : backend -> gateway -> client   (ssh GW 'cat f' > /dev/null)
#
# Same self-contained local topology as bench.sh (sshd + mock CP + gateway).
# A/B knobs via env (no recompile, edit gw.toml only):
#   GW_NODELAY=false|true   GW_WINDOW=1MB|2MiB|8MB   GW_MAXPACKET=32KB
#   GW_CIPHERS="aes256-gcm,aes128-gcm"   GW_GUARD=true|false
#   PL_FILE_MB (default 64)   PL_ITERS (default 3)   PL_ROUNDS (default 2)
#   GW_BIN (default ${CARGO_TARGET_DIR}/release/ssh-gw)
#
# Alternating A/B (direct vs via-gw) per round controls ordering bias.
# Strict rc checks — no fake numbers. Usage: run with CARGO_TARGET_DIR set.
set -uo pipefail
: "${PL_FILE_MB:=64}"
: "${PL_ITERS:=3}"
: "${PL_ROUNDS:=2}"
# Default the cargo target dir so a bare `./scripts/pure_legs.sh` works;
# build the release binary if it's missing (same fallback as bench.sh).
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
[ -x "$CARGO_TARGET_DIR/release/ssh-gw" ] || cargo build --release --bin ssh-gw >/dev/null 2>&1
GW_BIN=${GW_BIN:-${CARGO_TARGET_DIR}/release/ssh-gw}
WORK=$(mktemp -d /tmp/sshgw-plegs.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

NOW() { python3 -c 'import time; print(time.time())'; }
median() {
  python3 - "$@" <<'PY'
import sys
v = sorted(float(x) for x in sys.argv[1:])
print(v[len(v)//2])
PY
}

# --- sockets ---
S=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
CP=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
G=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
M=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

# --- assets ---
mkdir -p "$WORK/assets"; chmod 700 "$WORK/assets"
for n in hostkey_ed25519 backend_ed25519 user_ed25519 sshd_host_ed25519; do
  ssh-keygen -q -t ed25519 -N "" -C "plegs-$n" -f "$WORK/assets/$n" 2>/dev/null \
    || { echo "keygen failed for $n" >&2; exit 2; }
  chmod 600 "$WORK/assets/$n"
done
cat "$WORK/assets/backend_ed25519.pub" "$WORK/assets/user_ed25519.pub" > "$WORK/assets/authorized_keys"
chmod 600 "$WORK/assets/authorized_keys"

# --- backend sshd ---
cat > "$WORK/sshd.cfg" <<EOF
Port $S
ListenAddress 127.0.0.1
HostKey $WORK/assets/sshd_host_ed25519
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $WORK/assets/authorized_keys
StrictModes no
UsePAM no
PermitRootLogin yes
MaxSessions 10
PidFile $WORK/sshd.pid
EOF
/usr/sbin/sshd -f "$WORK/sshd.cfg" -D -e >"$WORK/sshd.log" 2>&1 & SSHD=$!
sleep 1
kill -0 "$SSHD" 2>/dev/null || { echo "sshd failed to start" >&2; tail -10 "$WORK/sshd.log" >&2; exit 2; }

# --- mock control plane ---
cat > "$WORK/rules.json" <<EOF
{"resolve":{"plegs":{"status":200,"target":{"host":"127.0.0.1","port":$S,"user":"$(id -un)"},"policy":{"ttl":60}}},"default":{"status":404,"error":"nf"}}
EOF
python3 "$PWD/scripts/mock_control_plane.py" --port "$CP" --rules "$WORK/rules.json" --access-log "$WORK/cp.log" >"$WORK/cp.out" 2>&1 & CPID=$!
sleep 1
curl -sf "http://127.0.0.1:$CP/healthz" >/dev/null || { echo "mock CP failed" >&2; exit 2; }

# --- gateway config (knobs from env; no recompile) ---
GW_CIPHERS_LINE=""
if [ -n "${GW_CIPHERS:-}" ]; then
  GW_CIPHERS_LINE="ciphers = [\"$(echo "$GW_CIPHERS" | sed 's/,/","/g')\"]"
fi
cat > "$WORK/gw.toml" <<EOF
[listen]
addr = "127.0.0.1:$G"
[host_keys]
keys = [ { path = "$WORK/assets/hostkey_ed25519", state = "active" } ]
[relay]
window_size = "${GW_WINDOW:-1MB}"
max_packet = "${GW_MAXPACKET:-32KB}"
outbound_guard = ${GW_GUARD:-true}
nodelay = ${GW_NODELAY:-false}
${GW_CIPHERS_LINE}
[backend]
private_key = "$WORK/assets/backend_ed25519"
host_key_policy = "accept-new"
[pool]
enabled = false
[control_plane]
url = "http://127.0.0.1:$CP/api/v1/resolve"
cache_ttl = "30s"
timeout = "2s"
[limits]
max_sessions = 1000
max_sessions_per_ip = 100
auth_timeout = "1s"
[shutdown]
drain_wait = "1s"
disconnect_flush = "2s"
hard_deadline = "20s"
[metrics]
addr = "127.0.0.1:$M"
EOF
[ -x "$GW_BIN" ] || { echo "gateway binary not found at $GW_BIN" >&2; exit 2; }
"$GW_BIN" --config "$WORK/gw.toml" >"$WORK/gw.log" 2>&1 & GWPID=$!
ok=0
for i in $(seq 1 40); do
  curl -sf "http://127.0.0.1:$M/healthz" >/dev/null 2>&1 && { ok=1; break; }
  sleep 0.25
done
[ "$ok" = 1 ] || { echo "gateway failed to start" >&2; tail -15 "$WORK/gw.log" >&2; exit 2; }

# --- ssh option arrays (bash arrays: correct word splitting) ---
# Persistent known_hosts so the two targets (direct:127.0.0.1:S, via:plegs@127.0.0.1:G)
# each record their host key without interfering with each other.
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile="$WORK/known_hosts" -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
DIRECT=("${SSH_OPTS[@]}" -p "$S" -i "$WORK/assets/user_ed25519" 127.0.0.1)
VIA=("${SSH_OPTS[@]}" -p "$G" -i "$WORK/assets/user_ed25519" plegs@127.0.0.1)

BYTES=$((PL_FILE_MB * 1024 * 1024))
python3 -c "open('$WORK/f.bin','wb').write(b'x'*(${PL_FILE_MB}*1024*1024))"

# --- per-direction measurement functions ---
# measure_up <label> <ssh-args...> -> sets global M_UP (MB/s best-of-PL_ITERS) or 0 on fail
measure_up() {
  local label="$1"; shift
  local best=0 i s t rc
  # untimed byte-verification pass (writes to backend tmp, checks count)
  local vout
  vout=$(ssh "$@" "cat > $WORK/up.bin; wc -c < $WORK/up.bin" < "$WORK/f.bin" 2>"$WORK/ssh.err") || true
  if [ "$(echo "$vout" | tr -d ' \t\n')" != "$BYTES" ]; then
    echo "  $label up verification failed: got='$vout' err=$(cat "$WORK/ssh.err")" >&2
    M_UP=0; return 1
  fi
  rm -f "$WORK/up.bin"
  # timed runs: pure pipe into the remote's /dev/null (no disk at either end)
  for i in $(seq 1 "$PL_ITERS"); do
    s=$(NOW)
    ssh "$@" "cat >/dev/null" < "$WORK/f.bin" >/dev/null 2>"$WORK/ssh.err"; rc=$?
    t=$(NOW)
    if [ "$rc" = 0 ]; then
      best=$(python3 -c "print(max($best, ${PL_FILE_MB}/($t-$s)))")
    else
      echo "  $label up iter $i rc=$rc err=$(cat "$WORK/ssh.err") (not counted)" >&2
    fi
  done
  M_UP=$best
}

measure_down() {
  local label="$1"; shift
  local best=0 i s t rc
  # untimed byte-verification pass (reads remote file to local pipe, counts bytes)
  local vcount
  vcount=$(ssh "$@" "cat $WORK/f.bin" 2>"$WORK/ssh.err" | wc -c | tr -d ' \t\n') || true
  if [ "$vcount" != "$BYTES" ]; then
    echo "  $label down verification failed: got='$vcount' err=$(cat "$WORK/ssh.err")" >&2
    M_DOWN=0; return 1
  fi
  # timed runs: pure pipe out of the remote file into local /dev/null (no disk)
  for i in $(seq 1 "$PL_ITERS"); do
    s=$(NOW)
    ssh "$@" "cat $WORK/f.bin" > /dev/null 2>"$WORK/ssh.err"; rc=$?
    t=$(NOW)
    if [ "$rc" = 0 ]; then
      best=$(python3 -c "print(max($best, ${PL_FILE_MB}/($t-$s)))")
    else
      echo "  $label down iter $i rc=$rc err=$(cat "$WORK/ssh.err") (not counted)" >&2
    fi
  done
  M_DOWN=$best
}

# --- alternating A/B: round-robin direct/via to control ordering bias ---
UP_D=(); UP_V=(); DN_D=(); DN_V=()
for r in $(seq 1 "$PL_ROUNDS"); do
  # direct first half of the round, via second (swap order on even rounds)
  if [ $((r % 2)) -eq 1 ]; then
    measure_up  "direct r$r" "${DIRECT[@]}"; UP_D+=("$M_UP")
    measure_up  "via r$r"    "${VIA[@]}";    UP_V+=("$M_UP")
    measure_down "direct r$r" "${DIRECT[@]}"; DN_D+=("$M_DOWN")
    measure_down "via r$r"    "${VIA[@]}";    DN_V+=("$M_DOWN")
  else
    measure_up  "via r$r"    "${VIA[@]}";    UP_V+=("$M_UP")
    measure_up  "direct r$r" "${DIRECT[@]}"; UP_D+=("$M_UP")
    measure_down "via r$r"    "${VIA[@]}";    DN_V+=("$M_DOWN")
    measure_down "direct r$r" "${DIRECT[@]}"; DN_D+=("$M_DOWN")
  fi
done

echo "== pure legs (node=$GW_NODELAY win=$GW_WINDOW; ${PL_FILE_MB}MB, best-of-$PL_ITERS x $PL_ROUNDS rounds; median) =="
printf '  direct up    %6.1f MB/s\n' "$(median "${UP_D[@]}")"
printf '  via-gw up    %6.1f MB/s\n' "$(median "${UP_V[@]}")"
printf '  direct down  %6.1f MB/s\n' "$(median "${DN_D[@]}")"
printf '  via-gw down  %6.1f MB/s\n' "$(median "${DN_V[@]}")"

kill "$GWPID" "$CPID" "$SSHD" 2>/dev/null; wait 2>/dev/null || true
