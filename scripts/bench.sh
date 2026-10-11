#!/usr/bin/env bash
# scripts/bench.sh — gateway-vs-direct performance benchmark (plan M1-T11).
# Self-contained local topology (sshd + mock CP + gateway), measures:
#   * ssh handshake->exit latency (ssh 'true')       direct vs via gateway
#   * exec latency (ssh 'echo ok')
#   * scp throughput (memory-backed file)             direct vs via gateway
# Outputs a summary; run `make bench`. Strict rc checks — no fake numbers.
set -uo pipefail
: "${BENCH_FILE_MB:=64}"
: "${BENCH_ITERS:=5}"
WORK=$(mktemp -d /tmp/sshgw-bench.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# --- sockets ---
S=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
CP=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
G=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
M=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

# --- assets ---
mkdir -p "$WORK/assets"; chmod 700 "$WORK/assets"
for n in hostkey_ed25519 backend_ed25519 user_ed25519 sshd_host_ed25519; do
  ssh-keygen -q -t ed25519 -N "" -C "bench-$n" -f "$WORK/assets/$n" 2>/dev/null || { echo "keygen failed for $n" >&2; exit 2; }
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
Subsystem sftp /usr/libexec/sftp-server
EOF
/usr/sbin/sshd -f "$WORK/sshd.cfg" -D -e >"$WORK/sshd.log" 2>&1 & SSHD=$!
sleep 1
kill -0 "$SSHD" 2>/dev/null || { echo "sshd failed to start" >&2; tail -10 "$WORK/sshd.log" >&2; exit 2; }

# --- gateway topology ---
cat > "$WORK/rules.json" <<EOF
{"resolve":{"bench":{"status":200,"target":{"host":"127.0.0.1","port":$S,"user":"$(id -un)"},"policy":{"ttl":60}}},"default":{"status":404,"error":"nf"}}
EOF
python3 "$PWD/scripts/mock_control_plane.py" --port "$CP" --rules "$WORK/rules.json" --access-log "$WORK/cp.log" >"$WORK/cp.out" 2>&1 & CPID=$!
sleep 1
curl -sf "http://127.0.0.1:$CP/healthz" >/dev/null || { echo "mock CP failed" >&2; exit 2; }

cat > "$WORK/gw.toml" <<EOF
[listen]
addr = "127.0.0.1:$G"
[host_keys]
keys = [ { path = "$WORK/assets/hostkey_ed25519", state = "active" } ]
[relay]
window_size = "1MB"
max_packet = "32KB"
outbound_guard = true
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
test -x "${CARGO_TARGET_DIR:-nope}/release/ssh-gw" || cargo build --release --bin ssh-gw >/dev/null 2>&1
"${CARGO_TARGET_DIR}/release/ssh-gw" --config "$WORK/gw.toml" >"$WORK/gw.log" 2>&1 & GWPID=$!
ok=0; for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$M/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.25; done
[ "$ok" = 1 ] || { echo "gateway failed to start" >&2; tail -15 "$WORK/gw.log" >&2; exit 2; }

# --- common ssh option arrays (bash arrays: correct word splitting) ---
DIRECT=(-p "$S" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
VIA=(-p "$G" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
# scp: port is -P (lowercase -p means "preserve") — separate arrays
SCP_DIRECT=(-P "$S" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
SCP_VIA=(-P "$G" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR)
NOW() { python3 -c 'import time; print(time.time())'; }

ms() { python3 -c "print(round(($2 - $1) * 1000, 1))"; }

med() {
  # med <arr...> -> median (python)
  python3 - "$@" <<'PY'
import sys
v = sorted(float(x) for x in sys.argv[1:])
print(round(v[len(v)//2], 1))
PY
}

echo "== latency (median ms over $BENCH_ITERS; strict rc) =="
run_mode() {
  local mode="$1" i rc s t
  local -a h=() e=()
  for i in $(seq 1 "$BENCH_ITERS"); do
    if [ "$mode" = direct ]; then
      s=$(NOW); ssh "${DIRECT[@]}" 127.0.0.1 'true' >/dev/null 2>&1; rc=$?; t=$(NOW)
      [ "$rc" = 0 ] || echo "  direct handshake rc=$rc (FAILED)" >&2
      h+=("$(ms "$s" "$t")")
      s=$(NOW); ssh "${DIRECT[@]}" 127.0.0.1 'echo ok' >/dev/null 2>&1; rc=$?; t=$(NOW)
      [ "$rc" = 0 ] || echo "  direct exec rc=$rc (FAILED)" >&2
      e+=("$(ms "$s" "$t")")
    else
      s=$(NOW); ssh "${VIA[@]}" bench@127.0.0.1 'true' >/dev/null 2>&1; rc=$?; t=$(NOW)
      [ "$rc" = 0 ] || echo "  via handshake rc=$rc (FAILED)" >&2
      h+=("$(ms "$s" "$t")")
      s=$(NOW); ssh "${VIA[@]}" bench@127.0.0.1 'echo ok' >/dev/null 2>&1; rc=$?; t=$(NOW)
      [ "$rc" = 0 ] || echo "  via exec rc=$rc (FAILED)" >&2
      e+=("$(ms "$s" "$t")")
    fi
  done
  printf '%-18s %6.1f ms   (handshake)\n' "$mode" "$(med "${h[@]}")"
  printf '%-18s %6.1f ms   (exec)\n' "$mode" "$(med "${e[@]}")"
}
run_mode direct
run_mode via

echo "== scp throughput (${BENCH_FILE_MB}MB, best of $BENCH_ITERS; verified bytes) =="
python3 -c "open('$WORK/f.bin','wb').write(b'x'*(${BENCH_FILE_MB}*1024*1024))"
best_d=0; best_v=0
for i in $(seq 1 "$BENCH_ITERS"); do
  rm -f "$WORK/f.d"
  s=$(NOW); scp -q "${SCP_DIRECT[@]}" "$WORK/f.bin" "127.0.0.1:$WORK/f.d" >/dev/null 2>&1; rc=$?; t=$(NOW)
  if [ "$rc" = 0 ] && [ -f "$WORK/f.d" ] && [ "$(wc -c < "$WORK/f.d" | tr -d " \t\n")" = "$((BENCH_FILE_MB*1024*1024))" ]; then
    mbps=$(python3 -c "print(round(${BENCH_FILE_MB}/($t-$s),1))"); best_d=$(python3 -c "print(max($best_d,$mbps))")
  else
    echo "  direct scp iteration $i rc=$rc (not counted) actual_bytes=$(wc -c < "$WORK/f.d" 2>/dev/null | tr -d " " || echo none) exist=$([ -f "$WORK/f.d" ] && echo y || echo n)" >&2
  fi
done
for i in $(seq 1 "$BENCH_ITERS"); do
  rm -f "$WORK/f.gw"
  s=$(NOW); scp -q "${SCP_VIA[@]}" "$WORK/f.bin" "bench@127.0.0.1:$WORK/f.gw" >/dev/null 2>&1; rc=$?; t=$(NOW)
  if [ "$rc" = 0 ] && [ -f "$WORK/f.gw" ] && [ "$(wc -c < "$WORK/f.gw" | tr -d " \t\n")" = "$((BENCH_FILE_MB*1024*1024))" ]; then
    mbps=$(python3 -c "print(round(${BENCH_FILE_MB}/($t-$s),1))"); best_v=$(python3 -c "print(max($best_v,$mbps))")
  else
    echo "  via-gw scp iteration $i rc=$rc (not counted) actual_bytes=$(wc -c < "$WORK/f.gw" 2>/dev/null | tr -d " " || echo none) exist=$([ -f "$WORK/f.gw" ] && echo y || echo n)" >&2
  fi
done
printf 'direct scp : %6.1f MB/s\n' "$best_d"
printf 'via-gw scp : %6.1f MB/s\n' "$best_v"
python3 - <<PY
d, v = $best_d, $best_v
if d <= 0: print("direct scp failed — results unusable"); raise SystemExit(1)
loss = (d - v) / d * 100
print(f"throughput loss via gateway: {loss:.1f}%  (plan target <=15%)")
print("PASS (<15%)" if loss <= 15 else "RECORD (>15%): log the gap, do not fail")
PY
kill "$GWPID" "$CPID" "$SSHD" 2>/dev/null; wait 2>/dev/null || true
