#!/usr/bin/env bash
# scripts/bench.sh — benchmark v2 (2026-10-13): three tiers, separated duties.
#
# v2 exists because v1 measured two different things with one number. Every
# new connection pays a fixed 1 s auth-backoff on its first "none" probe
# (min(auth_timeout, auth_rejection_pad), russh's stock anti-bruteforce pad),
# and v1 folded that into a 64 MB scp: "via ~45 MB/s / loss ~86%". That number
# is a measurement artifact — the same config on a reused connection does
# 386-602 MB/s (docs/perf-investigation.md 16/18) — and it also made the
# benchmark blind: a +-30% data-plane change is invisible under 1 s of setup.
#
#   Tier A — per-connection fixed cost      (diagnostic; ALERT only, never gates)
#     ssh true / ssh 'echo ok', median over BENCH_ITERS, direct vs via.
#     Expected: via ~1.06-1.17 s, direct ~0.10 s. The gap IS the 1 s backoff.
#     If via leaves [0.9x, 1.3x] of its baseline, print ALERT: per-connection
#     cost moved — that is what to look at when Tier C moves.
#
#   Tier B — data-plane throughput on a reused connection   (THE regression gate)
#     One OpenSSH ControlMaster per leg, many pure-stream rounds:
#       up   : ssh -S ctl 'cat >/dev/null'   < f
#       down : ssh -S ctl 'cat f'            > /dev/null
#     No handshake, no scp framing, no new connection inside a round. Median
#     MB/s over BENCH_ROUNDS per direction, byte-verified on an untimed pass.
#     Reuse is ASSERTED, not assumed: sshgw_agent_backend_auth_ok_total must
#     move by exactly 1 across the via master's lifetime (the gateway dials the
#     backend once, for the master's session) and by 0 on the direct leg. Any
#     other delta means the rounds silently opened fresh connections and the
#     numbers are the old artifact again -> exit 2.
#     Gate (BENCH_STRICT=1, default): via up/down median outside
#     [0.8x baseline, 1.2x baseline] -> non-zero exit.
#
#   Tier C — new-connection effective rate                  (record only)
#     The v1 64 MB scp over a fresh connection, relabelled `newconn`. It is
#     Tier A + Tier B together, not a data-plane number. NEVER gates.
#
#   How to read the three together (the only reason they are all here):
#     B unchanged + C worse  => per-connection cost moved   (check Tier A)
#     B worse + C unchanged  => data-plane regression       (the only action item)
#     C alone moved          => say nothing; C is not a gate.
#   Never judge a data-plane change from C. Ever.
#
# Knobs: BENCH_FILE_MB (64) BENCH_ITERS (5, Tier A/C rounds) BENCH_ROUNDS (5,
# Tier B rounds) BENCH_STRICT (1) BENCH_BASELINE_* (see below).
# A/B knobs for the gateway: GW_WINDOW GW_MAXPACKET GW_NODELAY GW_CIPHERS
# GW_GUARD. Self-contained local topology (sshd + mock CP + gateway).
set -uo pipefail
: "${BENCH_FILE_MB:=64}"
: "${BENCH_ITERS:=5}"
: "${BENCH_ROUNDS:=5}"
: "${BENCH_STRICT:=1}"
# Baselines for the Tier A/B bands (this host, release build, 64 MiB payload).
# Re-measure and update these together with docs/perf-report.md when the
# machine or the build changes; BENCH_STRICT=0 makes every band advisory.
: "${BENCH_BASELINE_VIA_MS:=1170}"           # Tier A: via ssh-true median
: "${BENCH_BASELINE_DIRECT_MS:=104}"         # Tier A: direct ssh-true median
: "${BENCH_BASELINE_VIA_UP_MBPS:=416}"       # Tier B: via uplink median
: "${BENCH_BASELINE_VIA_DOWN_MBPS:=556}"     # Tier B: via downlink median
: "${BENCH_BASELINE_DIRECT_UP_MBPS:=816}"    # Tier B: direct uplink median   (control leg)
: "${BENCH_BASELINE_DIRECT_DOWN_MBPS:=972}"  # Tier B: direct downlink median (control leg)
: "${BENCH_MASTER_SECS:=900}"               # master lifetime margin

WORK=$(mktemp -d /tmp/sshgw-bench.XXXXXX)
# The gateway holds no backend credential of its own (plan-agent-only), so the
# via-gateway legs need a live agent holding the end user's identity.
BENCH_AGENT_STARTED=0
CTL_DIRECT=""
CTL_VIA=""
bench_cleanup() {
  # Masters first: a leaked ControlMaster keeps a `sleep` and a backend
  # connection alive in the background.
  for ctl in "$CTL_DIRECT" "$CTL_VIA"; do
    [ -n "$ctl" ] && ssh -S "$ctl" -O exit localhost >/dev/null 2>&1 || true
  done
  [ -n "${GWPID:-}" ] && kill "$GWPID" 2>/dev/null || true
  [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null || true
  [ -n "${SSHD:-}" ] && kill "$SSHD" 2>/dev/null || true
  if [ "${BENCH_KEEP:-0}" = "1" ]; then
    echo "BENCH_KEEP=1: topology left in $WORK (gateway/sshd/mock-CP stopped)" >&2
  else
    rm -rf "$WORK"
  fi
  if [ "$BENCH_AGENT_STARTED" = "1" ]; then
    BENCH_AGENT_STARTED=0
    ssh-agent -k >/dev/null 2>&1 || true
  fi
}
trap bench_cleanup EXIT

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

# Shared signing backend for every via-gateway session.
eval "$(ssh-agent -s)" >/dev/null 2>&1 || { echo "ssh-agent failed" >&2; exit 2; }
BENCH_AGENT_STARTED=1
export SSH_AUTH_SOCK SSH_AGENT_PID
ssh-add "$WORK/assets/user_ed25519" </dev/null >/dev/null 2>&1   || { echo "ssh-add failed" >&2; exit 2; }

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
{"resolve":{"bench":{"status":200,"target":{"host":"127.0.0.1","port":$S,"user":"$(id -un)"},"policy":{"agent_forwarding":true,"ttl":60}}},"default":{"status":404,"error":"nf"}}
EOF
python3 "$PWD/scripts/mock_control_plane.py" --port "$CP" --rules "$WORK/rules.json" --access-log "$WORK/cp.log" >"$WORK/cp.out" 2>&1 & CPID=$!
sleep 1
curl -sf "http://127.0.0.1:$CP/healthz" >/dev/null || { echo "mock CP failed" >&2; exit 2; }


# A/B knobs: GW_NODELAY=true|false, GW_CIPHERS="aes256-gcm,aes128-gcm" (empty=none)
GW_CIPHERS_LINE=""
if [ -n "${GW_CIPHERS:-}" ]; then
  GW_CIPHERS_LINE="ciphers = [\"$(echo "$GW_CIPHERS" | sed 's/,/","/g')\"]"
fi
export GW_CIPHERS_LINE

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
# Default the target dir the way pure_legs.sh does: line 96 dereferences it
# unconditionally, so an unset CARGO_TARGET_DIR (any run outside `cargo`) aborted
# the whole benchmark before the gateway could start.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
test -x "${CARGO_TARGET_DIR}/release/ssh-gw" || cargo build --release --bin ssh-gw >/dev/null 2>&1
"${CARGO_TARGET_DIR}/release/ssh-gw" --config "$WORK/gw.toml" >"$WORK/gw.log" 2>&1 & GWPID=$!
ok=0; for i in $(seq 1 40); do curl -sf "http://127.0.0.1:$M/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.25; done
[ "$ok" = 1 ] || { echo "gateway failed to start" >&2; tail -15 "$WORK/gw.log" >&2; exit 2; }

# --- common ssh option arrays (bash arrays: correct word splitting) ---
DIRECT=(-p "$S" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes)
VIA=(-p "$G" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes)
# scp: port is -P (lowercase -p means "preserve") — separate arrays
SCP_DIRECT=(-P "$S" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes)
SCP_VIA=(-P "$G" -i "$WORK/assets/user_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ForwardAgent=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes)
TARGET_DIRECT="127.0.0.1"
TARGET_VIA="bench@127.0.0.1"
REMOTE_FILE="$WORK/r.bin"

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

# mbps <mib> <ms> -> MB/s for one round
mbps() { python3 -c "print(round($1*1000.0/$2,1))" 2>/dev/null || echo 0; }

# metric <name> -> integer counter value from the gateway's /metrics
metric() {
  curl -fsS --max-time 5 "http://127.0.0.1:$M/metrics" 2>/dev/null \
    | awk -v m="$1" '$1==m {print $2; exit}'
}

FAILURES=0
REUSE_FAILURES=0
note_failure() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }

# ---------------------------------------------------------------------------
# Tier A — per-connection fixed cost (diagnostic, never gates)
# ---------------------------------------------------------------------------
echo "== Tier A: per-connection fixed cost (median ms over $BENCH_ITERS; strict rc) =="
tier_a_latency() {
  local mode="$1" target="$2"; shift 2
  local -a opts=("$@")
  local i rc s t
  local -a h=() e=()
  for i in $(seq 1 "$BENCH_ITERS"); do
    s=$(NOW); ssh "${opts[@]}" "$target" 'true' >/dev/null 2>&1; rc=$?; t=$(NOW)
    [ "$rc" = 0 ] || note_failure "Tier A $mode handshake rc=$rc"
    h+=("$(ms "$s" "$t")")
    s=$(NOW); ssh "${opts[@]}" "$target" 'echo ok' >/dev/null 2>&1; rc=$?; t=$(NOW)
    [ "$rc" = 0 ] || note_failure "Tier A $mode exec rc=$rc"
    e+=("$(ms "$s" "$t")")
  done
  # The two modes are the only callers; keeping the storage explicit avoids
  # dynamic variable names that a reader (and shellcheck) cannot follow.
  local got_h got_e
  got_h=$(med "${h[@]}"); got_e=$(med "${e[@]}")
  if [ "$mode" = direct ]; then A_DIRECT_H=$got_h; A_DIRECT_E=$got_e; else A_VIA_H=$got_h; A_VIA_E=$got_e; fi
  printf '  %-8s handshake %7.1f ms   exec %7.1f ms\n' "$mode" "$got_h" "$got_e"
}
tier_a_latency direct "$TARGET_DIRECT" "${DIRECT[@]}"
tier_a_latency via "$TARGET_VIA" "${VIA[@]}"
# Band check (advisory: per-connection cost is not a regression gate).
python3 - "$A_VIA_H" "$BENCH_BASELINE_VIA_MS" <<'PY'
import sys
got, base = float(sys.argv[1]), float(sys.argv[2])
lo, hi = base * 0.9, base * 1.3
print(f"  via handshake {got:.1f} ms vs baseline {base:.0f} ms band [{lo:.0f},{hi:.0f}] "
      + ("OK" if lo <= got <= hi else "ALERT: per-connection cost moved (check this when Tier C moves)"))
PY

# ---------------------------------------------------------------------------
# Tier B — data-plane throughput over a reused connection (the gate)
# ---------------------------------------------------------------------------
echo "== Tier B: data-plane throughput on one reused connection ($BENCH_FILE_MB MB, $BENCH_ROUNDS rounds/direction; verified) =="
# Payload for every Tier B round; staged on the backend once per leg, untimed.
python3 -c "open('$WORK/f.bin','wb').write(b'x'*(${BENCH_FILE_MB}*1024*1024))"

# start_master <ctl> <target> <opts...> — one master per leg, held by a remote
# sleep. The session channel is what makes the gateway dial the backend, so the
# whole Tier B block costs exactly one backend dial (asserted below).
start_master() {
  local ctl="$1" target="$2"; shift 2
  local -a opts=("$@")
  rm -f "$ctl"
  ssh -M -S "$ctl" -f "${opts[@]}" "$target" "sleep $BENCH_MASTER_SECS" >/dev/null 2>&1 || return 1
  # A dead master would silently turn every round into a fresh connection.
  ssh -S "$ctl" -O check "$target" >/dev/null 2>&1 || return 1
}

stop_master() {
  local ctl="$1" target="$2"
  [ -n "$ctl" ] && [ -S "$ctl" ] && ssh -S "$ctl" -O exit "$target" >/dev/null 2>&1 || true
}

# measure_reuse <label> <ctl> <target> -> sets REUSE_UP/REUSE_DOWN (median MB/s)
measure_reuse() {
  local label="$1" ctl="$2" target="$3"
  local i rc s t remote_bytes
  local -a up=() down=()
  # Never inherit the previous leg's numbers: a failed leg must leave these
  # unset, not silently republish the leg before it.
  REUSE_UP=""; REUSE_DOWN=""

  # Untimed staging pass: proves the uplink path moves the whole file (rc +
  # size) and gives the downlink rounds something to cat.
  if ! ssh -S "$ctl" "$target" "cat > $REMOTE_FILE" < "$WORK/f.bin" >/dev/null 2>&1; then
    note_failure "Tier B $label: could not stage the payload on the backend"; return 1
  fi
  remote_bytes=$(ssh -S "$ctl" "$target" "wc -c < $REMOTE_FILE" 2>/dev/null | tr -d ' \t\n')
  if [ "$remote_bytes" != "$((BENCH_FILE_MB*1024*1024))" ]; then
    note_failure "Tier B $label: staged size mismatch (got '$remote_bytes')"; return 1
  fi
  # Untimed byte-verified downlink pass (cmp), so the timed rounds below are
  # allowed to be pure streams.
  ssh -S "$ctl" "$target" "cat $REMOTE_FILE" > "$WORK/v.bin" 2>/dev/null
  if ! cmp -s "$WORK/f.bin" "$WORK/v.bin"; then
    note_failure "Tier B $label: downlink bytes differ from the source"; rm -f "$WORK/v.bin"; return 1
  fi
  rm -f "$WORK/v.bin"

  for i in $(seq 1 "$BENCH_ROUNDS"); do
    s=$(NOW); ssh -S "$ctl" "$target" 'cat >/dev/null' < "$WORK/f.bin" >/dev/null 2>&1; rc=$?; t=$(NOW)
    [ "$rc" = 0 ] || { note_failure "Tier B $label uplink round $i rc=$rc"; return 1; }
    up+=("$(mbps "$BENCH_FILE_MB" "$(ms "$s" "$t")")")
    s=$(NOW); ssh -S "$ctl" "$target" "cat $REMOTE_FILE" >/dev/null 2>&1; rc=$?; t=$(NOW)
    [ "$rc" = 0 ] || { note_failure "Tier B $label downlink round $i rc=$rc"; return 1; }
    down+=("$(mbps "$BENCH_FILE_MB" "$(ms "$s" "$t")")")
  done
  ssh -S "$ctl" "$target" "rm -f $REMOTE_FILE" >/dev/null 2>&1 || true

  REUSE_UP=$(med "${up[@]}")
  REUSE_DOWN=$(med "${down[@]}")
  printf '  %-8s up %7.1f MB/s   down %7.1f MB/s   (median of %s rounds)\n' \
    "$label" "$REUSE_UP" "$REUSE_DOWN" "$BENCH_ROUNDS"
}

tier_b() {
  local mode="$1" ctl="$2" target="$3"; shift 3
  local -a opts=("$@")
  local before after dial_delta expected_dials
  local rc=0

  # The reuse assertion is the difference, not the absolute counter: Tier A
  # already opened sessions, and the gateway's counter is process-wide. What
  # must hold is that the master contributed the right number of dials —
  # exactly 1 on the via leg (the gateway dials the backend for the master's
  # session), and 0 on the direct leg (which never touches the gateway; a
  # non-zero there would mean the "direct" leg is not direct at all).
  expected_dials=0; [ "$mode" = via ] && expected_dials=1
  before=$(metric sshgw_agent_backend_auth_ok_total)
  before=${before:-0}
  if ! start_master "$ctl" "$target" "${opts[@]}"; then
    note_failure "Tier B $mode: could not start/verify the ControlMaster"; return 1
  fi
  if ! measure_reuse "$mode" "$ctl" "$target"; then rc=1; fi
  stop_master "$ctl" "$target"
  after=$(metric sshgw_agent_backend_auth_ok_total)
  after=${after:-0}
  dial_delta=$((after - before))
  printf '  %-8s backend dials during the master: %s (sshgw_agent_backend_auth_ok_total %s -> %s, expected %s)\n' \
    "$mode" "$dial_delta" "$before" "$after" "$expected_dials"
  if [ "$dial_delta" != "$expected_dials" ]; then
    note_failure "Tier B $mode: expected $expected_dials backend dial(s), got $dial_delta — connection reuse failed, numbers are a new-connection artifact"
    REUSE_FAILURES=$((REUSE_FAILURES + 1))
    return 1
  fi
  [ "$rc" = 0 ] || return 1
  if [ "$mode" = direct ]; then DIRECT_UP=$REUSE_UP; DIRECT_DOWN=$REUSE_DOWN
  else VIA_UP=$REUSE_UP; VIA_DOWN=$REUSE_DOWN; fi
}

CTL_DIRECT="$WORK/ctl.direct"
CTL_VIA="$WORK/ctl.via"
tier_b direct "$CTL_DIRECT" "$TARGET_DIRECT" "${DIRECT[@]}"
tier_b via "$CTL_VIA" "$TARGET_VIA" "${VIA[@]}"

# ---------------------------------------------------------------------------
# Tier C — new-connection effective rate (record only, never gates)
# ---------------------------------------------------------------------------
echo "== Tier C: new-connection scp (${BENCH_FILE_MB}MB, best of $BENCH_ITERS; setup + transfer, record only) =="
best_d=0; best_v=0
for i in $(seq 1 "$BENCH_ITERS"); do
  rm -f "$WORK/f.d"
  s=$(NOW); scp -q "${SCP_DIRECT[@]}" "$WORK/f.bin" "$TARGET_DIRECT:$WORK/f.d" >/dev/null 2>&1; rc=$?; t=$(NOW)
  if [ "$rc" = 0 ] && [ -f "$WORK/f.d" ] && [ "$(wc -c < "$WORK/f.d" | tr -d " \t\n")" = "$((BENCH_FILE_MB*1024*1024))" ]; then
    mbps=$(python3 -c "print(round(${BENCH_FILE_MB}/($t-$s),1))"); best_d=$(python3 -c "print(max($best_d,$mbps))")
  else
    note_failure "Tier C direct scp iteration $i rc=$rc actual_bytes=$(wc -c < "$WORK/f.d" 2>/dev/null | tr -d " " || echo none)"
  fi
done
for i in $(seq 1 "$BENCH_ITERS"); do
  rm -f "$WORK/f.gw"
  s=$(NOW); scp -q "${SCP_VIA[@]}" "$WORK/f.bin" "$TARGET_VIA:$WORK/f.gw" >/dev/null 2>&1; rc=$?; t=$(NOW)
  if [ "$rc" = 0 ] && [ -f "$WORK/f.gw" ] && [ "$(wc -c < "$WORK/f.gw" | tr -d " \t\n")" = "$((BENCH_FILE_MB*1024*1024))" ]; then
    mbps=$(python3 -c "print(round(${BENCH_FILE_MB}/($t-$s),1))"); best_v=$(python3 -c "print(max($best_v,$mbps))")
  else
    note_failure "Tier C via scp iteration $i rc=$rc actual_bytes=$(wc -c < "$WORK/f.gw" 2>/dev/null | tr -d " " || echo none)"
  fi
done
printf '  %-8s %6.1f MB/s\n' "direct" "$best_d"
printf '  %-8s %6.1f MB/s   (Tier A + Tier B combined — NOT a data-plane number)\n' "newconn" "$best_v"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
echo "== verdict =="
tier_b_gate() {
  local dir="$1" got="$2" base="$3"
  python3 - "$dir" "$got" "$base" <<'PY'
import sys
d, got, base = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
if base <= 0:
    print(f"  Tier B {d}: baseline unset — set BENCH_BASELINE_{d.upper()}_MBPS"); raise SystemExit(1)
lo, hi = base * 0.8, base * 1.2
ok = lo <= got <= hi
verdict = "OK" if ok else ("UPSIDE: >1.2x — re-measure and raise the baseline" if got > hi else "REGRESSION: data plane moved")
note = "" if d.startswith("via") else "  [control leg: a move here is the host or the harness, not the gateway]"
print(f"  Tier B {d:11} {got:7.1f} MB/s vs baseline {base:.1f} MB/s band [{lo:.1f},{hi:.1f}] {verdict}{note}")
raise SystemExit(0 if ok else 1)
PY
}
GATE_FAILURES=0
if [ -n "${DIRECT_UP:-}" ]; then
  tier_b_gate direct_up "$DIRECT_UP" "$BENCH_BASELINE_DIRECT_UP_MBPS" || GATE_FAILURES=$((GATE_FAILURES + 1))
  tier_b_gate direct_down "$DIRECT_DOWN" "$BENCH_BASELINE_DIRECT_DOWN_MBPS" || GATE_FAILURES=$((GATE_FAILURES + 1))
fi
if [ -n "${VIA_UP:-}" ]; then
  tier_b_gate via_up "$VIA_UP" "$BENCH_BASELINE_VIA_UP_MBPS" || GATE_FAILURES=$((GATE_FAILURES + 1))
  tier_b_gate via_down "$VIA_DOWN" "$BENCH_BASELINE_VIA_DOWN_MBPS" || GATE_FAILURES=$((GATE_FAILURES + 1))
fi
[ "$GATE_FAILURES" = 0 ] && echo "  Tier B gate: within +-20% of baseline (the only throughput regression gate)"

if [ "$REUSE_FAILURES" != 0 ]; then
  # Distinct code: a reuse failure does not mean the gateway is slow, it means
  # the numbers are not Tier B numbers at all.
  echo "RESULT: INVALID (connection reuse failed; Tier B numbers are unusable)" >&2
  exit 2
fi
if [ "$FAILURES" != 0 ]; then
  echo "RESULT: FAILED ($FAILURES hard failure(s): rc / byte check)" >&2
  exit 1
fi
if [ "$GATE_FAILURES" != 0 ]; then
  if [ "${BENCH_STRICT}" = "1" ]; then
    echo "RESULT: FAILED (Tier B outside +-20%, BENCH_STRICT=1)" >&2
    exit 1
  fi
  echo "RESULT: OK with advisory gate failures (BENCH_STRICT=0)"
  exit 0
fi
echo "RESULT: OK"
exit 0
