#!/usr/bin/env bash
# scripts/lib.sh — shared helpers for the ssh-gateway black-box integration suite.
#
# Sourced by orchestrator and by test cases. Pure bash 3.2 compatible (macOS
# /bin/bash is 3.2.57). No associative arrays, no ${var,,}, no mapfile.
#
# This file declares helpers only; it does not create directories or processes.
set -uo pipefail

# ---------------------------------------------------------------------------
# Logging (all diagnostics to stderr so stdout stays machine-friendly)
# ---------------------------------------------------------------------------
_ts() { date "+%H:%M:%S"; }
log()     { printf '[%s] %s\n' "$(_ts)" "$*" >&2; }
log_err() { printf '[%s] ERROR: %s\n' "$(_ts)" "$*" >&2; }
die()     { log_err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Networking helpers (python3 is guaranteed present on macOS + CI images).
# ---------------------------------------------------------------------------

# alloc_port -> prints a freshly-allocated free TCP port on 127.0.0.1.
alloc_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# wait_tcp_open <host> <port> <timeout_secs> -> 0 if a TCP connect succeeded.
wait_tcp_open() {
  local host="$1" port="$2" timeout="${3:-20}"
  python3 - "$host" "$port" "$timeout" <<'PY'
import socket, sys, time
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        c = socket.create_connection((host, port), timeout=1.0)
        c.close()
        sys.exit(0)
    except OSError:
        time.sleep(0.15)
sys.exit(1)
PY
}

# wait_http_ok <url> <timeout_secs> -> 0 when the URL returns a 2xx/3xx.
wait_http_ok() {
  local url="$1" timeout="${2:-20}"
  python3 - "$url" "$timeout" <<'PY'
import sys, time, urllib.request
url, timeout = sys.argv[1], float(sys.argv[2])
deadline = time.time() + timeout
while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            if 200 <= r.status < 400:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(0.15)
sys.exit(1)
PY
}

# ---------------------------------------------------------------------------
# Portable timeout runner. Prefers GNU coreutils `timeout`, then `gtimeout`,
# then a perl fork/exec/alarm fallback so the suite never depends on any single
# tool being on PATH.
# ---------------------------------------------------------------------------
run_with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
  else
    perl -e '
      my $t = shift @ARGV;
      my $pid = fork();
      if ($pid == 0) { exec @ARGV; exit 127; }
      eval {
        local $SIG{ALRM} = sub { kill "TERM", $pid; die "timeout\n"; };
        alarm $t; waitpid($pid, 0); alarm 0;
      };
      exit($? >> 8);
    ' "$secs" "$@"
  fi
}

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------
pid_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }

# stop_pid <pid> — polite TERM, escalate to KILL after ~2s.
stop_pid() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL "$pid" 2>/dev/null || true
}

# rss_kb <pid> — resident set size in KB via ps (macOS `ps -o rss=`).
rss_kb() {
  local pid="$1" v
  v="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"
  [ -n "$v" ] && printf '%s' "$v" || printf '0'
}

# tail_log <file> [lines] — diagnostic dump used on failure.
tail_log() {
  local f="$1" n="${2:-40}"
  if [ -f "$f" ]; then
    printf '%s\n' "----- tail -n $n $f -----" >&2
    tail -n "$n" "$f" >&2 || true
    printf '%s\n' "----- end $f -----" >&2
  fi
}

# ---------------------------------------------------------------------------
# Minimal assertions for standalone scripts/*.sh harnesses that source lib.sh
# but not tests/integration/common.sh (cases redefine these with CASE_NAME, so
# they are unaffected — common.sh is sourced after lib.sh and overrides).
# ---------------------------------------------------------------------------
pass() { printf 'PASS: %s\n' "$*" >&2; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq()        { if [ "$1" = "$2" ]; then pass "eq '$1' ($3)"; else fail "$3: expected [$2] got [$1]"; fi; }
assert_ne()        { if [ "$1" != "$2" ]; then pass "ne ($3)"; else fail "$3: expected != [$2]"; fi; }
assert_contains()  { case "$1" in *"$2"*) pass "contains '$2' ($3)";; *) fail "$3: expected to contain [$2]";; esac; }
assert_not_contains(){ case "$1" in *"$2"*) fail "$3: expected NOT to contain [$2]";; *) pass "not-contains ($3)";; esac; }
assert_rc0()       { local rc=0 o; o="$("$@" 2>&1)" || rc=$?; if [ "$rc" = 0 ]; then pass "rc0 :: $*"; else fail "rc0 expected: $* got rc=$rc out=[$o]"; fi; }
