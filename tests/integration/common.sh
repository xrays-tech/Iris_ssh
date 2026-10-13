#!/usr/bin/env bash
# tests/integration/common.sh — sourced by every case script.
#
# Relies on env exported by scripts/run_integration.sh:
#   GW_ADDR GW_PORT USER_KEY PRINCIPAL DENIED_PRINCIPAL NOTFOUND_PRINCIPAL
#   BACKEND_HOST BACKEND_PORT BACKEND_USER IT_WORK_DIR REMOTE_TMP_DIR
#
# Path semantics:
#   IT_WORK_DIR    gateway-host-local scratch (downloads, logs, local files)
#   REMOTE_TMP_DIR backend-side scratch (paths placed on the backend via the
#                  gateway: local mode == IT_WORK_DIR; remote mode == a /tmp dir
#                  created on the backend). Only difference matters in remote mode.
#
# Provides:
#   SSH_OPTS[]  ssh option array (client -> gateway)
#   TARGET      "principal@gateway"
#   sfp/scp helpers + assertion helpers. All assertion failures print a clear
#   FAIL line to stderr and exit(1). Success prints a PASS line.
#
# Cases must `set -euo pipefail` themselves; helpers here tolerate intentional
# non-zero exits via `|| rc=$?` and `if cmd; then`.
set -uo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../scripts/lib.sh
. "$CASE_DIR/../../scripts/lib.sh"

: "${GW_ADDR:?GW_ADDR not set (run via scripts/run_integration.sh)}"
: "${GW_PORT:?GW_PORT not set}"
: "${USER_KEY:?USER_KEY not set}"
: "${PRINCIPAL:?PRINCIPAL not set}"
: "${IT_WORK_DIR:?IT_WORK_DIR not set}"
: "${REMOTE_TMP_DIR:?REMOTE_TMP_DIR not set (run via scripts/run_integration.sh)}"

TARGET="${PRINCIPAL}@${GW_ADDR}"

# Common ssh options to the gateway. LogLevel=ERROR keeps client noise out so
# assertions can reason about clean stdout/stderr.
SSH_OPTS=(
  -p "$GW_PORT"
  -i "$USER_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o ConnectTimeout=10
  -o LogLevel=ERROR
)

SFTP_OPTS=(
  -P "$GW_PORT"
  -i "$USER_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o ConnectTimeout=10
  -o LogLevel=ERROR
)

SCP_OPTS=(
  -P "$GW_PORT"
  -i "$USER_KEY"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o ConnectTimeout=10
  -o LogLevel=ERROR
)

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
CASE_NAME="$(basename "${BASH_SOURCE[1]:-$0}" .sh 2>/dev/null || echo case)"
pass() { printf '[%s] PASS: %s\n' "$CASE_NAME" "$*" >&2; }
fail() { printf '[%s] FAIL: %s\n' "$CASE_NAME" "$*" >&2; exit 1; }
# skip_case <reason> — capability-gated skip. Emits a machine-visible marker on
# stdout and exits 0; the orchestrator counts these as SKIP (never as PASS), so a
# skipped case is never mistaken for a green assertion. Use ONLY when a real
# capability (real machine, a not-yet-landed src feature, a missing binary) is
# absent — never to paper over a real failing assertion.
skip_case() { printf 'SKIP_CASE: %s\n' "$*"; printf '[%s] SKIP: %s\n' "$CASE_NAME" "$*" >&2; exit 0; }

# run_capture <cmd...> -> sets RUN_OUT (stdout+stderr merged) and RUN_RC.
run_capture() {
  RUN_RC=0
  RUN_OUT="$("$@" 2>&1)" || RUN_RC=$?
}

assert_rc0() {           # assert_rc0 <cmd...>
  local rc=0 out
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then pass "rc=0 :: $*"; else
    fail "expected rc=0 got rc=$rc :: $* :: out=[$out]"; fi
}

expect_rc() {            # expect_rc <want_rc> <cmd...>
  local want="$1"; shift
  local rc=0 out
  out="$("$@" 2>&1)" || rc=$?
  if [ "$rc" -eq "$want" ]; then pass "rc=$rc :: $*"; else
    fail "expected rc=$want got rc=$rc :: $* :: out=[$out]"; fi
}

assert_contains() {      # assert_contains <haystack> <needle> <label>
  case "$1" in
    *"$2"*) pass "contains '$2' ($3)" ;;
    *) fail "$3: expected to contain '$2' in [$1]" ;;
  esac
}
assert_not_contains() {
  case "$1" in
    *"$2"*) fail "$3: expected NOT to contain '$2' in [$1]" ;;
    *) pass "does not contain '$2' ($3)" ;;
  esac
}
assert_eq() {            # assert_eq <actual> <expected> <label>
  if [ "$1" = "$2" ]; then pass "eq '$1' ($3)"; else
    fail "$3: expected [$2] got [$1]"; fi
}
assert_ne() {
  if [ "$1" != "$2" ]; then pass "ne ($3)"; else
    fail "$3: expected != [$2]"; fi
}

# ---------------------------------------------------------------------------
# RSS monitor: sample a target pid's RSS to a file until a stop flag appears.
# Used by the backpressure / slow-link / rekey cases to assert bounded memory.
# ---------------------------------------------------------------------------
RSS_MON_PID=""
rss_monitor_start() {   # rss_monitor_start <pid> <samplefile> <stopflag>
  local pid="$1" sf="$2" stop="$3"
  rm -f "$sf" "$stop"
  ( while [ ! -f "$stop" ]; do
      printf '%s %s\n' "$(date +%s)" "$(rss_kb "$pid")" >>"$sf" 2>/dev/null || true
      sleep 0.5
    done ) &
  RSS_MON_PID=$!
}
rss_monitor_stop() {    # rss_monitor_stop <stopflag>
  touch "$1"
  [ -n "$RSS_MON_PID" ] && wait "$RSS_MON_PID" 2>/dev/null || true
  RSS_MON_PID=""
}
rss_stats() {           # rss_stats <samplefile> -> prints "max min count"
  awk 'NF>=2{v=$2+0; if(n==0||v>mx)mx=v; if(n==0||v<mn)mn=v; n++} END{print mx+0, mn+0, n+0}' "$1" 2>/dev/null || echo "0 0 0"
}

# assert_ordered <label> <file> <s1> <s2> ... : strings appear in order (by line).
assert_ordered() {
  local label="$1" file="$2"; shift 2
  local prev=0 n found pat line
  for pat in "$@"; do
    found=0; n=0
    while IFS= read -r line; do
      n=$((n+1))
      if [ "$n" -le "$prev" ]; then continue; fi
      case "$line" in *"$pat"*) found="$n"; break ;; esac
    done < "$file"
    if [ "$found" -eq 0 ]; then fail "$label: '$pat' not found in order"; fi
    prev="$found"
  done
  pass "$label ordered: $*"
}

# strip CR (pty output carries CRLF) from a var
decr() { printf '%s' "$1" | tr -d '\r'; }

# gw_metric_value <metric-name> -> the integer value of a counter on the *main*
# gateway that run_integration.sh starts. Sub-topology gateways are queried by
# `subtopo_metric` instead. Prints nothing (and fails) when unavailable.
gw_metric_value() {
  curl -fsS --max-time 5 "http://${GW_ADDR:-127.0.0.1}:${GW_METRICS_PORT:-}/metrics" \
    2>/dev/null | awk -v m="$1" '$1==m {print $2; exit}'
}
