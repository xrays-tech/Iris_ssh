#!/usr/bin/env bash
# tests/integration/common.sh — sourced by every case script.
#
# Relies on env exported by scripts/run_integration.sh:
#   GW_ADDR GW_PORT USER_KEY PRINCIPAL DENIED_PRINCIPAL NOTFOUND_PRINCIPAL
#   BACKEND_HOST BACKEND_PORT BACKEND_USER IT_WORK_DIR
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
