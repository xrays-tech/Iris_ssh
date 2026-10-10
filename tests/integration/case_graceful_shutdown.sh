#!/usr/bin/env bash
# case_graceful_shutdown.sh — graceful drain (propose §5.4 / plan M1-T9).
# Open a long-lived session, send SIGTERM to the gateway, and assert the active
# client receives a *clean* protocol-level goodbye (SSH_MSG_DISCONNECT wording
# like "Gateway is shutting down"), NOT a "broken pipe"/"connection reset".
#
# NOTE: this case terminates the shared gateway, so the orchestrator runs it
# LAST. Run standalone it bootstraps its own gateway via run_integration.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

: "${GW_PID:?GW_PID not set; graceful-shutdown case requires a live gateway}"

sess_out="$IT_WORK_DIR/shutdown_session.out"
sess_err="$IT_WORK_DIR/shutdown_session.err"

# Long-running remote command under a normal (no pty) exec; it prints READY then
# sleeps so the session is active when we signal the gateway.
ssh "${SSH_OPTS[@]}" "$TARGET" 'echo READY; sleep 60' \
  >"$sess_out" 2>"$sess_err" &
sess_pid=$!

ready=0
for _ in $(seq 1 50); do
  if grep -q READY "$sess_out" 2>/dev/null; then ready=1; break; fi
  kill -0 "$sess_pid" 2>/dev/null || break
  sleep 0.2
done
if [ "$ready" != "1" ]; then
  kill "$sess_pid" 2>/dev/null || true; wait "$sess_pid" 2>/dev/null || true
  tail_log "$sess_err" 20
  fail "session never reached READY before SIGTERM window"
fi
pass "long-lived session established (pid $sess_pid)"

# ---- signal graceful shutdown ----
if ! pid_alive "$GW_PID"; then fail "gateway not alive before SIGTERM"; fi
kill -TERM "$GW_PID"
pass "sent SIGTERM to gateway (pid $GW_PID)"

# ---- wait for the client to exit cleanly (drain_wait + flush grace) ----
exited=0
for _ in $(seq 1 120); do           # up to ~24s (drain_wait 2s + flush 3s + slack)
  kill -0 "$sess_pid" 2>/dev/null || { exited=1; break; }
  sleep 0.2
done
sess_rc=0
if [ "$exited" = "1" ]; then
  wait "$sess_pid" 2>/dev/null || sess_rc=$?
  pass "active client exited after SIGTERM (rc=$sess_rc)"
else
  kill -TERM "$sess_pid" 2>/dev/null || true
  kill -KILL "$sess_pid" 2>/dev/null || true
  wait "$sess_pid" 2>/dev/null || true
  fail "active client did NOT exit after gateway SIGTERM (still running)"
fi

combined="$(cat "$sess_out" 2>/dev/null; cat "$sess_err" 2>/dev/null)"
lower="$(printf '%s' "$combined" | tr 'A-Z' 'a-z' | tr -d '\r')"
log "client combined output around shutdown:"
printf '%s\n' "$lower" >&2

# A clean protocol goodbye must be present.
if printf '%s' "$lower" | grep -Eq 'shutting down|shutdown|draining|drain'; then
  pass "clean goodbye message received"
else
  fail "no clean goodbye message found in client output"
fi
# And it must NOT look like an ungraceful socket teardown.
assert_not_contains "$lower" "broken pipe" "not a broken pipe"
assert_not_contains "$lower" "connection reset" "not a connection reset"
assert_not_contains "$lower" "kex error" "no kex error"

echo "OK: case_graceful_shutdown"
