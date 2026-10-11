#!/usr/bin/env bash
# case_control_plane_failopen.sh — control-plane failover (plan M2-U2/U5). Proves
# BOTH policies by running a self-contained gateway (subtopo.sh) twice:
#
#   A) fail_open=true : one good resolve fills last-known-good + positive cache,
#      then the mock control plane is killed and the positive TTL is allowed to
#      lapse. A new session's control-plane fetch fails (Transport/Transient) and
#      the resolver FAILS OPEN by serving last-known-good -> session proceeds.
#   B) fail_open=false: identical setup, but the resolver FAILS CLOSED ->
#      the new session is refused.
#
# Short positive TTL (1s, 0 jitter) is used so the cached entry lapses before the
# second session, forcing a real control-plane round-trip (otherwise the positive
# cache would serve it regardless of policy). The control plane is a controllable
# local mock that we kill by pid. Never touches the shared topology or
# SSH_GW_ASSET_DIR; runs in LOCAL and REMOTE modes alike.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"

trap subtopo_stop EXIT INT TERM

run_mode() {   # run_mode <true|false>
  local fo="$1" r1=0 r2=0 out2=""
  subtopo_stop
  SUBTOP_FAIL_OPEN="$fo"; SUBTOP_CACHE_TTL="1s"; SUBTOP_TTL_JITTER="0s"
  subtopo_start
  log "control-plane failover: fail_open=$fo (cache_ttl=1s)"

  # S1: control plane up -> grant cached AND last-known-good populated.
  subtopo_ssh 'true' </dev/null >/dev/null 2>"$IT_WORK_DIR/cpf.s1.err" || r1=$?
  assert_eq "$r1" "0" "fail_open=$fo: initial session (CP up) rc"

  # Kill the control plane, let the positive cache lapse, then reconnect.
  log "fail_open=$fo: killing mock control plane (pid $ST_CP_PID)"
  subtopo_kill_cp
  sleep 2.0

  out2="$(subtopo_ssh 'echo REACHED_BACKEND' </dev/null 2>&1)" || r2=$?
  if [ "$fo" = "true" ]; then
    if [ "$r2" = "0" ]; then
      pass "fail_open=true: session served from last-known-good after CP death (rc=0)"
    else
      tail_log "$SUBTOPO_DIR/gw.log" 40
      fail "fail_open=true: expected session to proceed on CP death, got rc=$r2 out=[$out2]"
    fi
    assert_contains "$out2" "REACHED_BACKEND" "fail_open=true exec reached backend"
  else
    if [ "$r2" -ne 0 ]; then
      pass "fail_open=false: session refused after CP death (rc=$r2)"
    else
      fail "fail_open=false: expected refusal on CP death, but session succeeded out=[$out2]"
    fi
    assert_not_contains "$out2" "REACHED_BACKEND" "fail_open=false did not run the command"
  fi
}

# Positive demonstration, then negative. Each run is an independent sub-topology.
run_mode true
run_mode false
echo "OK: case_control_plane_failopen"
