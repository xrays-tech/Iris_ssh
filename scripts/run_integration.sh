#!/usr/bin/env bash
# scripts/run_integration.sh — orchestrate the ssh-gateway black-box suite.
#
# Topology (all on localhost, random high ports — CI-safe, no external deps):
#
#     client (this suite)
#        |  ssh  user@GW_ADDR:GW_PORT   (principal = username)
#        v
#     ssh-gw  (--config GW_CONFIG)      authenticates + resolves + relays
#        |  russh client leg, backend_ed25519 key
#        v
#     backend sshd  (127.0.0.1:SSHD_PORT)   authorized_keys := backend pubkey
#     mock control plane (127.0.0.1:CP_PORT)  POST /api/v1/resolve
#
# Modes:
#   run_integration.sh                  # full suite, all cases in order
#   run_integration.sh <case> [<case>]  # bootstrap env then run only those cases
#   run_integration.sh --selftest       # infra health only (no gateway needed)
#
# Flags:
#   --skip-backpressure   skip case_backpressure even in local mode.
#
# Env knobs:
#   SSH_GW_BIN            path to gateway binary (default target/debug/ssh-gw)
#   SSH_GW_BACKEND_TARGET "user@host:port" -> switch to a REMOTE backend for
#                         manual real-machine validation. When unset, a local
#                         sshd is started (the default, CI path). In remote mode
#                         case_backpressure is skipped by default (see below).
#   SSH_GW_ASSET_DIR      reuse a FIXED key/asset dir instead of a fresh
#                         per-run $WORK_DIR/assets. Required for REMOTE mode:
#                         pre-install its backend_ed25519.pub in the remote
#                         authorized_keys, or the gateway can't authenticate.
#   SSHGW_SKIP_BACKPRESSURE  non-empty => always skip case_backpressure
#   KEEP_WORK=1           preserve the temp work dir for post-mortem
#   BP_BYTES / BP_MAX_RSS_KB   backpressure case overrides (see that case)
#
# Note: case_graceful_shutdown signals the LOCAL gateway process ($GW_PID) in all
#       modes — the graceful-drain behaviour under test is the gateway's, not the
#       backend's, so remote mode is unaffected.
#
# Remote path semantics (REMOTE_TMP_DIR): cases place files on the BACKEND via
#   the gateway, so the *backend-side* temp path is distinct from the gateway-host
#   work dir. The harness exports REMOTE_TMP_DIR for that:
#     - local mode : REMOTE_TMP_DIR = $WORK_DIR (backend IS localhost, dir exists)
#     - remote mode: a unique /tmp/sshgw-it-<stamp>-<pid> on the backend, created
#       up front via the backend key and rm -rf'd at cleanup (only that path).
#
# Exit code: 1 if any case FAILs; 0 otherwise (BLOCKED cases do not fail, so the
# gate stays green while the src/ lane is still landing).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CASES_DIR="$REPO_ROOT/tests/integration"

# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"
# shellcheck source=scripts/gen_assets.sh
. "$SCRIPT_DIR/gen_assets.sh"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
SELFTEST=0
KEEP_WORK="${KEEP_WORK:-0}"
SKIP_BP_FLAG=0
REQUESTED_CASES=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --selftest) SELFTEST=1 ;;
    --keep)     KEEP_WORK=1 ;;
    --skip-backpressure) SKIP_BP_FLAG=1 ;;
    -h|--help)
      awk 'NR==1{next} /^#/{sub(/^#[ ]?/,""); print; next} {exit}' "$0" >&2
      exit 0 ;;
    *) REQUESTED_CASES+=("$1") ;;
  esac
  shift
done

PRINCIPAL="alex_host1"
DENIED_PRINCIPAL="bob"
NOTFOUND_PRINCIPAL="ghost"
CURRENT_USER="$(id -un)"

# ---------------------------------------------------------------------------
# Work dir + assets + ports
# ---------------------------------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK_DIR="${TMPDIR:-/tmp}/sshgw-it.${STAMP}.$$"
mkdir -p "$WORK_DIR"

# Asset dir: per-run under $WORK_DIR by default. Set SSH_GW_ASSET_DIR to reuse a
# fixed dir — required for remote-backend validation, where the gateway's backend
# pubkey must be pre-installed once in the remote authorized_keys (a fresh key
# each run would never match). gen_assets is idempotent, so an existing dir is
# reused as-is (all downstream references use $ASSET_DIR).
ASSET_DIR="${SSH_GW_ASSET_DIR:-$WORK_DIR/assets}"
mkdir -p "$ASSET_DIR"
log "work dir: $WORK_DIR"
log "asset dir: $ASSET_DIR"

gen_assets "$ASSET_DIR"

SSHD_CONFIG="$WORK_DIR/sshd_config"
SSHD_LOG="$WORK_DIR/sshd.log"
SSHD_PIDFILE="$WORK_DIR/sshd.pid"
CP_RULES="$WORK_DIR/cp_rules.json"
CP_LOG="$WORK_DIR/control_plane.log"
CP_ACCESS_LOG="$WORK_DIR/cp_access.log"
CP_PIDFILE="$WORK_DIR/cp.pid"
GW_CONFIG="$WORK_DIR/gateway.toml"
GW_LOG="$WORK_DIR/gateway.log"
RUN_ENV="$WORK_DIR/run.env"

GW_ADDR="127.0.0.1"
SSHD_ADDR="127.0.0.1"
CP_ADDR="127.0.0.1"

# ---------------------------------------------------------------------------
# Backend target: local sshd (default) vs REMOTE override
# ---------------------------------------------------------------------------
REMOTE_MODE=0
SSHD_UP=0
GW_PORT="$(alloc_port)"
CP_PORT="$(alloc_port)"
# The gateway serves /healthz, /readyz and /metrics on [metrics] addr. Its
# built-in default (127.0.0.1:9090) collides with unrelated host daemons on this
# machine (e.g. ClashX on 9090), so we always allocate a free port and pin it.
METRICS_PORT="$(alloc_port)"
SSHD_PORT=""

if [ -n "${SSH_GW_BACKEND_TARGET:-}" ]; then
  REMOTE_MODE=1
  RT="${SSH_GW_BACKEND_TARGET}"
  BACKEND_USER="${RT%@*}"
  RT_REST="${RT#*@}"
  BACKEND_HOST="${RT_REST%:*}"
  case "$RT_REST" in
    *:*) BACKEND_PORT="${RT_REST##*:}" ;;
    *)   BACKEND_PORT="22" ;;
  esac
  # sanity: user@host:port
  if [ -z "$BACKEND_USER" ] || [ "$BACKEND_USER" = "$RT" ]; then
    die "SSH_GW_BACKEND_TARGET must look like user@host:port (got '$RT')"
  fi
  log "REMOTE backend mode: ${BACKEND_USER}@${BACKEND_HOST}:${BACKEND_PORT} (manual run — not used by CI auto-suite)"
  log "NOTE: ensure the gateway backend pubkey is in the remote authorized_keys:"
  log "      $(cat "$ASSET_DIR/backend_ed25519.pub")"
else
  SSHD_PORT="$(alloc_port)"
  BACKEND_HOST="127.0.0.1"
  BACKEND_USER="$CURRENT_USER"
  BACKEND_PORT="$SSHD_PORT"
fi

# Direct-to-backend ssh options (used only in remote mode: to mkdir/cleanup the
# backend-side temp dir). The backend key is already authorized on the remote
# (the gateway authenticates with it), so the harness can log in the same way —
# mirrors infra_selftest's `-i "$ASSET_DIR/backend_ed25519"` usage.
BACKEND_LOGIN="${BACKEND_USER}@${BACKEND_HOST}"
SSH_BACKEND_OPTS=(
  -p "$BACKEND_PORT"
  -i "$ASSET_DIR/backend_ed25519"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o ConnectTimeout=15
  -o LogLevel=ERROR
)

# Backend-side temp dir (paths cases place *on the backend* through the gateway).
# Local mode: the work dir (backend is localhost, so it already exists). Remote
# mode: a unique /tmp path on the backend, created + verified now and cleaned in
# cleanup(). Distinct from $WORK_DIR, which is gateway-host-local only.
if [ "$REMOTE_MODE" = "1" ]; then
  REMOTE_TMP_DIR="/tmp/sshgw-it-${STAMP}-$$"
  log "remote backend: creating writable tmp dir ${BACKEND_LOGIN}:${REMOTE_TMP_DIR}"
  if ssh "${SSH_BACKEND_OPTS[@]}" "$BACKEND_LOGIN" \
       "mkdir -p '$REMOTE_TMP_DIR' && test -w '$REMOTE_TMP_DIR' && echo ok" \
       >"$WORK_DIR/remote_tmp.out" 2>&1 \
     && grep -q '^ok$' "$WORK_DIR/remote_tmp.out"; then
    log "remote tmp dir ready: ${BACKEND_LOGIN}:${REMOTE_TMP_DIR}"
  else
    tail_log "$WORK_DIR/remote_tmp.out" 20
    die "could not create/write remote tmp dir on ${BACKEND_LOGIN}:${REMOTE_TMP_DIR} (is backend_ed25519.pub in the remote authorized_keys?)"
  fi
else
  REMOTE_TMP_DIR="$WORK_DIR"
fi

# ---------------------------------------------------------------------------
# Write configs
# ---------------------------------------------------------------------------
write_sshd_config() {
  cat > "$SSHD_CONFIG" <<EOF
# generated sshd config for the ssh-gw backend test server (local mode)
Port ${SSHD_PORT}
ListenAddress ${SSHD_ADDR}
HostKey ${ASSET_DIR}/sshd_host_ed25519
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile ${ASSET_DIR}/authorized_keys
StrictModes no
UsePAM no
PermitRootLogin yes
MaxSessions 10
MaxAuthTries 6
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PidFile ${SSHD_PIDFILE}
LogLevel DEBUG2
Subsystem sftp /usr/libexec/sftp-server
EOF
}

write_gateway_config() {
  cat > "$GW_CONFIG" <<EOF
# generated ssh-gw config (schema per propose.md §5.2)
[listen]
addr = "${GW_ADDR}:${GW_PORT}"

[host_keys]
keys = [
  { path = "${ASSET_DIR}/hostkey_ed25519", state = "active" },
]

[relay]
window_size = "1MB"
max_packet = "32KB"
outbound_guard = true

[backend]
private_key = "${ASSET_DIR}/backend_ed25519"
host_key_policy = "accept-new"

[pool]
enabled = false
# keepalive_interval/max_miss drive the backend-leg half-open detection (
# ~interval*(max+1)). Honored here so A1 (case_halfopen_lost) can speed the
# gateway's detection via HALFOPEN_KEEPALIVE_INTERVAL=5s; defaults 15s/2.
keepalive_interval = "${HALFOPEN_KEEPALIVE_INTERVAL:-15s}"
keepalive_max_miss = ${HALFOPEN_KEEPALIVE_MAX_MISS:-2}

[control_plane]
# The gateway POSTs this URL verbatim (no path is appended — src/resolve/mod.rs
# calls client.post(&self.url)), so it must be the full /api/v1/resolve endpoint.
url = "http://${CP_ADDR}:${CP_PORT}/api/v1/resolve"
cache_ttl = "30s"
timeout = "2s"

[limits]
max_sessions = 10000
max_sessions_per_ip = 20
# src decouples auth_timeout (the auth-phase budget) from the russh rejection
# delay via auth_rejection_pad (default 250ms): the initial 'none' probe waits
# min(auth_timeout, auth_rejection_pad), ongoing rejections wait the pad. A 0s
# budget keeps the initial probe instant in tests (the lane's own tests use 0s).
auth_timeout = "0s"

[shutdown]
drain_wait = "2s"
disconnect_flush = "3s"
hard_deadline = "30s"

[metrics]
addr = "${GW_ADDR}:${METRICS_PORT}"

# [ca] is required (validation rejects an empty CA section). These tests never
# use cert auth, so we point trusted_ca_keys at a harmless valid pubkey to make
# the CA section non-empty without enabling anything.
[ca]
trusted_ca_keys = ["${ASSET_DIR}/user_ed25519.pub"]
EOF
}

write_cp_rules() {
  cat > "$CP_RULES" <<EOF
{
  "resolve": {
    "${PRINCIPAL}": {"status":200,"target":{"host":"${BACKEND_HOST}","port":${BACKEND_PORT},"user":"${BACKEND_USER}"},"policy":{"agent_forwarding":false,"tcp_forwarding":false,"recording":false,"ttl":60}},
    "bob": {"status":403,"error":"principal not authorized"},
    "ghost": {"status":404,"error":"principal not found"},
    "slow": {"status":200,"delay_ms":5000,"target":{"host":"${BACKEND_HOST}","port":${BACKEND_PORT},"user":"${BACKEND_USER}"},"policy":{"ttl":60}}
  },
  "default": {"status":404,"error":"principal not found"}
}
EOF
}

write_run_env() {
  cat > "$RUN_ENV" <<EOF
export IT_WORK_DIR='${WORK_DIR}'
export IT_ASSET_DIR='${ASSET_DIR}'
export REMOTE_TMP_DIR='${REMOTE_TMP_DIR}'
export GW_ADDR='${GW_ADDR}'
export GW_PORT='${GW_PORT}'
export GW_METRICS_PORT='${METRICS_PORT}'
export GW_PID='${GW_PID}'
export GATEWAY_UP='${GATEWAY_UP}'
export SSHD_ADDR='${SSHD_ADDR}'
export SSHD_PORT='${SSHD_PORT}'
export SSHD_UP='${SSHD_UP}'
export CP_ADDR='${CP_ADDR}'
export CP_PORT='${CP_PORT}'
export CP_URL='http://${CP_ADDR}:${CP_PORT}'
export USER_KEY='${ASSET_DIR}/user_ed25519'
export PRINCIPAL='${PRINCIPAL}'
export DENIED_PRINCIPAL='${DENIED_PRINCIPAL}'
export NOTFOUND_PRINCIPAL='${NOTFOUND_PRINCIPAL}'
export BACKEND_HOST='${BACKEND_HOST}'
export BACKEND_PORT='${BACKEND_PORT}'
export BACKEND_USER='${BACKEND_USER}'
EOF
}

write_cp_rules
write_gateway_config

# ---------------------------------------------------------------------------
# Cleanup (registered last-ish; runs on EXIT/INT/TERM)
# ---------------------------------------------------------------------------
GW_PID=""
GATEWAY_UP=0
CP_PID=""
SSHD_PID=""

cleanup() {
  trap - EXIT INT TERM
  # gateway first so backend channels close and sshd sessions drain naturally
  [ "$GATEWAY_UP" = "1" ] && stop_pid "$GW_PID"
  stop_pid "$CP_PID"
  [ "$SSHD_UP" = "1" ] && stop_pid "$SSHD_PID"
  if [ "$KEEP_WORK" = "1" ]; then
    log "KEEP_WORK=1 -> preserving work dir: $WORK_DIR"
  else
    # Remote mode: remove the backend-side temp dir we created. Safety-guarded so
    # only our unique prefix is ever removed (a stray var can't rm the wrong tree).
    if [ "${REMOTE_MODE:-0}" = "1" ] && [ -n "${REMOTE_TMP_DIR:-}" ] \
       && [ "${REMOTE_TMP_DIR#/tmp/sshgw-it-}" != "$REMOTE_TMP_DIR" ]; then
      if ssh "${SSH_BACKEND_OPTS[@]}" "$BACKEND_LOGIN" "rm -rf '$REMOTE_TMP_DIR'" >"$WORK_DIR/remote_tmp.cleanup.log" 2>&1; then
        log "removed remote tmp dir ${BACKEND_LOGIN}:${REMOTE_TMP_DIR}"
      else
        log_err "could not remove remote tmp dir ${BACKEND_LOGIN}:${REMOTE_TMP_DIR} (idempotent — safe to remove manually):"
        tail_log "$WORK_DIR/remote_tmp.cleanup.log" 15
      fi
    fi
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Start backend sshd (local mode only)
# ---------------------------------------------------------------------------
if [ "$REMOTE_MODE" = "0" ]; then
  write_sshd_config
  /usr/sbin/sshd -t -f "$SSHD_CONFIG" 2>>"$SSHD_LOG" \
    || { tail_log "$SSHD_LOG" 20; die "sshd_config validation failed"; }
  /usr/sbin/sshd -D -e -f "$SSHD_CONFIG" >"$SSHD_LOG" 2>&1 &
  SSHD_PID=$!
  if wait_tcp_open "$SSHD_ADDR" "$SSHD_PORT" 20; then
    SSHD_UP=1
    log "backend sshd up on ${SSHD_ADDR}:${SSHD_PORT} (pid $SSHD_PID)"
  else
    tail_log "$SSHD_LOG" 30
    die "backend sshd did not open ${SSHD_ADDR}:${SSHD_PORT}"
  fi
fi

# ---------------------------------------------------------------------------
# Start mock control plane
# ---------------------------------------------------------------------------
python3 "$SCRIPT_DIR/mock_control_plane.py" \
  --port "$CP_PORT" --rules "$CP_RULES" --pidfile "$CP_PIDFILE" \
  --access-log "$CP_ACCESS_LOG" \
  >"$CP_LOG" 2>&1 &
CP_PID=$!
if wait_http_ok "http://${CP_ADDR}:${CP_PORT}/healthz" 20; then
  log "mock control plane up on ${CP_ADDR}:${CP_PORT} (pid $CP_PID)"
else
  tail_log "$CP_LOG" 30
  stop_pid "$CP_PID"
  die "mock control plane did not become healthy"
fi

# ---------------------------------------------------------------------------
# Start gateway (skipped in selftest mode / when binary missing)
# ---------------------------------------------------------------------------
# Resolve default gateway binary, honouring a global CARGO_TARGET_DIR so the
# harness finds the binary where this environment's cargo actually put it.
DEFAULT_BIN="$REPO_ROOT/target/debug/ssh-gw"
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  DEFAULT_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
fi
GW_BIN="${SSH_GW_BIN:-$DEFAULT_BIN}"
if [ "$SELFTEST" = "0" ]; then
  if [ ! -x "$GW_BIN" ]; then
    # Only auto-build for the default binary path and when the operator did not
    # explicitly pin SSH_GW_BIN (an explicit pin to a missing binary is honored
    # as-is -> cases report BLOCKED rather than triggering a slow rebuild).
    if [ -z "${SSH_GW_BIN:-}" ] && [ -f "$REPO_ROOT/Cargo.toml" ]; then
      log "gateway binary missing -> attempting 'cargo build'"
      if (cd "$REPO_ROOT" && cargo build --bin ssh-gw >"$WORK_DIR/build.log" 2>&1); then
        log "cargo build ok"
      else
        tail_log "$WORK_DIR/build.log" 30
      fi
    fi
  fi
  if [ -x "$GW_BIN" ]; then
    "$GW_BIN" --config "$GW_CONFIG" >"$GW_LOG" 2>&1 &
    GW_PID=$!
    sleep 0.3
    # Readiness = SSH listener open AND the observability /healthz answering.
    # The healthz probe doubles as an early tripwire for a metrics bind failure.
    if pid_alive "$GW_PID" \
       && wait_tcp_open "$GW_ADDR" "$GW_PORT" 20 \
       && wait_http_ok "http://${GW_ADDR}:${METRICS_PORT}/healthz" 20; then
      GATEWAY_UP=1
      log "gateway up on ${GW_ADDR}:${GW_PORT} (healthz :${METRICS_PORT}, pid $GW_PID)"
    else
      tail_log "$GW_LOG" 40
      log_err "gateway exited at startup or did not listen — gateway cases BLOCKED"
    fi
  else
    log_err "gateway binary not found ($GW_BIN) — gateway cases BLOCKED"
    log_err "  (src/ lane pending? run 'make build' first; infra selftest still valid)"
  fi
fi

write_run_env
# Export the case-visible contract. IT_WORK_DIR/IT_ASSET_DIR are the names cases
# consume; the orchestrator holds them as WORK_DIR/ASSET_DIR, so map explicitly
# (`export IT_WORK_DIR` alone would export an unset name).
export IT_WORK_DIR="$WORK_DIR"
export IT_ASSET_DIR="$ASSET_DIR"
export REMOTE_TMP_DIR="$REMOTE_TMP_DIR"
# GW_METRICS_PORT is held as METRICS_PORT internally, so map it explicitly (a
# bare `export GW_METRICS_PORT` would export an unset name -> unbound in cases).
export GW_ADDR GW_PORT GW_METRICS_PORT="$METRICS_PORT" GW_PID GATEWAY_UP
export SSHD_ADDR SSHD_PORT SSHD_UP CP_ADDR CP_PORT
export USER_KEY="$ASSET_DIR/user_ed25519" PRINCIPAL DENIED_PRINCIPAL NOTFOUND_PRINCIPAL
export BACKEND_HOST BACKEND_PORT BACKEND_USER

log "topology: principal=${PRINCIPAL} backend=${BACKEND_USER}@${BACKEND_HOST}:${BACKEND_PORT}"

# ---------------------------------------------------------------------------
# Case set
# ---------------------------------------------------------------------------
ALL_CASES=(
  case_ssh_true
  case_exit_status
  case_exec_no_pty
  case_pty_shell
  case_ordering_matrix
  case_stderr
  case_sftp
  case_scp
  case_auth_denied_403
  case_port_forward_denied
  case_backpressure
  case_backpressure_down
  case_slow_link
  case_rekey_midstream
  case_backend_lost
  case_control_plane_failopen
  case_wire_ordering
  case_client_matrix
  case_jump
  case_sftp_intercept
  case_hostkey_rotation
  case_host_cert_authority
  case_cert_dial
  case_halfopen_lost
  case_netem_slow
  case_graceful_shutdown
  case_agent_auth
  case_agent_missing
  case_agent_no_key
  case_agent_target_scope
  case_agent_env
)

resolve_case_path() {
  local arg="$1"
  if [ -f "$arg" ]; then echo "$arg"; return 0; fi
  if [ -f "$CASES_DIR/${arg%.sh}.sh" ]; then echo "$CASES_DIR/${arg%.sh}.sh"; return 0; fi
  if [ -f "$CASES_DIR/case_${arg}.sh" ]; then echo "$CASES_DIR/case_${arg}.sh"; return 0; fi
  return 1
}

# case_backpressure pushes 200MB: fine locally, wasteful/slow over the public
# internet. Local mode runs it by default; REMOTE mode skips it by default.
# Forces: --skip-backpressure / SSHGW_SKIP_BACKPRESSURE skip it (any mode);
# an explicit BP_BYTES opts back in. This filter only drops it from the *default*
# all-cases list — naming `case_backpressure` explicitly always runs it.
SKIP_BACKPRESSURE=0
if [ "$SKIP_BP_FLAG" = "1" ] || [ -n "${SSHGW_SKIP_BACKPRESSURE:-}" ]; then
  SKIP_BACKPRESSURE=1
elif [ "$REMOTE_MODE" = "1" ] && [ -z "${BP_BYTES:-}" ]; then
  SKIP_BACKPRESSURE=1
fi

if [ "$SELFTEST" = "1" ]; then
  CASE_LIST=()
else
  CASE_LIST=()
  if [ "${#REQUESTED_CASES[@]}" -gt 0 ]; then
    for c in "${REQUESTED_CASES[@]}"; do
      if p="$(resolve_case_path "$c")"; then CASE_LIST+=("$p"); else die "unknown case: $c"; fi
    done
  else
    for name in "${ALL_CASES[@]}"; do
      if [ "$name" = "case_backpressure" ] && [ "$SKIP_BACKPRESSURE" = "1" ]; then
        log "skipping case_backpressure (remote/no-bandwidth mode; set BP_BYTES or --skip-backpressure controls)"
        continue
      fi
      CASE_LIST+=("$CASES_DIR/$name.sh")
    done
  fi
fi

# ---------------------------------------------------------------------------
# Infra selftest (runs whenever --selftest, and always as a prelude)
# ---------------------------------------------------------------------------
PASS_COUNT=0 FAIL_COUNT=0 BLOCKED_COUNT=0 SKIP_COUNT=0
FAILED_NAMES=""

bump() { # bump <PASS|FAIL|BLOCKED|SKIP> <name>
  case "$1" in
    PASS)    PASS_COUNT=$((PASS_COUNT+1)); log "RESULT PASS    :: $2" ;;
    FAIL)    FAIL_COUNT=$((FAIL_COUNT+1)); FAILED_NAMES="$FAILED_NAMES $2"; log_err "RESULT FAIL    :: $2" ;;
    BLOCKED) BLOCKED_COUNT=$((BLOCKED_COUNT+1)); log "RESULT BLOCKED :: $2" ;;
    SKIP)    SKIP_COUNT=$((SKIP_COUNT+1)); log "RESULT SKIP    :: $2 (capability-gated; not a pass)" ;;
  esac
}

infra_selftest() {
  log "selftest: control plane resolve for ${PRINCIPAL} ..."
  if ! python3 - "$CP_ADDR" "$CP_PORT" "$PRINCIPAL" "$BACKEND_HOST" "$BACKEND_PORT" "$BACKEND_USER" <<'PY'
import json, sys, urllib.request
host, port, principal, bhost, bport, buser = sys.argv[1:7]
url = "http://%s:%s/api/v1/resolve" % (host, port)
p = int(bport)
body = json.dumps({"principal": principal, "client_ip": "127.0.0.1",
                   "key_fp": "SHA256:selftest"}).encode()
req = urllib.request.Request(url, data=body,
                             headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=5) as r:
    assert r.status == 200, "status=%s" % r.status
    obj = json.load(r)
tgt = obj.get("target", {})
assert tgt.get("port") == p, "target.port=%r want=%r" % (tgt.get("port"), p)
assert tgt.get("host") == bhost, "target.host=%r" % tgt.get("host")
assert tgt.get("user") == buser, "target.user=%r" % tgt.get("user")
print("resolve-ok")
PY
  then
    log_err "control-plane resolve check failed"
    return 1
  fi

  if [ "$SSHD_UP" = "1" ]; then
    log "selftest: backend sshd pubkey auth as ${BACKEND_USER} ..."
    local out rc=0
    out="$(ssh -p "$SSHD_PORT" -i "$ASSET_DIR/backend_ed25519" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
      "${BACKEND_USER}@${SSHD_ADDR}" 'printf "who=%s" "$(id -un)"; test -x /usr/libexec/sftp-server && echo -n " sftp=yes"' 2>&1)" || rc=$?
    if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q "who=${BACKEND_USER}" && printf '%s' "$out" | grep -q "sftp=yes"; then
      log "sshd selftest: $out"
    else
      log "sshd selftest output: $out (rc=$rc)"
      return 1
    fi
  fi
  return 0
}

if [ "$SELFTEST" = "1" ]; then
  log "=== infra selftest (no gateway) ==="
  if infra_selftest; then
    log "SELFTEST PASS (backend sshd + control plane healthy)"
    exit 0
  else
    log_err "SELFTEST FAIL"
    exit 1
  fi
fi

# As a prelude to the full run, confirm the infra is sound before cases.
log "=== infra prelude ==="
if infra_selftest; then
  bump PASS infra-prelude
else
  log_err "infra prelude failed; dumping logs"
  tail_log "$CP_LOG" 30; tail_log "$SSHD_LOG" 30; tail_log "$GW_LOG" 40
  bump FAIL infra-prelude
fi

# ---------------------------------------------------------------------------
# Run cases
# ---------------------------------------------------------------------------
if [ "${#CASE_LIST[@]}" -gt 0 ]; then
  for case_path in "${CASE_LIST[@]}"; do
    name="$(basename "$case_path" .sh)"
    outfile="$WORK_DIR/out.${name}.txt"
    if [ ! -f "$case_path" ]; then
      bump FAIL "$name (missing script)"; continue
    fi
    if [ "$GATEWAY_UP" != "1" ]; then
      bump BLOCKED "$name"
      continue
    fi
    log "--- running case: $name ---"
    rc=0
    bash "$case_path" >"$outfile" 2>&1 || rc=$?
    if grep -q '^SKIP_CASE:' "$outfile"; then
      # capability-gated skip (case printed the SKIP_CASE: marker) — not a pass.
      bump SKIP "$name"
    elif [ "$rc" -eq 0 ]; then
      bump PASS "$name"
    else
      bump FAIL "$name"
      log_err "output tail for $name:"
      tail_log "$outfile" 30
      tail_log "$GW_LOG" 40
    fi
  done
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "================ run summary ================"
log "work dir : $WORK_DIR"
log "pass=$PASS_COUNT fail=$FAIL_COUNT blocked=$BLOCKED_COUNT skip=$SKIP_COUNT"
[ -n "$FAILED_NAMES" ] && log "failed  :$FAILED_NAMES"
if [ "$SKIP_COUNT" -gt 0 ]; then
  log "NOTE: $SKIP_COUNT case(s) SKIPPED (capability-gated: real-machine / not-yet-landed feature)."
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  log "NOTE: $BLOCKED_COUNT case(s) BLOCKED — gateway unavailable (src/ lane pending)."
fi
log "============================================="

[ "$FAIL_COUNT" -eq 0 ]
