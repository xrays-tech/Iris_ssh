#!/usr/bin/env bash
# tests/integration/subtopo.sh — a throwaway LOCAL sub-topology (backend sshd +
# mock control plane + gateway) so a case can drive the FULL lifecycle (kill the
# backend, kill the control plane, set fail_open / small window / short TTL)
# without disturbing the shared suite topology that run_integration.sh owns.
#
# Source-only. The caller MUST register cleanup:
#     trap subtopo_stop EXIT INT TERM
# It uses the SHARED asset keys ($IT_ASSET_DIR) and lib.sh helpers; it never
# touches SSH_GW_ASSET_DIR. On teardown it only kills its own per-run procs and
# lsof-scoped backend sessions on its own unique port.
#
# Tunables (set BEFORE subtopo_start; all optional):
#   SUBTOP_FAIL_OPEN   "true"/"false"  -> [control_plane] fail_open  (default false)
#   SUBTOP_CACHE_TTL   duration string -> control_plane.cache_ttl     (default "30s")
#   SUBTOP_TTL_JITTER  duration string -> control_plane.cache_ttl_jitter (default "3s")
#   SUBTOP_WINDOW      byte string     -> relay.window_size           (default "1MB")
#   SUBTOP_RULES       path to a rules JSON. If unset, a default rule resolves
#                      $PRINCIPAL -> (127.0.0.1:<backend>, $BACKEND_USER) with
#                      policy.agent_forwarding=true (see SUBTOP_AGENT_FORWARDING).
#   SUBTOP_AGENT_FORWARDING  "false" -> the default resolve rule stops allowing
#                              agent forwarding for this grant. Default "true":
#                              the gateway reaches the backend ONLY by asking the
#                              client's forwarded agent to sign, so a grant that
#                              refuses it grants no session at all.
#   SUBTOP_SSH_A       "0" -> subtopo_ssh does NOT pass -A (the client never
#                      requests agent forwarding). Default "1".
#   SUBTOP_NO_AGENT    "1" -> subtopo_start does not stand up an ssh-agent when
#                      the environment has none. Default "0".
#
# Manually, sub-unique prefer removing remote grep; probe result vars set by
# subtopo_start: ST_SSHD_PORT ST_CP_PORT ST_GW_PORT ST_MET_PORT ST_GW_PID
# ST_CP_PID ST_SSHD_PID. Helpers: subtopo_metric, subtopo_ssh,
# subtopo_kill_backend, subtopo_kill_cp.
set -uo pipefail

SUBTOPO_DIR="${SUBTOPO_DIR:-}"
ST_SSHD_PORT=""; ST_CP_PORT=""; ST_GW_PORT=""; ST_MET_PORT=""; ST_OS_PORT=""
ST_GW_PID=""; ST_CP_PID=""; ST_SSHD_PID=""; ST_OS_PID=""
SUBTOP_FAIL_OPEN="${SUBTOP_FAIL_OPEN:-false}"
SUBTOP_CACHE_TTL="${SUBTOP_CACHE_TTL:-30s}"
SUBTOP_TTL_JITTER="${SUBTOP_TTL_JITTER:-3s}"
SUBTOP_WINDOW="${SUBTOP_WINDOW:-1MB}"
SUBTOP_KEEPALIVE_INTERVAL="${SUBTOP_KEEPALIVE_INTERVAL:-15s}"
SUBTOP_KEEPALIVE_MAX_MISS="${SUBTOP_KEEPALIVE_MAX_MISS:-2}"
# B3 sftp-intercept drivers (defaults keep every existing case unchanged).
SUBTOP_SFTP_ENABLED="${SUBTOP_SFTP_ENABLED:-false}"
SUBTOP_SFTP_DENY="${SUBTOP_SFTP_DENY:-}"                # space-separated SFTP cmd names
SUBTOP_SFTP_ALLOW_PREFIX="${SUBTOP_SFTP_ALLOW_PREFIX:-}"
SUBTOP_SFTP_DENY_PREFIX="${SUBTOP_SFTP_DENY_PREFIX:-}"
# Overridable host key (for rotation rehearsal); defaults to the shared asset key.
SUBTOP_HOSTKEY="${SUBTOP_HOSTKEY:-$IT_ASSET_DIR/hostkey_ed25519}"
# Backend host-cert topology knobs (all default off -> identical to prior
# behaviour).
#   SUBTOP_SSHD_HOST_CERT  path to a host cert: backend sshd presents it (HostCertificate).
#   SUBTOP_TRUSTED_CA_KEYS space-separated CA .pub: gateway [ca] trusted_ca_keys
#                          (host @cert-authority). [ca] is verify-only: the
#                          gateway issues nothing (plan-agent-only D3).
#   SUBTOP_ENV_ALLOWLIST   space-separated names -> [relay] env_allowlist, i.e.
#                          the gateway filters `env` requests (M1). Empty means
#                          forward every variable.
SUBTOP_SSHD_HOST_CERT="${SUBTOP_SSHD_HOST_CERT:-}"
# Authorized-keys override (for cert-only backends where the gateway key must NOT
# be accepted, so only trusted-CA cert auth works). Default = shared asset file.
SUBTOP_SSHD_AUTHORIZED_KEYS="${SUBTOP_SSHD_AUTHORIZED_KEYS:-$IT_ASSET_DIR/authorized_keys}"
# Backend host key override (needed when the cert must sit beside the key: sshd
# requires <hostkey>-cert.pub). Default = shared asset key.
SUBTOP_SSHD_HOSTKEY="${SUBTOP_SSHD_HOSTKEY:-$IT_ASSET_DIR/sshd_host_ed25519}"
SUBTOP_TRUSTED_CA_KEYS="${SUBTOP_TRUSTED_CA_KEYS:-}"
# Agent forwarding is the only way this gateway can reach the backend, so the
# default grant allows it; a case can still turn it off to test the deny.
SUBTOP_AGENT_FORWARDING="${SUBTOP_AGENT_FORWARDING:-true}"
SUBTOP_ENV_ALLOWLIST="${SUBTOP_ENV_ALLOWLIST:-}"
# -A by default (see subtopo_ssh); SUBTOP_SSH_A=0 opts one call out.
SUBTOP_SSH_A="${SUBTOP_SSH_A:-1}"
# Whether subtopo_start is allowed to stand up an agent for this shell.
SUBTOP_NO_AGENT="${SUBTOP_NO_AGENT:-0}"

# --- OpenStack topology (plan-openstack §4.2) ------------------------------
# SUBTOP_OPENSTACK          non-empty => render a [openstack] section AND start
#                           scripts/mock_openstack.py (the gateway then routes
#                           instance UUIDs to it). Empty keeps today's topology
#                           byte-for-byte, which is what "default off" means.
# SUBTOP_OPENSTACK_RULES    path to an instances rules JSON (static: every test
#                           instance lives on 127.0.0.1 and the SSH port comes
#                           from [openstack] ssh_port). Empty => a default
#                           single-instance file built from the knobs below.
# SUBTOP_OPENSTACK_PURE     "1" (default) => omit [control_plane] entirely, so
#                           every OpenStack case also proves the gateway boots
#                           with no control plane at all (MUST2). "0" keeps both.
SUBTOP_OPENSTACK="${SUBTOP_OPENSTACK:-}"
SUBTOP_OPENSTACK_RULES="${SUBTOP_OPENSTACK_RULES:-}"
SUBTOP_OPENSTACK_PURE="${SUBTOP_OPENSTACK_PURE:-1}"
SUBTOP_OPENSTACK_UUID="${SUBTOP_OPENSTACK_UUID:-550e8400-e29b-41d4-a716-446655440000}"
SUBTOP_OS_METADATA_KEY="${SUBTOP_OS_METADATA_KEY:-iris_ssh_user}"
SUBTOP_OS_METADATA_USER="${SUBTOP_OS_METADATA_USER:-${BACKEND_USER:-alex}}"
SUBTOP_OS_DEFAULT_USER="${SUBTOP_OS_DEFAULT_USER:-${BACKEND_USER:-alex}}"
SUBTOP_OS_ON_AMBIGUOUS="${SUBTOP_OS_ON_AMBIGUOUS:-reject}"
# `[openstack] route_by` — space-separated route kinds. Unset (or "uuid") is
# the default pre-name-routing world; "uuid name" opts a case into the
# instance-name route (plan-openstack appendix A).
SUBTOP_OS_ROUTE_BY="${SUBTOP_OS_ROUTE_BY:-}"
# `[openstack]` carries its own cache/timeout knobs, independent of
# [control_plane]; `fail_open` stays false (red line 5: serving a stale address
# requires an explicit opt-in AND a pinned host-key policy).
SUBTOP_OS_CACHE_TTL="${SUBTOP_OS_CACHE_TTL:-30s}"
SUBTOP_OS_TIMEOUT="${SUBTOP_OS_TIMEOUT:-3s}"
SUBTOP_OS_FAIL_OPEN="${SUBTOP_OS_FAIL_OPEN:-false}"
# Extra `[openstack]` lines a case may need (e.g. network = "private").
SUBTOP_OS_EXTRA="${SUBTOP_OS_EXTRA:-}"
# `[openstack] scope` — empty = single_project (default, all existing cases);
# "cross_project" renders scope + auth_method="password" so the gateway asks
# Nova with `all_tenants=1` (plan-openstack appendix C). The mock never checks
# the password, so a placeholder value is fine.
SUBTOP_OS_SCOPE="${SUBTOP_OS_SCOPE:-}"

# toml_arr "a b c" -> ["a","b","c"]  (empty -> [])
toml_arr() {
  local out='[' first=1 v
  for v in $1; do
    if [ "$first" = 1 ]; then first=0; else out="$out, "; fi
    out="$out\"$v\""
  done
  printf '%s]' "$out"
}

# Resolve the gateway binary the same way run_integration.sh does.
SUBTOPO_CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
SUBTOPO_GW_BIN="${SSH_GW_BIN:-}"
if [ -z "$SUBTOPO_GW_BIN" ]; then
  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    SUBTOPO_GW_BIN="${CARGO_TARGET_DIR%/}/debug/ssh-gw"
  else
    SUBTOPO_GW_BIN="$SUBTOPO_CASE_DIR/../../target/debug/ssh-gw"
  fi
fi

subtopo_start() {
  SUBTOPO_DIR="$IT_WORK_DIR/subtopo"
  mkdir -p "$SUBTOPO_DIR"

  # The gateway holds no backend credential (plan-agent-only D3): without a live
  # agent holding the end user's key, no session in this topology could ever
  # reach the backend. Stand one up when the environment did not give us one.
  if [ "$SUBTOP_NO_AGENT" != "1" ] && [ -z "${SSH_AUTH_SOCK:-}" ]; then
    subtopo_agent_start "$IT_ASSET_DIR/user_ed25519" || return 1
  fi

  ST_SSHD_PORT="$(alloc_port)"; ST_CP_PORT="$(alloc_port)"
  ST_GW_PORT="$(alloc_port)";   ST_MET_PORT="$(alloc_port)"
  ST_OS_PORT=""
  [ -n "$SUBTOP_OPENSTACK" ] && ST_OS_PORT="$(alloc_port)"

  # The agent-env case needs the backend to actually *accept* the variable the
  # gateway forwards; without an AcceptEnv line sshd drops it and the case would
  # be testing OpenSSH rather than the gateway. LANG/LC_* restated because sshd
  # only applies its built-in default while no AcceptEnv directive is present.
  # The second ListenAddress (127.0.0.2, still this host's loopback) lets the
  # appendix-D floating-only case publish a *distinct* floating address that is
  # genuinely dialable — so it can prove which address was selected instead of
  # relying on a companion refusal case. Every other case keeps dialing
  # 127.0.0.1.
  printf 'Port %s\nListenAddress 127.0.0.1\nListenAddress 127.0.0.2\nHostKey %s\nPasswordAuthentication no\nPubkeyAuthentication yes\nAuthorizedKeysFile %s\nStrictModes no\nUsePAM no\nMaxSessions 10\nAcceptEnv LANG LC_* SSHGW_AGENT_ENV\nPidFile %s/sshd.pid\nSubsystem sftp /usr/libexec/sftp-server\n' \
    "$ST_SSHD_PORT" "$SUBTOP_SSHD_HOSTKEY" "$SUBTOP_SSHD_AUTHORIZED_KEYS" "$SUBTOPO_DIR" \
    > "$SUBTOPO_DIR/sshd.cfg"
  # Backend presents a host certificate (M4-1).
  [ -n "$SUBTOP_SSHD_HOST_CERT" ] && printf 'HostCertificate %s\n' "$SUBTOP_SSHD_HOST_CERT" >> "$SUBTOPO_DIR/sshd.cfg"

  if [ -n "${SUBTOP_RULES:-}" ]; then
    cp "$SUBTOP_RULES" "$SUBTOPO_DIR/rules.json"
  else
    local _pol_extra=""
    if [ "$SUBTOP_AGENT_FORWARDING" = "true" ]; then
      _pol_extra="$_pol_extra,\"agent_forwarding\":true"
    fi
    printf '{"resolve":{"%s":{"status":200,"target":{"host":"127.0.0.1","port":%s,"user":"%s"},"policy":{"ttl":60%s}}},"default":{"status":404}}\n' \
      "$PRINCIPAL" "$ST_SSHD_PORT" "$BACKEND_USER" "$_pol_extra" > "$SUBTOPO_DIR/rules.json"
  fi

  local _env_al=""
  [ -n "$SUBTOP_ENV_ALLOWLIST" ] && _env_al="env_allowlist=$(toml_arr "$SUBTOP_ENV_ALLOWLIST")"

  # Instance table for the mock Nova. Static on purpose: the SSH port lives in
  # [openstack] ssh_port, never in the instance document, so a case can hand us
  # a rules file it wrote before the topology existed.
  if [ -n "$SUBTOP_OPENSTACK" ]; then
    if [ -n "$SUBTOP_OPENSTACK_RULES" ]; then
      cp "$SUBTOP_OPENSTACK_RULES" "$SUBTOPO_DIR/os_rules.json" || return 1
    else
      printf '{"servers":{"%s":{"addresses":{"private":[{"addr":"127.0.0.1","version":4,"OS-EXT-IPS:type":"fixed"}]},"metadata":{"%s":"%s"},"name":"inst-1","image":{"id":"img-1"}}},"default":{"status":404}}\n' \
        "$SUBTOP_OPENSTACK_UUID" "$SUBTOP_OS_METADATA_KEY" "$SUBTOP_OS_METADATA_USER" \
        > "$SUBTOPO_DIR/os_rules.json"
    fi
  fi

  # No [backend] credential: the gateway signs for the backend leg with the
  # client's forwarded agent (plan-agent-only D3), so [backend] carries only the
  # host-key policy.
  # [control_plane] disappears in OpenStack pure mode: the gateway has to boot
  # with no control plane at all there, and every OpenStack case re-proves it.
  local _cp_toml=""
  if [ -z "$SUBTOP_OPENSTACK" ] || [ "$SUBTOP_OPENSTACK_PURE" = "0" ]; then
    _cp_toml="$(printf '[control_plane]\nurl="http://127.0.0.1:%s/api/v1/resolve"\ncache_ttl="%s"\ntimeout="2s"\nfail_open=%s\ncache_ttl_jitter="%s"\n' \
      "$ST_CP_PORT" "$SUBTOP_CACHE_TTL" "$SUBTOP_FAIL_OPEN" "$SUBTOP_TTL_JITTER")"
  fi
  local _os_toml=""
  if [ -n "$SUBTOP_OPENSTACK" ]; then
    # `route_by` only when a case asked for it: the default gateway config
    # must keep resolving UUIDs alone (appendix A.1).
    local _os_route_by=""
    [ -n "$SUBTOP_OS_ROUTE_BY" ] && _os_route_by="$(printf 'route_by = %s\n' "$(toml_arr "$SUBTOP_OS_ROUTE_BY")")"
    # Appendix C: `scope = "cross_project"` is the only lab shape that needs a
    # password credential (an application credential cannot span projects) and
    # makes the gateway ask Nova with `all_tenants=1`. The mock never checks
    # the password, so a placeholder is fine.
    local _os_scope=""
    [ "$SUBTOP_OS_SCOPE" = "cross_project" ] && \
      _os_scope="$(printf 'scope = "cross_project"\nauth_method = "password"\nusername = "ops-admin"\npassword = "lab-pw"\n')"
    _os_toml="$(printf '[openstack]\nenabled = true\nrouting = "openstack_only"\nauthorization = "openstack_only"\nallow_any_authenticated_key = true\nauth_url = "http://127.0.0.1:%s/v3"\nnova_endpoint = "http://127.0.0.1:%s/v2.1"\napplication_credential_id = "cred-id"\napplication_credential_secret = "cred-secret"\nproject_id = "proj-1"\nregion = "RegionOne"\ninterface = "public"\nssh_port = %s\ncache_ttl = "%s"\ntimeout = "%s"\nfail_open = %s\naddress_family = "ipv4"\nprefer = "floating"\non_ambiguous = "%s"\ndefault_backend_user = "%s"\nbackend_user_metadata_key = "%s"\n%s\n%s\n%s\n' \
      "$ST_OS_PORT" "$ST_OS_PORT" "$ST_SSHD_PORT" \
      "$SUBTOP_OS_CACHE_TTL" "$SUBTOP_OS_TIMEOUT" "$SUBTOP_OS_FAIL_OPEN" \
      "$SUBTOP_OS_ON_AMBIGUOUS" "$SUBTOP_OS_DEFAULT_USER" "$SUBTOP_OS_METADATA_KEY" \
      "$_os_scope" "$_os_route_by" "$SUBTOP_OS_EXTRA")"
  fi

  printf '[listen]\naddr="127.0.0.1:%s"\n[host_keys]\nkeys=[{path="%s",state="active"}]\n[relay]\nwindow_size="%s"\nmax_packet="32KB"\noutbound_guard=true\n%s\n[backend]\nhost_key_policy="accept-new"\n[pool]\nenabled=false\nkeepalive_interval="%s"\nkeepalive_max_miss=%s\n%s%s\n[limits]\nauth_timeout="0s"\n[metrics]\naddr="127.0.0.1:%s"\n' \
    "$ST_GW_PORT" "$SUBTOP_HOSTKEY" "$SUBTOP_WINDOW" "$_env_al" \
    "$SUBTOP_KEEPALIVE_INTERVAL" "$SUBTOP_KEEPALIVE_MAX_MISS" \
    "$_cp_toml" "$_os_toml" "$ST_MET_PORT" > "$SUBTOPO_DIR/gw.toml"

  # B3 sftp-intercept section (defaults are inert; older gateways that predate
  # these fields simply ignore the unknown sections).
  {
    printf '[intercept.sftp]\nenabled=%s\ndeny_commands=%s\nallowed_path_prefixes=%s\ndenied_path_prefixes=%s\n' \
      "$SUBTOP_SFTP_ENABLED" "$(toml_arr "$SUBTOP_SFTP_DENY")" \
      "$(toml_arr "$SUBTOP_SFTP_ALLOW_PREFIX")" "$(toml_arr "$SUBTOP_SFTP_DENY_PREFIX")"
    # [ca] required by the gateway validator. M4-1: point trusted_ca_keys at the
    # host CA (gateway @cert-authority trust). Default: harmless non-empty key.
    local _ca_keys="${SUBTOP_TRUSTED_CA_KEYS:-$IT_ASSET_DIR/user_ed25519.pub}"
    printf '[ca]\ntrusted_ca_keys=%s\n' "$(toml_arr "$_ca_keys")"
  } >> "$SUBTOPO_DIR/gw.toml"

  /usr/sbin/sshd -t -f "$SUBTOPO_DIR/sshd.cfg" 2>>"$SUBTOPO_DIR/sshd.log" \
    || { tail_log "$SUBTOPO_DIR/sshd.log" 20; return 1; }
  /usr/sbin/sshd -D -e -f "$SUBTOPO_DIR/sshd.cfg" >"$SUBTOPO_DIR/sshd.log" 2>&1 &
  ST_SSHD_PID=$!
  python3 "$SUBTOPO_CASE_DIR/../../scripts/mock_control_plane.py" \
    --port "$ST_CP_PORT" --rules "$SUBTOPO_DIR/rules.json" \
    >"$SUBTOPO_DIR/cp.log" 2>&1 &
  ST_CP_PID=$!
  if [ -n "$SUBTOP_OPENSTACK" ]; then
    python3 "$SUBTOPO_CASE_DIR/../../scripts/mock_openstack.py" \
      --port "$ST_OS_PORT" --rules "$SUBTOPO_DIR/os_rules.json" \
      --access-log "$SUBTOPO_DIR/os_access.log" \
      >"$SUBTOPO_DIR/os.log" 2>&1 &
    ST_OS_PID=$!
  fi
  "$SUBTOPO_GW_BIN" --config "$SUBTOPO_DIR/gw.toml" >"$SUBTOPO_DIR/gw.log" 2>&1 &
  ST_GW_PID=$!

  wait_tcp_open 127.0.0.1 "$ST_SSHD_PORT" 20 || { tail_log "$SUBTOPO_DIR/sshd.log" 20; return 1; }
  wait_http_ok "http://127.0.0.1:${ST_CP_PORT}/healthz"  20 || { tail_log "$SUBTOPO_DIR/cp.log" 20;  return 1; }
  if [ -n "$SUBTOP_OPENSTACK" ]; then
    wait_http_ok "http://127.0.0.1:${ST_OS_PORT}/healthz" 20 || { tail_log "$SUBTOPO_DIR/os.log" 20; return 1; }
  fi
  wait_http_ok "http://127.0.0.1:${ST_MET_PORT}/healthz" 20 || { tail_log "$SUBTOPO_DIR/gw.log" 20; return 1; }
  log "subtopo up: gateway=$ST_GW_PORT cp=$ST_CP_PORT backend=$ST_SSHD_PORT${ST_OS_PORT:+ os=$ST_OS_PORT}"
}

# Kill server-side backend session procs on our port (drops the gateway's backend
# connect) + the master listener. lsof-scoped: never touches the system sshd.
_subtopo_kill_port_sessions() {
  local port="$1" p
  [ -n "$port" ] || return 0
  for p in $(lsof -nP -iTCP:"$port" -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 && $1 ~ /sshd/ {print $2}' | sort -u); do
    kill -9 "$p" 2>/dev/null || true
  done
}

subtopo_kill_backend() {
  _subtopo_kill_port_sessions "$ST_SSHD_PORT"
  [ -n "$ST_SSHD_PID" ] && kill -9 "$ST_SSHD_PID" 2>/dev/null || true
}

subtopo_kill_cp() {
  [ -n "$ST_CP_PID" ] && kill -TERM "$ST_CP_PID" 2>/dev/null || true
  # ensure it is gone
  sleep 0.3
  [ -n "$ST_CP_PID" ] && kill -9 "$ST_CP_PID" 2>/dev/null || true
}

subtopo_metric() {  # subtopo_metric <regex> -> matching /metrics lines
  python3 - "http://127.0.0.1:${ST_MET_PORT}/metrics" "$1" <<'PY' 2>/dev/null
import sys, urllib.request, re
url, pat = sys.argv[1], sys.argv[2]
rx = re.compile(pat)
data = urllib.request.urlopen(url, timeout=4).read().decode()
for line in data.splitlines():
    if rx.search(line):
        print(line)
PY
}

# subtopo_ssh <remote-command...> — ssh as $PRINCIPAL into the sub-topology gateway.
#
# Agent forwarding is requested by DEFAULT (`SUBTOP_SSH_A=1`): it is the only
# credential the gateway can present to the backend. Set `SUBTOP_SSH_A=0` for a
# case that is specifically about a client that never asks. The agent is never
# used for *user* auth here (`IdentitiesOnly=yes` + an explicit -i pin that),
# which is exactly the separation the passthrough feature needs: the agent is a
# signing backend, not a credential the client offers for itself.
subtopo_ssh() {
  local _a=()
  [ "${SUBTOP_SSH_A:-1}" = "1" ] && _a+=(-A)
  ssh -p "$ST_GW_PORT" -i "$USER_KEY" "${_a[@]}" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes -o ConnectTimeout=15 -o LogLevel=ERROR \
    "$PRINCIPAL@127.0.0.1" "$@"
}

# subtopo_ssh_A <remote-command...> — same, with agent forwarding requested.
subtopo_ssh_A() {
  SUBTOP_SSH_A=1 subtopo_ssh "$@"
}

# subtopo_agent_start <key-to-add...> — start a throwaway ssh-agent holding those
# keys and export SSH_AUTH_SOCK/SSH_AGENT_PID **in the caller's shell** (so run
# this directly, never inside `$(...)`). Pair with subtopo_agent_stop.
#
# Any agent *this shell* started is stopped first, so a restart never leaks one
# and at most one agent is ever ours. An agent inherited from the orchestrator
# (the shared suite agent) is simply replaced in this shell, never killed: other
# cases still depend on it.
subtopo_agent_start() {
  local key
  subtopo_agent_stop
  eval "$(ssh-agent -s)" >/dev/null 2>&1 || return 1
  SUBTOP_AGENT_STARTED=1
  export SSH_AUTH_SOCK SSH_AGENT_PID
  for key in "$@"; do
    ssh-add "$key" </dev/null >/dev/null 2>&1 || return 1
  done
  log "agent up on $SSH_AUTH_SOCK (agent pid $SSH_AGENT_PID)"
}

# subtopo_agent_stop — kill the agent this shell started (if any) and drop the
# variables. Deliberately does NOT touch an agent it did not start: that one
# belongs to the orchestrator and is shared with every other case.
subtopo_agent_stop() {
  if [ "${SUBTOP_AGENT_STARTED:-0}" = "1" ]; then
    SUBTOP_AGENT_STARTED=0
    ssh-agent -k >/dev/null 2>&1 || true
  fi
  unset SSH_AUTH_SOCK SSH_AGENT_PID || true
}

subtopo_stop() {
  [ -n "$ST_GW_PID" ]  && kill -9 "$ST_GW_PID"  2>/dev/null || true
  [ -n "$ST_CP_PID" ]  && kill -9 "$ST_CP_PID"  2>/dev/null || true
  subtopo_kill_os
  _subtopo_kill_port_sessions "$ST_SSHD_PORT"
  [ -n "$ST_SSHD_PID" ] && kill -9 "$ST_SSHD_PID" 2>/dev/null || true
}

# Kill the mock OpenStack only (the "Nova is down" case); the gateway keeps
# running so the assertion is about fail-closed resolution, not about a dead
# gateway.
subtopo_kill_os() {
  if [ -n "${ST_OS_PID:-}" ]; then
    kill -TERM "$ST_OS_PID" 2>/dev/null || true
    sleep 0.3
    kill -9 "$ST_OS_PID" 2>/dev/null || true
    ST_OS_PID=""
  fi
}

# openstack_topo_start <authorized_keys-file> [instances-rules-json]
#
# Sub-topology with an agent-key-only backend *and* the OpenStack route: the
# gateway resolves instance UUIDs through the mock Nova and reaches the backend
# only by asking the client's forwarded agent to sign. No [control_plane] is
# rendered (SUBTOP_OPENSTACK_PURE default), so a green case also proves pure
# mode boots with no control plane (MUST2).
openstack_topo_start() {
  SUBTOP_SSHD_AUTHORIZED_KEYS="$1"
  SUBTOP_AGENT_FORWARDING="true"
  SUBTOP_OPENSTACK="1"
  # Second argument is the instance table, not a mode: SUBTOP_OPENSTACK is the
  # on/off switch (anything non-empty), SUBTOP_OPENSTACK_RULES is the table.
  [ -n "${2:-}" ] && SUBTOP_OPENSTACK_RULES="$2"
  subtopo_start
}

# subtopo_os_count <METHOD> <path-prefix> -> number of matching mock requests.
# This is the MUST1 probe: "zero Nova requests while only the public-key shape
# was checked" reads as `subtopo_os_count GET /v2.1/servers/` == 0.
subtopo_os_count() {
  local method="$1" prefix="$2"
  curl -fsS --max-time 4 "http://127.0.0.1:${ST_OS_PORT}/__log" 2>/dev/null |
    python3 -c 'import json, sys
method, prefix = sys.argv[1], sys.argv[2]
try:
    data = json.load(sys.stdin).get("requests", [])
except Exception:
    data = []
print(sum(1 for r in data
          if r.get("method") == method and str(r.get("path", "")).startswith(prefix)))' \
      "$method" "$prefix"
}

# subtopo_os_statuses <METHOD> <path-prefix> -> the response codes of the
# matching requests, space-separated. "404" and "200" look identical from the
# client (both end in a plain auth failure) but only "200" proves the lookup
# succeeded and the *selection* refused the instance.
subtopo_os_statuses() {
  local method="$1" prefix="$2"
  curl -fsS --max-time 4 "http://127.0.0.1:${ST_OS_PORT}/__log" 2>/dev/null |
    python3 -c 'import json, sys
method, prefix = sys.argv[1], sys.argv[2]
try:
    data = json.load(sys.stdin).get("requests", [])
except Exception:
    data = []
print(" ".join(str(r.get("status", "-")) for r in data
               if r.get("method") == method and str(r.get("path", "")).startswith(prefix)))' \
      "$method" "$prefix"
}

# subtopo_os_log -> the mock's request log as JSON ({"requests":[]} when down).
subtopo_os_log() {
  curl -fsS --max-time 4 "http://127.0.0.1:${ST_OS_PORT}/__log" 2>/dev/null \
    || printf '{"requests":[]}'
}
