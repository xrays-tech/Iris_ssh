#!/usr/bin/env bash
# case_agent_env.sh — C2 review follow-up: `env` requests must actually reach the
# backend in agent mode.
#
# Regression guard for the one handler whose agent branch sat *behind* the inline
# relay lookup. An agent session deliberately has no inline relay, so that
# ordering made `env_request` the single request handler that silently dropped
# the client's request instead of handing it to the supervisor: `SendEnv` simply
# vanished, with no error on either side. Everything else (`pty`/`shell`/`exec`/
# `subsystem`/`eof`/`close`/data) had the agent branch first.
#
# Two runs on the same hostile topology as case_agent_auth (backend
# authorized_keys holds only the user's key, so no fallback could succeed):
#
#   1. no allowlist -> the variable reaches the backend shell and comes back;
#   2. an allowlist that does not name it -> the M1 filter still applies on the
#      agent path, so agent mode cannot smuggle a filtered variable.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"
. "$HERE/subtopo.sh"
. "$HERE/agent_topo.sh"
trap 'subtopo_agent_stop; subtopo_stop' EXIT INT TERM

KEYDIR="$IT_WORK_DIR/agent-keys"; mkdir -p "$KEYDIR"
agent_topo_backend_keys "$KEYDIR/authorized_keys" "$IT_ASSET_DIR/user_ed25519.pub"
subtopo_agent_start "$IT_ASSET_DIR/user_ed25519"

# `ssh -o SendEnv=NAME` forwards NAME from the *local* environment, and the
# remote command is expanded by the remote shell, so both ends are wired up
# here. The angle brackets make an empty value distinguishable from a missing
# one: a filtered variable prints `<>`, a forwarded one prints its value.
export SSHGW_AGENT_ENV="sshgw-agent-env-value"

# --- (1) no allowlist: every variable is forwarded, agent path included. ---
SUBTOP_SSHD_AUTHORIZED_KEYS="$KEYDIR/authorized_keys"
SUBTOP_AGENT_FORWARDING="true"
SUBTOP_ENV_ALLOWLIST=""
subtopo_start

run_capture subtopo_ssh_A -o SendEnv=SSHGW_AGENT_ENV \
  "printf %s \"<\$SSHGW_AGENT_ENV>\""
if [ "$RUN_RC" -ne 0 ]; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "agent-mode SendEnv session failed (rc=$RUN_RC out=[$RUN_OUT])"
fi
assert_contains "$RUN_OUT" "<sshgw-agent-env-value>" \
  "the variable the client sent with SendEnv reached the backend shell"

# --- (2) allowlist that excludes it: the M1 filter still applies. ---
subtopo_stop
SUBTOP_ENV_ALLOWLIST="SOMETHING_ELSE"
subtopo_start

run_capture subtopo_ssh_A -o SendEnv=SSHGW_AGENT_ENV \
  "printf %s \"<\$SSHGW_AGENT_ENV>\""
if [ "$RUN_RC" -ne 0 ]; then
  tail_log "$SUBTOPO_DIR/gw.log" 40
  fail "agent-mode session failed under an allowlist (rc=$RUN_RC out=[$RUN_OUT])"
fi
assert_not_contains "$RUN_OUT" "<sshgw-agent-env-value>" \
  "a variable outside env_allowlist is still filtered on the agent path"

echo "OK: case_agent_env"
