#!/usr/bin/env bash
# tests/integration/agent_topo.sh — shared setup for the agent-passthrough cases
# (plan-agent-passthrough C3). Source-only; sourced AFTER common.sh + subtopo.sh.
#
# The topology these cases need is deliberately hostile to a silent downgrade:
# the backend's authorized_keys contains **only** the end user's agent key, and
# the gateway holds no credential of its own to offer (plan-agent-only D3). If
# an agent session ever succeeded without the agent, or a failed agent session
# ever fell back to a second credential, these cases would catch it.
set -uo pipefail

# agent_topo_backend_keys <file> [pubkey...] — write an authorized_keys holding
# exactly the listed public keys, mode 0600.
agent_topo_backend_keys() {
  local out="$1" k
  shift
  mkdir -p "$(dirname "$out")"
  : > "$out"
  for k in "$@"; do
    cat "$k" >> "$out"
  done
  chmod 600 "$out"
}

# agent_topo_start <authorized_keys-file> — bring up the sub-topology with an
# agent-key-only backend and a control-plane grant that allows this principal to
# forward its agent. There is nothing else to switch on: agent passthrough is
# the only backend auth mode there is.
agent_topo_start() {
  SUBTOP_SSHD_AUTHORIZED_KEYS="$1"
  SUBTOP_AGENT_FORWARDING="true"
  subtopo_start
}

# agent_topo_wait_for_audit <pattern> — the audit record is emitted when the
# client session is dropped, which trails the command by a moment; poll for it.
agent_topo_wait_for_audit() {
  local pat="$1" i
  for i in $(seq 1 40); do
    if grep -q -- "$pat" "$SUBTOPO_DIR/gw.log" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# agent_topo_audit_json — the most recent `session audit` payload, unescaped.
#
# The gateway logs the audit record as a JSON *string* nested inside the tracing
# line, so a raw grep for `"auth_kind":"agent"` never matches the file; parse it
# out instead. Prints nothing if no audit record has landed yet.
agent_topo_audit_json() {
  python3 - "$SUBTOPO_DIR/gw.log" <<'PY'
import json, sys
try:
    lines = open(sys.argv[1], encoding="utf-8", errors="replace")
except OSError:
    raise SystemExit(0)
last = None
for line in lines:
    try:
        doc = json.loads(line)
    except ValueError:
        continue
    fields = doc.get("fields") or {}
    if fields.get("message") == "session audit" and "json" in fields:
        last = fields["json"]
if last is not None:
    print(last)
PY
}

# agent_topo_metric_value <metric-name> — the current integer value of a counter.
# (`subtopo_metric` takes a *Python* regex, so the trailing separator is a plain
# space, not a POSIX bracket class.)
agent_topo_metric_value() {
  subtopo_metric "^$1 " | awk '{print $2}'
}
