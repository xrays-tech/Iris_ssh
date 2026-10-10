#!/usr/bin/env bash
# case_port_forward_denied.sh — TCP port forwarding (-L / direct-tcpip) must be
# rejected by the gateway by default (D6). We open a local forward aimed at the
# backend sshd and try to speak SSH through it: if forwarding worked we would
# receive the backend's SSH banner, so a denial looks like refused / closed /
# timeout-without-data.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/common.sh"

fwd_port="$(alloc_port)"
probe_log="$IT_WORK_DIR/fwd_probe.out"

# -N : no remote command. Background the forward-bearing session.
ssh -N -L "${fwd_port}:${BACKEND_HOST}:${BACKEND_PORT}" "${SSH_OPTS[@]}" "$TARGET" \
  >"$IT_WORK_DIR/fwd_ssh.log" 2>&1 &
fwd_pid=$!

# Ensure the client-side listener is up before probing.
if ! wait_tcp_open "$GW_ADDR" "$fwd_port" 10; then
  kill "$fwd_pid" 2>/dev/null || true
  # Listener never came up is *also* a form of denial; nothing was forwarded.
  pass "local -L listener never opened (forward denied)"
  echo "OK: case_port_forward_denied"
  exit 0
fi
sleep 0.5

result="$(python3 - "$fwd_port" <<'PY'
import socket, sys
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
except OSError:
    print("refused"); sys.exit(0)
s.settimeout(4)
try:
    data = s.recv(64)
except socket.timeout:
    print("timeout"); s.close(); sys.exit(0)
except OSError:
    print("closed"); s.close(); sys.exit(0)
if data:
    print("banner:" + data.split(b"\n", 1)[0].decode("latin1", "replace"))
else:
    print("closed")
s.close()
PY
)"

kill "$fwd_pid" 2>/dev/null || true
wait "$fwd_pid" 2>/dev/null || true

printf '%s\n' "$result" > "$probe_log"
case "$result" in
  banner:*)
    fail "port forward was NOT denied — received data through the tunnel: $result" ;;
  refused|closed|timeout)
    pass "port forward denied (probe result: $result)" ;;
  *)
    fail "unexpected probe result: $result" ;;
esac
echo "OK: case_port_forward_denied"
