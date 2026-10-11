#!/usr/bin/env python3
"""Programmable mock control plane for the ssh-gateway black-box suite.

Contract (propose.md §3.1 / task spec):
    POST /api/v1/resolve
        request  {"principal":"alex_host1","client_ip":"..","key_fp":"SHA256:.."}
        200      {"target":{"host","port","user"},"policy":{...}}
        403 / 404 / 429 / 500 / 503  {"error":"..."}

The response for each principal is fully driven by a JSON *rules* file so the
orchestrator (which knows dynamically-allocated backend ports) can bake the real
target in before starting the server:

    {
      "resolve": {
        "<principal>": {
            "status": 200,
            "target": {"host":"127.0.0.1","port":22222,"user":"alex"},
            "policy": {"agent_forwarding":false,"tcp_forwarding":false,
                       "recording":false,"ttl":60},
            "delay_ms": 0            # optional: simulate control-plane latency
        },
        "<denied>": {"status":403,"error":"principal not authorized"}
      },
      "default": {"status":404,"error":"principal not found"}
    }

Endpoints:
    GET  /healthz   -> {"ok":true}            (readiness probe)
    GET  /__log     -> JSON array of requests seen (debugging only)
    POST /api/v1/resolve

Self-contained: stdlib only, graceful SIGTERM, binds a configurable port.
"""
import argparse
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

# do_POST builds the 200/4xx/5xx body from the matched rule VERBATIM (every
# non-control key is passed through). So `policy` may carry any field the
# gateway's Policy understands today (agent_forwarding, tcp_forwarding,
# recording, ttl) AND forward-compatible fields the gateway will consume later
# (e.g. policy.tcp_forward_targets for B4 jump target whitelisting,
# policy.sftp_intercept for B3 command interception). Unknown fields are inert
# until the gateway reads them, so rules stay backward-compatible. Example rule:
#     "<principal>": {"status":200,
#                     "target":{"host","port","user"},
#                     "policy":{"ttl":60,"tcp_forwarding":true,
#                               "tcp_forward_targets":["127.0.0.1:22223"],
#                               "sftp_intercept":{"deny_ops":["remove"]}}}


class State:
    def __init__(self, rules_path: str, access_log: str = "") -> None:
        self.lock = threading.Lock()
        self.requests: List[Dict[str, Any]] = []
        self.access_log = access_log
        self.rules: Dict[str, Dict[str, Any]] = {
            "resolve": {},
            "default": {"status": 404, "error": "not found"},
        }
        if rules_path and os.path.exists(rules_path):
            with open(rules_path) as fh:
                loaded = json.load(fh)
            self.rules["resolve"] = loaded.get("resolve", {})
            self.rules["default"] = loaded.get(
                "default", {"status": 404, "error": "not found"}
            )
            # tolerate a flat {principal: rule, ...} dialect too (defensive).
            for key, value in loaded.items():
                if key not in ("resolve", "default"):
                    self.rules["resolve"][key] = value

    def record(self, entry: Dict[str, Any]) -> None:
        with self.lock:
            self.requests.append(entry)
        if self.access_log:
            # best-effort on-disk trace so requests survive CP restarts for debug
            try:
                with open(self.access_log, "a") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError:
                pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # silence access log
        pass

    def _send(self, code: int, obj: Dict[str, Any]) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        state: State = self.server.state  # type: ignore[attr-defined]
        if self.path == "/healthz":
            self._send(200, {"ok": True})
        elif self.path == "/__log":
            with state.lock:
                data = list(state.requests)
            self._send(200, {"requests": data})
        else:
            self._send(404, {"error": "unknown path"})

    def do_POST(self) -> None:
        state: State = self.server.state  # type: ignore[attr-defined]
        if self.path != "/api/v1/resolve":
            self._send(404, {"error": "unknown path"})
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            self._send(400, {"error": "bad json"})
            return
        principal = req.get("principal", "")
        rule = state.rules["resolve"].get(principal, state.rules["default"])
        state.record({"t": time.time(), "body": req, "verdict": rule.get("status")})
        delay = rule.get("delay_ms", 0)
        if delay:
            time.sleep(delay / 1000.0)
        status = int(rule.get("status", 404))
        obj = {k: v for k, v in rule.items() if k not in ("status", "delay_ms")}
        self._send(status, obj)


class ControlPlane(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr: Any, state: State) -> None:
        self.state = state
        ThreadingHTTPServer.__init__(self, addr, Handler)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--rules", required=True, help="path to rules JSON")
    ap.add_argument("--pidfile", default="")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--access-log", default="", help="append each request as a JSON line")
    args = ap.parse_args()

    state = State(args.rules, args.access_log)
    if args.pidfile:
        with open(args.pidfile, "w") as fh:
            fh.write(str(os.getpid()))

    httpd = ControlPlane((args.bind, args.port), state)

    def _term(signum: int, frame: Optional[Any]) -> None:
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    sys.stderr.write("[mock-cp] listening on %s:%d rules=%s\n"
                     % (args.bind, args.port, args.rules))
    sys.stderr.flush()
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
