#!/usr/bin/env python3
"""Programmable mock OpenStack (Keystone + Nova) for the ssh-gateway suite.

Contract (plan-openstack §3.2 / §4.2):
    POST /v3/auth/tokens
        -> 201, `X-Subject-Token: <token>`, body carrying a service catalog
           whose compute endpoint points back at this server.
    GET  /v2.1/servers/{uuid}
        -> 200 with the instance JSON from the rules file, or 404 when the uuid
           is unknown (Nova's answer for "not visible to this credential" is
           deliberately indistinguishable from "does not exist").
    GET  /v2.1/servers?name={value}
        -> 200 with `{"servers": [...]}`, the instances whose `name` *contains*
           the value (Nova's `name` filter is a substring/regex search, so the
           gateway must narrow the result to an exact match locally — plan-
           openstack appendix A.2/A.3). No hit => `{"servers": []}`, never 404.
    GET  /healthz  -> {"ok": true}         (readiness probe)
    GET  /__log    -> {"requests": [...]}  (debugging / MUST1 assertions)

The rules file is fully static (no dynamic ports: the gateway learns the SSH
port from `[openstack] ssh_port`, and every test instance lives on 127.0.0.1):

    {
      "servers": {
        "550e8400-e29b-41d4-a716-446655440000": {
          "addresses": {"private": [{"addr": "127.0.0.1", "version": 4,
                                     "OS-EXT-IPS:type": "fixed"}]},
          "metadata": {"iris_ssh_user": "alice"},
          "name": "web-1",
          "image": {"id": "img-1"}
        }
      },
      "default": {"status": 404}
    }

Per-server control keys (stripped from the Nova body):
    status   HTTP status to return (default 200)
    delay_ms sleep before answering — used to widen a race window
    envelope answer `{"server": {…}}` (classic v2 wire format) instead of
             the flat v2.1 document — for the envelope-robustness case
    slim_list answer the `?name=` list with only `id`/`links`/`name` and no
             addresses — some real clouds (e.g. T_3741) slim list entries, so
             the gateway must refine a unique name match with show-by-id
    cross_tenant mark this instance as living in a *different* project (the
             mock gives it a `tenant_id` when served). Visible only when the
             request carries `all_tenants=1` (the gateway's `cross_project`
             mode); a single-project request must not see it — that is exactly
             how Nova separates projects (appendix C.3).

Self-contained: stdlib only, graceful SIGTERM, `--access-log` for assertions
that must survive a restart.
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
from urllib.parse import parse_qs, urlparse

CONTROL_KEYS = ("status", "delay_ms", "envelope", "slim_list", "cross_tenant")

# Headers worth keeping in the log: they are the evidence that the gateway
# authenticated with a real token and asked for the microversion it claims to.
RECORDED_HEADERS = (
    "x-auth-token",
    "openstack-api-version",
    "x-openstack-nova-api-version",
    "content-type",
)


class State:
    def __init__(self, rules_path: str, access_log: str = "") -> None:
        self.lock = threading.Lock()
        self.requests: List[Dict[str, Any]] = []
        self.access_log = access_log
        self.rules: Dict[str, Any] = {"servers": {}, "default": {"status": 404}}
        if rules_path and os.path.exists(rules_path):
            with open(rules_path) as fh:
                loaded = json.load(fh)
            self.rules["servers"] = loaded.get("servers", {})
            self.rules["default"] = loaded.get("default", {"status": 404})
            # Tolerate a flat {uuid: server, ...} dialect too (defensive).
            for key, value in loaded.items():
                if key not in ("servers", "default"):
                    self.rules["servers"][key] = value

    def record(self, entry: Dict[str, Any]) -> None:
        with self.lock:
            self.requests.append(entry)
        if self.access_log:
            try:
                with open(self.access_log, "a") as fh:
                    fh.write(json.dumps(entry) + "\n")
            except OSError:
                pass

    def count(self, method: str, path_prefix: str) -> int:
        with self.lock:
            return sum(
                1
                for r in self.requests
                if r.get("method") == method and str(r.get("path", "")).startswith(path_prefix)
            )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # silence access log
        pass

    def _send(self, code: int, obj: Dict[str, Any], extra: Optional[List[tuple]] = None) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _record(self, body: Any = None, status: Optional[int] = None) -> None:
        """Log one request. `status` is the response code, recorded because a
        case must be able to tell "Nova said 404" from "Nova said 200 and the
        gateway then refused the instance" — both reach the same client-facing
        rejection but only one proves the lookup succeeded."""
        state: State = self.server.state  # type: ignore[attr-defined]
        entry: Dict[str, Any] = {
            "t": time.time(),
            "method": self.command,
            "path": self.path,
            "headers": {k: self.headers.get(k) for k in RECORDED_HEADERS if self.headers.get(k)},
            "body": body,
        }
        if status is not None:
            entry["status"] = status
        state.record(entry)

    def do_GET(self) -> None:
        state: State = self.server.state  # type: ignore[attr-defined]
        if self.path == "/healthz":
            self._record()
            self._send(200, {"ok": True})
            return
        if self.path == "/__log":
            self._record()
            with state.lock:
                data = list(state.requests)
            self._send(200, {"requests": data})
            return
        if self.path.startswith("/v2.1/servers?"):
            # Instance-name lookup (plan-openstack appendix A.2): Nova's
            # `name` filter is a substring search, so the gateway's local
            # exact-match narrowing is what a case is actually testing.
            query = parse_qs(urlparse(self.path).query)
            needle = query.get("name", [""])[0]
            # `scope="cross_project"` sends `all_tenants=1`; anything else is a
            # single-project request that must not see another project's
            # instances (appendix C.3).
            all_tenants = query.get("all_tenants", ["0"])[0] == "1"
            matched = []
            for uuid, server in state.rules["servers"].items():
                if not isinstance(server, dict):
                    continue
                if server.get("cross_tenant") and not all_tenants:
                    continue  # a different project: invisible to this scope
                if needle and needle in str(server.get("name", "")):
                    if server.get("slim_list"):
                        # A directory entry only: id/links/name, no addresses.
                        matched.append(
                            {"id": uuid, "name": server.get("name"), "links": []}
                        )
                        continue
                    body = {k: v for k, v in server.items() if k not in CONTROL_KEYS}
                    body.setdefault("id", uuid)
                    if server.get("cross_tenant"):
                        body.setdefault("tenant_id", "other-tenant")
                    matched.append(body)
            self._record(status=200)
            self._send(200, {"servers": matched})
            return
        if self.path.startswith("/v2.1/servers/"):
            path_only = self.path[len("/v2.1/servers/"):].split("?", 1)[0]
            query = parse_qs(urlparse(self.path).query)
            all_tenants = query.get("all_tenants", ["0"])[0] == "1"
            uuid = path_only
            server = state.rules["servers"].get(uuid, state.rules["default"])
            if not isinstance(server, dict):
                server = {"status": 404}
            if server.get("cross_tenant") and not all_tenants:
                # Same visibility boundary as the list path: Nova answers 404
                # for "not visible to this credential" and the gateway must not
                # be able to tell it apart from "does not exist".
                self._record(status=404)
                self._send(404, {"itemNotFound": {"code": 404, "message": "no such server"}})
                return
            delay = server.get("delay_ms", 0)
            if delay:
                time.sleep(delay / 1000.0)
            status = int(server.get("status", 200))
            self._record(status=status)
            if status != 200:
                self._send(status, {"itemNotFound": {"code": status, "message": "no such server"}})
                return
            body = {k: v for k, v in server.items() if k not in CONTROL_KEYS}
            body.setdefault("id", uuid)
            if server.get("cross_tenant"):
                body.setdefault("tenant_id", "other-tenant")
            if server.get("envelope"):
                body = {"server": body}
            self._send(200, body)
            return
        self._record()
        self._send(404, {"error": "unknown path"})

    def do_POST(self) -> None:
        raw = self._read_body()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            parsed = {"_unparsable": True}
        self._record(parsed)

        if self.path != "/v3/auth/tokens":
            self._send(404, {"error": "unknown path"})
            return
        base = self.server.base_url  # type: ignore[attr-defined]
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(time.time() + 86400))
        body = {
            "token": {
                "expires_at": expires_at,
                "catalog": [
                    {
                        "type": "compute",
                        "region": "RegionOne",
                        "endpoints": [
                            {
                                "interface": "public",
                                "region": "RegionOne",
                                "url": base + "/v2.1",
                            }
                        ],
                    }
                ],
            }
        }
        self._send(201, body, extra=[("X-Subject-Token", "mock-subject-token")])


class OpenStack(ThreadingHTTPServer):
    daemon_threads = True
    #: The catalog URL Nova hands back to the gateway: this server itself.
    base_url: str

    def __init__(self, addr: Any, state: State) -> None:
        self.state = state
        host, port = addr
        self.base_url = f"http://{host}:{port}"
        ThreadingHTTPServer.__init__(self, addr, Handler)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--rules", required=True, help="path to the instances rules JSON")
    ap.add_argument("--pidfile", default="")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--access-log", default="", help="append each request as a JSON line")
    args = ap.parse_args()

    state = State(args.rules, args.access_log)
    if args.pidfile:
        with open(args.pidfile, "w") as fh:
            fh.write(str(os.getpid()))

    httpd = OpenStack((args.bind, args.port), state)

    def _term(signum: int, frame: Optional[Any]) -> None:
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    sys.stderr.write(
        "[mock-os] listening on %s:%d rules=%s\n" % (args.bind, args.port, args.rules)
    )
    sys.stderr.flush()
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
