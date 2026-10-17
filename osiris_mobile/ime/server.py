"""Loopback daemon the OSIRIS keyboard talks to: ``osiris-ime-bridge``.

Endpoints (all JSON, all authenticated)::

    GET  /v1/health            component status, journal head, chain check
    POST /v1/ast/ingest        explicit capture -> typed, redacted, journaled node
    POST /v1/intent/intercept  rough intent -> delineated prompt (+ staged next turns)
    POST /v1/control/dispatch  hinge-spine key -> allowlisted, idempotent action

Transport rules, each a fix to the v1.0 reference daemon:

* **Loopback only.** Binding anything but 127.0.0.1 / ::1 is refused at start-up.
  Android's loopback is shared by every app on the device, so loopback is not
  authentication; the signature below is.
* **Signed requests, signed replies.** The client sends ``X-Osiris-Timestamp`` (epoch ms)
  and ``X-Osiris-Signature: v1=<hex>``, an HMAC-SHA256 under the pairing key over
  ``METHOD\\nPATH\\nTIMESTAMP\\nSHA256(body)``. The key never crosses the socket, and a
  request older than ``MAX_SKEW_MS`` is refused. Replies carry ``X-Osiris-Signature``
  over the reply body, so the keyboard can tell the paired daemon from anything else
  listening on the port. A bare digest proves nothing about who produced it.
* **Fail closed.** No pairing key, no start. Oversized, unparseable, non-object or
  mistyped bodies get a 4xx with an error code, never a traceback. JSON booleans must be
  booleans: ``"false"`` is rejected, not read as true.
* **Nothing leaves the device.** The daemon never calls a model, an API or a shell. It
  returns text and states; the keyboard dispatches only on an operator tap.
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import stat
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from .. import __version__, store
from .clipboard import ASTClipboard, IngestRejected
from .control import PROTOCOL_VERSION, Action, ControlPlane, ControlRejected, TaskConflict
from .engine import IntentEngine, SensitiveField
from .labels import guard_label
from .ledger import HashChainLedger

__all__ = [
    "MAX_BODY_BYTES", "MAX_SKEW_MS", "LOOPBACK_HOSTS",
    "sign_request", "sign_reply", "Bridge", "make_server", "main",
]

log = logging.getLogger("osiris_mobile.ime")

DEFAULT_PORT = 8420
MAX_BODY_BYTES = 256 * 1024
MAX_SKEW_MS = 60_000
MAX_CONTEXT_NODES = 8
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
MIN_KEY_BYTES = 16


def _sig(key: bytes, message: bytes) -> str:
    return "v1=" + hmac.new(key, message, hashlib.sha256).hexdigest()


def sign_request(key: bytes, method: str, path: str, timestamp_ms: int, body: bytes) -> str:
    """Signature the client puts in ``X-Osiris-Signature``. Mirrored by the Kotlin client."""
    message = "%s\n%s\n%d\n%s" % (method.upper(), path, timestamp_ms, hashlib.sha256(body).hexdigest())
    return _sig(key, message.encode("utf-8"))


def sign_reply(key: bytes, body: bytes) -> str:
    return _sig(key, body)


class _BadRequest(Exception):
    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super(_BadRequest, self).__init__(code)
        self.status, self.code, self.detail = status, code, detail


def _field(body: Dict[str, Any], key: str, kind: type, default: Any = None,
           required: bool = False, max_len: Optional[int] = None) -> Any:
    if key not in body:
        if required:
            raise _BadRequest(400, "MISSING_FIELD", key)
        return default
    value = body[key]
    # bool is an int subclass; an integer field must not accept true/false.
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise _BadRequest(400, "BAD_FIELD_TYPE", "%s must be %s" % (key, kind.__name__))
    if max_len is not None and len(value) > max_len:
        raise _BadRequest(400, "FIELD_TOO_LONG", key)
    return value


class Bridge(object):
    """Everything a request needs, built once and shared by the handler threads."""

    def __init__(self, key: bytes, ledger_path: Path, node_label: str = "NODE_ALPHA",
                 clock_ms: Any = None) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError("pairing key must be at least %d bytes" % MIN_KEY_BYTES)
        self.key = key
        self.node_label = node_label
        self.ledger = HashChainLedger(ledger_path)
        self.clipboard = ASTClipboard(self.ledger)
        self.engine = IntentEngine(node_label)
        self.control = ControlPlane(handlers={
            Action.HEALTH_CHECK: self.health,
            Action.LEDGER_VERIFY: self._ledger_status,
        })
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))

    def _ledger_status(self) -> Dict[str, Any]:
        ok, count, problem = self.ledger.verify()
        return {"entries": count, "head": self.ledger.head()[:16], "chain_ok": ok, "problem": problem}

    def health(self) -> Dict[str, Any]:
        return {
            "status": guard_label("ok"),
            "component": guard_label("osiris-ime-bridge %s" % __version__),
            "node": guard_label(self.node_label),
            "protocol_version": PROTOCOL_VERSION,
            "planner": "template",
            "ledger": self._ledger_status(),
        }

    def authenticate(self, method: str, path: str, headers: Any, body: bytes) -> None:
        stamp = headers.get("X-Osiris-Timestamp")
        signature = headers.get("X-Osiris-Signature")
        if not stamp or not signature:
            raise _BadRequest(401, "UNSIGNED")
        try:
            stamp_ms = int(stamp)
        except ValueError:
            raise _BadRequest(401, "BAD_TIMESTAMP")
        if abs(self._clock_ms() - stamp_ms) > MAX_SKEW_MS:
            raise _BadRequest(401, "STALE_REQUEST")
        expected = sign_request(self.key, method, path, stamp_ms, body)
        if not hmac.compare_digest(expected, signature):
            raise _BadRequest(401, "BAD_SIGNATURE")

    def route(self, method: str, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        if method == "GET" and path == "/v1/health":
            return self.health()
        if method != "POST":
            raise _BadRequest(404, "NO_ROUTE", "%s %s" % (method, path))
        if path == "/v1/ast/ingest":
            try:
                node = self.clipboard.ingest(
                    text=_field(body, "text", str, required=True),
                    source_package=_field(body, "source_package", str, "unknown", max_len=200),
                    provenance=_field(body, "provenance", str, required=True, max_len=40),
                )
            except IngestRejected as exc:
                raise _BadRequest(422, "INGEST_REJECTED", str(exc))
            return {"status": "ingested", "node": node}
        if path == "/v1/intent/intercept":
            host = _field(body, "host_package", str, "", max_len=200)
            n_context = _field(body, "context_nodes", int, 3)
            if not 0 <= n_context <= MAX_CONTEXT_NODES:
                raise _BadRequest(400, "BAD_FIELD_VALUE", "context_nodes must be 0..%d" % MAX_CONTEXT_NODES)
            try:
                result = self.engine.compile(
                    intent=_field(body, "intent", str, required=True),
                    host_package=host,
                    context=self.clipboard.recent(n_context),
                    auto_enhance=_field(body, "auto_enhance", bool, True),
                    auto_advance=_field(body, "auto_advance", bool, False),
                    iteration=_field(body, "iteration", int, 1),
                    sensitive_field=_field(body, "sensitive_field", bool, False),
                )
            except SensitiveField as exc:
                raise _BadRequest(409, "SENSITIVE_FIELD", str(exc))
            except ValueError as exc:
                raise _BadRequest(400, "BAD_INTENT", str(exc))
            # The journal keeps the prompt digest, not the prompt: intents are private.
            self.ledger.append({
                "event": "INTENT_COMPILED", "timestamp_utc": time.time(), "host_package": host,
                "prompt_sha256": result["prompt_sha256"], "staged": len(result["staged_next"]),
                "irreversible": result["irreversible"],
            })
            result["status"] = "ok"
            return result
        if path == "/v1/control/dispatch":
            try:
                result = self.control.dispatch(body)
            except ControlRejected as exc:
                raise _BadRequest(422, "CONTROL_REJECTED", str(exc))
            except TaskConflict as exc:
                raise _BadRequest(409, "TASK_ID_CONFLICT", str(exc))
            if not result["replayed"]:
                self.ledger.append({
                    "event": "CONTROL_DISPATCH", "timestamp_utc": time.time(),
                    "task_id": result["task_id"], "action_name": result["action_name"],
                    "state": result["state"], "request_sha256": result["request_sha256"],
                })
            return result
        raise _BadRequest(404, "NO_ROUTE", "%s %s" % (method, path))


class _Handler(BaseHTTPRequestHandler):
    server_version = "osiris-ime-bridge"
    sys_version = ""
    timeout = 10  # a client that stalls mid-body must not pin a thread
    bridge: Bridge  # set on the subclass made by make_server

    def log_message(self, fmt: str, *args: Any) -> None:
        # Request lines only, at debug level: bodies may hold private text.
        log.debug("%s %s", self.address_string(), fmt % args)

    def _reply(self, status: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Osiris-Signature", sign_reply(self.bridge.key, raw))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _read_body(self) -> bytes:
        if self.command == "GET":
            return b""
        length = self.headers.get("Content-Length")
        if length is None:
            raise _BadRequest(411, "LENGTH_REQUIRED")
        try:
            n = int(length)
        except ValueError:
            raise _BadRequest(400, "BAD_LENGTH")
        if n < 0:
            raise _BadRequest(400, "BAD_LENGTH")
        if n > MAX_BODY_BYTES:
            raise _BadRequest(413, "BODY_TOO_LARGE", "limit %d bytes" % MAX_BODY_BYTES)
        return self.rfile.read(n)

    def _handle(self) -> None:
        try:
            raw = self._read_body()
            path = self.path.split("?", 1)[0]
            self.bridge.authenticate(self.command, path, self.headers, raw)
            body: Dict[str, Any] = {}
            if self.command != "GET":
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except (UnicodeDecodeError, ValueError):
                    raise _BadRequest(400, "BAD_JSON")
                if not isinstance(body, dict):
                    raise _BadRequest(400, "BAD_JSON", "body must be a JSON object")
            self._reply(200, self.bridge.route(self.command, path, body))
        except _BadRequest as exc:
            self._reply(exc.status, {"error": exc.code, "detail": exc.detail})
        except Exception:  # never hand a traceback to the client
            log.exception("unhandled error on %s %s", self.command, self.path)
            self._reply(500, {"error": "INTERNAL"})

    do_GET = _handle
    do_POST = _handle

    def _no_route(self) -> None:
        self._reply(405, {"error": "METHOD_NOT_ALLOWED"})

    do_PUT = do_DELETE = do_PATCH = _no_route


def make_server(bridge: Bridge, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    if host not in LOOPBACK_HOSTS:
        raise ValueError("refusing to bind %r: the bridge listens on loopback only" % host)
    handler = type("BoundHandler", (_Handler,), {"bridge": bridge})
    server_cls = ThreadingHTTPServer
    if ":" in host:
        server_cls = type("ThreadingHTTPServer6", (ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
    server = server_cls((host, port), handler)
    server.daemon_threads = True
    return server


def _default_key_file() -> Path:
    return store.home() / "ime" / "pairing.key"


def _load_key(path: Path) -> bytes:
    """Read the pairing key, refusing a file other users could read."""
    st = path.stat()
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("%s is readable by group/other; chmod 600 it" % path)
    key = bytes.fromhex(path.read_text(encoding="ascii").strip())
    if len(key) < MIN_KEY_BYTES:
        raise ValueError("pairing key in %s is shorter than %d bytes" % (path, MIN_KEY_BYTES))
    return key


def _pair(path: Path) -> str:
    """Create a new 32-byte pairing key with mode 0600; return its hex for the keyboard."""
    path.parent.mkdir(parents=True, exist_ok=True)
    hex_key = secrets.token_hex(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(hex_key + "\n")
    os.chmod(str(path), 0o600)
    return hex_key


def _parse(argv: Optional[list]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="osiris-ime-bridge",
                                description="Loopback daemon for the OSIRIS keyboard.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--key-file", type=Path, default=None,
                   help="pairing key (hex, mode 0600); default $OSIRIS_HOME/ime/pairing.key")
    p.add_argument("--ledger", type=Path, default=None,
                   help="journal path; default $OSIRIS_HOME/ime/journal.jsonl")
    p.add_argument("--pair", action="store_true",
                   help="create a new pairing key, print it once for the keyboard, and exit")
    p.add_argument("--verify", action="store_true", help="verify the journal chain and exit")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = _parse(argv)
    key_file = args.key_file or _default_key_file()
    ledger_path = args.ledger or (store.home() / "ime" / "journal.jsonl")

    if args.pair:
        hex_key = _pair(key_file)
        print("Pairing key written to %s (mode 0600). Enter it in the OSIRIS keyboard once;" % key_file)
        print("it is not shown again. Re-run --pair to rotate.")
        print(hex_key)
        return 0
    if args.verify:
        ok, count, problem = HashChainLedger(ledger_path).verify()
        print("journal %s: %d entries, %s" % (ledger_path, count, "chain ok" if ok else "BROKEN: %s" % problem))
        return 0 if ok else 1

    try:
        key = _load_key(key_file)
    except (OSError, ValueError) as exc:
        print("osiris-ime-bridge: no usable pairing key (%s). Run with --pair first." % exc, file=sys.stderr)
        return 2

    bridge = Bridge(key, ledger_path, node_label=os.environ.get("OSIRIS_NODE_ID", "NODE_ALPHA"))
    try:
        server = make_server(bridge, args.host, args.port)
    except (OSError, ValueError) as exc:
        print("osiris-ime-bridge: %s" % exc, file=sys.stderr)
        return 2
    print("osiris-ime-bridge %s listening on %s:%d (%s), journal %s"
          % (__version__, args.host, server.server_address[1], bridge.node_label, ledger_path))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
