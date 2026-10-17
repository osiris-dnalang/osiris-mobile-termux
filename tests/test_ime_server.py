"""End-to-end tests for ``osiris-ime-bridge`` over a real loopback socket.

The server binds 127.0.0.1 on an ephemeral port inside the test process; nothing
leaves the host.
"""

import hashlib
import hmac
import http.client
import json
import os
import stat
import threading
import time

import pytest

from osiris_mobile.ime import server as srv
from osiris_mobile.ime.server import Bridge, make_server, sign_request

KEY = bytes(range(32))
TASK = "0199e8b4-7c2a-7000-8a11-3f90c8210042"


@pytest.fixture
def live(tmp_path):
    bridge = Bridge(KEY, tmp_path / "journal.jsonl")
    server = make_server(bridge, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield bridge, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def call(port, method, path, body=None, key=KEY, stamp=None, raw=None, headers=None):
    data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode("utf-8"))
    stamp = int(time.time() * 1000) if stamp is None else stamp
    hdrs = {"X-Osiris-Timestamp": str(stamp),
            "X-Osiris-Signature": sign_request(key, method, path, stamp, data),
            "Content-Type": "application/json"}
    if method != "GET":
        hdrs["Content-Length"] = str(len(data))
    hdrs.update(headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=data if method != "GET" else None, headers=hdrs)
    resp = conn.getresponse()
    payload = resp.read()
    reply_sig = resp.getheader("X-Osiris-Signature")
    conn.close()
    return resp.status, json.loads(payload.decode("utf-8")), payload, reply_sig


def test_health_is_signed_and_honest(live):
    _, port = live
    status, body, raw, sig = call(port, "GET", "/v1/health")
    assert status == 200 and body["status"] == "ok" and body["planner"] == "template"
    assert body["ledger"]["chain_ok"] is True
    expected = "v1=" + hmac.new(KEY, raw, hashlib.sha256).hexdigest()
    assert sig == expected


@pytest.mark.parametrize("kwargs,code", [
    ({"key": b"k" * 32}, "BAD_SIGNATURE"),
    ({"stamp": int(time.time() * 1000) - 120_000}, "STALE_REQUEST"),
])
def test_bad_auth_is_refused(live, kwargs, code):
    _, port = live
    status, body, _, _ = call(port, "GET", "/v1/health", **kwargs)
    assert status == 401 and body["error"] == code


def test_unsigned_request_is_refused(live):
    _, port = live
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/v1/health")
    resp = conn.getresponse()
    assert resp.status == 401 and json.loads(resp.read())["error"] == "UNSIGNED"
    conn.close()


def test_signature_binds_the_body(live):
    _, port = live
    stamp = int(time.time() * 1000)
    signed_for = json.dumps({"intent": "explain", "host_package": ""}).encode()
    sent = json.dumps({"intent": "push to main", "host_package": ""}).encode()
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept", raw=sent, stamp=stamp, headers={
        "X-Osiris-Signature": sign_request(KEY, "POST", "/v1/intent/intercept", stamp, signed_for)})
    assert status == 401 and body["error"] == "BAD_SIGNATURE"


def test_intercept_round_trip_journals_digest_not_text(live):
    bridge, port = live
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept", {
        "intent": "defuce the failing test", "host_package": "com.openai.chatgpt", "auto_advance": True})
    assert status == 200 and body["deduced_intent"] == "deduce the failing test"
    assert body["requires_operator_dispatch"] is True and len(body["staged_next"]) == 4
    journal = bridge.ledger.path.read_text(encoding="utf-8")
    assert "failing test" not in journal and body["prompt_sha256"] in journal


def test_string_booleans_are_rejected(live):
    # v1.0 read bool("false") as True and silently switched Auto Advance on.
    _, port = live
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept",
                              {"intent": "x", "auto_advance": "false"})
    assert status == 400 and body["error"] == "BAD_FIELD_TYPE"


def test_sensitive_field_is_409(live):
    _, port = live
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept",
                              {"intent": "x", "sensitive_field": True})
    assert status == 409 and body["error"] == "SENSITIVE_FIELD"


def test_ingest_then_intercept_cites_node(live):
    _, port = live
    status, ing, _, _ = call(port, "POST", "/v1/ast/ingest", {
        "text": "def run():\n    return 1\n", "source_package": "com.termux", "provenance": "share_target"})
    assert status == 200
    node_id = ing["node"]["node_id"]
    _, out, _, _ = call(port, "POST", "/v1/intent/intercept",
                        {"intent": "review run()", "host_package": "com.anthropic.claude"})
    assert node_id in out["compiled_host_prompt"]


def test_ingest_without_provenance_is_refused(live):
    _, port = live
    status, body, _, _ = call(port, "POST", "/v1/ast/ingest", {"text": "x"})
    assert status == 400 and body == {"error": "MISSING_FIELD", "detail": "provenance"}
    status, body, _, _ = call(port, "POST", "/v1/ast/ingest", {"text": "x", "provenance": "passive"})
    assert status == 422 and body["error"] == "INGEST_REJECTED"


def test_control_dispatch_idempotent_and_journaled_once(live):
    bridge, port = live
    request = {"protocol_version": "1.0", "task_id": TASK, "intent": "tui.dispatch_card",
               "parameters": {"accelerator": "1", "action_name": "health.check"}}
    _, first, _, _ = call(port, "POST", "/v1/control/dispatch", request)
    _, again, _, _ = call(port, "POST", "/v1/control/dispatch", request)
    assert first["state"] == "EXECUTED" and not first["replayed"] and again["replayed"]
    events = [e["event"] for e in bridge.ledger.entries()]
    assert events.count("CONTROL_DISPATCH") == 1
    request["parameters"]["action_name"] = "ledger.verify"
    status, body, _, _ = call(port, "POST", "/v1/control/dispatch", request)
    assert status == 409 and body["error"] == "TASK_ID_CONFLICT"


def test_control_rejects_non_allowlisted(live):
    _, port = live
    status, body, _, _ = call(port, "POST", "/v1/control/dispatch", {
        "protocol_version": "1.0", "task_id": TASK, "intent": "tui.dispatch_card",
        "parameters": {"action_name": "shell.exec"}})
    assert status == 422 and body["error"] == "CONTROL_REJECTED"


@pytest.mark.parametrize("raw,code", [
    (b"{not json", "BAD_JSON"),
    (b"[1, 2]", "BAD_JSON"),
    (b"\xff\xfe", "BAD_JSON"),
])
def test_malformed_bodies_fail_closed(live, raw, code):
    _, port = live
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept", raw=raw)
    assert status == 400 and body["error"] == code


def test_oversized_body_is_413(live):
    _, port = live
    raw = b'{"intent": "' + b"a" * (srv.MAX_BODY_BYTES + 1) + b'"}'
    status, body, _, _ = call(port, "POST", "/v1/intent/intercept", raw=raw)
    assert status == 413 and body["error"] == "BODY_TOO_LARGE"


def test_unknown_route_and_method(live):
    _, port = live
    assert call(port, "POST", "/v1/shell", {})[0] == 404
    assert call(port, "DELETE", "/v1/health", {})[0] == 405


def test_journal_chain_survives_traffic(live):
    bridge, port = live
    for i in range(5):
        call(port, "POST", "/v1/intent/intercept", {"intent": "step %d" % i})
    ok, count, _ = bridge.ledger.verify()
    assert ok and count == 5


# --- start-up ------------------------------------------------------------------------

def test_refuses_non_loopback_bind(tmp_path):
    with pytest.raises(ValueError):
        make_server(Bridge(KEY, tmp_path / "j.jsonl"), "0.0.0.0", 0)


def test_refuses_short_key(tmp_path):
    with pytest.raises(ValueError):
        Bridge(b"short", tmp_path / "j.jsonl")


def test_pair_writes_owner_only_key(tmp_path, capsys):
    key_file = tmp_path / "ime" / "pairing.key"
    assert srv.main(["--pair", "--key-file", str(key_file)]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert key_file.read_text().strip() == printed and len(bytes.fromhex(printed)) == 32
    if os.name == "posix":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
        assert srv._load_key(key_file) == bytes.fromhex(printed)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_load_key_refuses_group_readable(tmp_path):
    key_file = tmp_path / "pairing.key"
    key_file.write_text("00" * 32)
    key_file.chmod(0o640)
    with pytest.raises(PermissionError):
        srv._load_key(key_file)


def test_main_without_key_exits_nonzero(tmp_path, capsys):
    assert srv.main(["--key-file", str(tmp_path / "missing.key"), "--ledger", str(tmp_path / "j")]) == 2
    assert "--pair" in capsys.readouterr().err


def test_verify_flag_reports_chain(tmp_path, capsys):
    ledger = tmp_path / "j.jsonl"
    Bridge(KEY, ledger).ledger.append({"event": "X"})
    assert srv.main(["--verify", "--ledger", str(ledger)]) == 0
    assert "1 entries, chain ok" in capsys.readouterr().out
