"""Unit tests for the interception layer's pure parts: redaction, journal, clipboard,
intent engine, label guard and control plane. No sockets here; see test_ime_server.py.

Every fake credential below is assembled at runtime from a prefix and filler, so no
token-shaped literal lives in the repository.
"""

import json

import pytest

from osiris_mobile.ime import clipboard as clip_mod
from osiris_mobile.ime.clipboard import ASTClipboard, IngestRejected, PayloadType, Provenance
from osiris_mobile.ime.control import (
    Action,
    ControlPlane,
    ControlRejected,
    State,
    TaskCache,
    TaskConflict,
)
from osiris_mobile.ime.engine import (
    _ADVANCE_STEPS,
    _DEFAULT_PROFILE,
    HOST_PROFILES,
    MAX_ADVANCE_DEPTH,
    IntentEngine,
    SensitiveField,
    normalize,
)
from osiris_mobile.ime.labels import LabelRejected, guard_label, label_violations
from osiris_mobile.ime.ledger import GENESIS, HashChainLedger
from osiris_mobile.ime.redact import REDACTED, redact

TASK = "0199e8b4-7c2a-7000-8a11-3f90c8210042"


def fake(prefix, n=36, ch="x"):
    return prefix + ch * n


# --- redaction -----------------------------------------------------------------------

@pytest.mark.parametrize("secret,kind", [
    (fake("ghp_"), "github_token"),
    (fake("github_pat_", 30), "github_token"),
    (fake("sk-", 24), "api_key_sk"),
    (fake("AIza", 35), "google_api_key"),
    (fake("xoxb-", 20), "slack_token"),
    ("AKIA" + "A" * 16, "aws_access_key"),
    ("eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12, "jwt"),
])
def test_redact_known_token_shapes(secret, kind):
    out, kinds = redact("before %s after" % secret)
    assert secret not in out
    assert REDACTED in out
    assert kind in kinds


def test_redact_keeps_key_name_and_db_user():
    out, kinds = redact("password = " + "p" * 10 + "\npostgres://osiris:" + "q" * 10 + "@db.local/x")
    assert out.startswith("password = " + REDACTED)
    assert "postgres://osiris:" + REDACTED + "@db.local/x" in out
    assert set(kinds) == {"assignment", "db_url_password"}


def test_redact_private_key_block():
    armour = "OPENSSH " + "PRIVATE KEY-----"
    block = "-----BEGIN " + armour + "\nAAAA\nBBBB\n-----END " + armour
    out, kinds = redact("key:\n" + block)
    assert "AAAA" not in out and kinds == ["private_key"]


def test_redact_leaves_ordinary_text():
    text = "run the mux benchmark phase B on the token ring example"
    assert redact(text) == (text, [])


# --- journal -------------------------------------------------------------------------

def test_ledger_chain_and_verify(tmp_path):
    led = HashChainLedger(tmp_path / "j.jsonl")
    assert led.head() == GENESIS and led.verify() == (True, 0, None)
    a = led.append({"event": "A"})
    b = led.append({"event": "B"})
    assert (a["seq"], b["seq"]) == (0, 1)
    assert a["prev_digest"] == GENESIS and b["prev_digest"] == a["entry_digest"]
    assert led.head() == b["entry_digest"]
    assert led.verify() == (True, 2, None)


def test_ledger_detects_edit(tmp_path):
    path = tmp_path / "j.jsonl"
    led = HashChainLedger(path)
    for i in range(3):
        led.append({"event": "E", "i": i})
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["i"] = 99
    lines[1] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, count, problem = led.verify()
    assert not ok and count == 1 and "digest mismatch at seq 1" in problem


def test_ledger_detects_deleted_middle_line(tmp_path):
    path = tmp_path / "j.jsonl"
    led = HashChainLedger(path)
    for i in range(3):
        led.append({"i": i})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    ok, _, problem = led.verify()
    assert not ok and "seq" in problem


def test_ledger_rejects_reserved_fields(tmp_path):
    with pytest.raises(ValueError):
        HashChainLedger(tmp_path / "j.jsonl").append({"seq": 7})


def test_ledger_resumes_chain_across_instances(tmp_path):
    path = tmp_path / "j.jsonl"
    first = HashChainLedger(path).append({"n": 1})
    second = HashChainLedger(path).append({"n": 2})
    assert second["seq"] == 1 and second["prev_digest"] == first["entry_digest"]


def test_ledger_tail_read_spans_chunks(tmp_path):
    led = HashChainLedger(tmp_path / "j.jsonl")
    led.append({"blob": "z" * 10000})
    last = led.append({"blob": "y" * 9000})
    assert led.head() == last["entry_digest"]
    assert led.verify()[0]


# --- clipboard -----------------------------------------------------------------------

@pytest.fixture
def board(tmp_path):
    return ASTClipboard(HashChainLedger(tmp_path / "j.jsonl"))


def test_ingest_python_symbols(board):
    node = board.ingest("import os\n\nclass A:\n    def f(self):\n        pass\n",
                        "com.termux", Provenance.EXPLICIT_COPY)
    assert node["payload_type"] == PayloadType.PYTHON
    assert node["symbols"] == ["import:os", "class:A", "fn:f"]
    assert node["learnable"] is False
    assert node["node_id"] == "ast_" + node["sha256"][:12]


def test_bare_word_is_not_python(board):
    # "hello" is a valid Python expression; v1.0 classified it as code.
    node = board.ingest("hello", "com.android.chrome", Provenance.SELECTION_MENU)
    assert node["payload_type"] == PayloadType.TEXT


def test_shell_and_chat_classification(board):
    assert board.ingest("git push origin main", "x", Provenance.SHARE_TARGET)["payload_type"] == PayloadType.SHELL
    node = board.ingest("Here is a plan", "com.openai.chatgpt", Provenance.SHARE_TARGET)
    assert node["payload_type"] == PayloadType.CHAT_LOG


def test_unknown_provenance_is_refused(board):
    # There is no label for passive clipboard watching, so it cannot get in.
    for label in ("passive_clipboard", "", "EXPLICIT_COPY"):
        with pytest.raises(IngestRejected):
            board.ingest("text", "x", label)
    assert len(board.ledger) == 0


def test_ingest_redacts_before_hashing(board):
    secret = fake("ghp_")
    node = board.ingest("token " + secret, "x", Provenance.EXPLICIT_COPY)
    raw = board.ledger.path.read_text(encoding="utf-8")
    assert secret not in raw
    assert node["redactions"] == ["github_token"]


def test_ingest_rejects_empty_and_oversized(tmp_path):
    small = ASTClipboard(HashChainLedger(tmp_path / "j.jsonl"), max_chars=10)
    with pytest.raises(IngestRejected):
        small.ingest("   ", "x", Provenance.EXPLICIT_COPY)
    with pytest.raises(IngestRejected):
        small.ingest("a" * 11, "x", Provenance.EXPLICIT_COPY)


def test_llm_hosts_match_engine_profiles():
    llm = {pkg for pkg, p in HOST_PROFILES.items() if p["mode"] == "LLM_INTERCEPT"}
    assert llm == set(clip_mod.LLM_HOSTS)


# --- engine --------------------------------------------------------------------------

def test_normalize_recovers_known_shorthand():
    assert normalize("defuce  user intent recurwiely in oogle cloud") == \
        "deduce user intent recursively in Google Cloud"
    assert normalize("Clinical notes") == "Clinical notes"  # whole words only


def test_enhance_delineates_and_never_dispatches():
    out = IntentEngine().compile("summarise this diff", "com.anthropic.claude")
    assert out["detected_app"] == "Claude" and out["planner"] == "template"
    for section in ("### Objective", "### Context", "### Constraints"):
        assert section in out["compiled_host_prompt"]
    assert out["requires_operator_dispatch"] is True
    assert out["staged_next"] == [] and out["advance_state"] is None


def test_enhance_off_passes_normalized_text_through():
    out = IntentEngine().compile("  defuce  it ", "com.termux", auto_enhance=False)
    assert out["compiled_host_prompt"] == "deduce it"


def test_advance_stages_but_never_submits():
    out = IntentEngine().compile("refactor the parser", "com.openai.chatgpt", auto_advance=True)
    staged = out["staged_next"]
    assert out["advance_state"] == "STAGED"
    assert [s["iteration"] for s in staged] == list(range(2, MAX_ADVANCE_DEPTH + 1))
    assert all(s["requires_operator_dispatch"] for s in staged)
    assert [s["irreversible"] for s in staged] == [flag for _, flag in _ADVANCE_STEPS]


def test_advance_is_bounded():
    eng = IntentEngine()
    mid = eng.compile("x", "", auto_advance=True, iteration=3)
    assert [s["iteration"] for s in mid["staged_next"]] == [4, 5]
    end = eng.compile("x", "", auto_advance=True, iteration=MAX_ADVANCE_DEPTH)
    assert end["advance_state"] == "ADVANCE_LIMIT" and end["staged_next"] == []


def test_irreversible_intent_is_flagged():
    assert IntentEngine().compile("push branch feat/x after tests", "com.github.android")["irreversible"]
    assert not IntentEngine().compile("explain the failing test", "com.github.android")["irreversible"]


def test_sensitive_field_suppresses_compilation():
    with pytest.raises(SensitiveField):
        IntentEngine().compile("anything", "com.google.android.gm", sensitive_field=True)


def test_context_nodes_are_cited(board):
    node = board.ingest("def f():\n    pass\n", "com.termux", Provenance.EXPLICIT_COPY)
    out = IntentEngine().compile("explain f", "com.openai.chatgpt", context=board.recent(3))
    assert node["node_id"] in out["compiled_host_prompt"]


def test_unknown_host_gets_standard_profile():
    out = IntentEngine().compile("hi there", "org.example.app")
    assert out["interception_mode"] == "STANDARD_ASSIST" and out["detected_app"] == "org.example.app"


# --- label guard ---------------------------------------------------------------------

@pytest.mark.parametrize("label", [
    "Substrate nominal (11D CRSM)",
    "theta_lock=51.843°",
    "θ_lock locked",
    "Γ_floor = 0.0920 enforced",
    "Gamma_floor ok",
    "τ₀ ≈ 46 μs",
    "Φ = 0.7734",
])
def test_label_guard_rejects_unregistered_quantities(label):
    assert label_violations(label)
    with pytest.raises(LabelRejected):
        guard_label(label)


def test_label_guard_passes_component_status():
    assert guard_label("osiris-ime-bridge 0.4.0b0 · NODE_ALPHA · ok") == \
        "osiris-ime-bridge 0.4.0b0 · NODE_ALPHA · ok"


def test_osiris_authored_strings_pass_the_guard():
    texts = [p["directive"] for p in HOST_PROFILES.values()] + [p["name"] for p in HOST_PROFILES.values()]
    texts += [t for t, _ in _ADVANCE_STEPS] + [_DEFAULT_PROFILE["directive"]]
    assert [t for t in texts if label_violations(t)] == []


# --- control plane -------------------------------------------------------------------

def req(action="health.check", task_id=TASK, **extra):
    body = {"protocol_version": "1.0", "task_id": task_id, "origin": "android.osiris.ime",
            "intent": "tui.dispatch_card",
            "parameters": {"accelerator": "1", "action_name": action}}
    body.update(extra)
    return body


def test_control_executes_read_only_handler():
    plane = ControlPlane(handlers={Action.HEALTH_CHECK: lambda: {"status": "ok"}})
    out = plane.dispatch(req())
    assert out["state"] == State.EXECUTED and out["output"] == {"status": "ok"} and not out["replayed"]


def test_control_replays_same_task_id():
    calls = []
    plane = ControlPlane(handlers={Action.HEALTH_CHECK: lambda: calls.append(1) or {}})
    first = plane.dispatch(req())
    again = plane.dispatch(req())
    assert len(calls) == 1 and again["replayed"] and again["state"] == first["state"]


def test_control_conflict_on_reused_task_id():
    plane = ControlPlane(handlers={Action.HEALTH_CHECK: dict})
    plane.dispatch(req())
    with pytest.raises(TaskConflict):
        plane.dispatch(req(action="ledger.verify"))


def test_compute_actions_require_a_grant():
    out = ControlPlane().dispatch(req(action=Action.MENTOR_BENCHMARK))
    assert out["state"] == State.REQUIRES_GRANT and "output" not in out


def test_missing_handler_is_unsupported_not_executed():
    assert ControlPlane().dispatch(req(action=Action.NCLM_STATUS))["state"] == State.UNSUPPORTED


def test_handler_error_reports_failed():
    def boom():
        raise RuntimeError("nope")
    out = ControlPlane(handlers={Action.HEALTH_CHECK: boom}).dispatch(req())
    assert out["state"] == State.FAILED and out["detail"] == "RuntimeError"


def test_handlers_cannot_be_registered_for_compute_actions():
    with pytest.raises(ValueError):
        ControlPlane(handlers={Action.MENTOR_BENCHMARK: dict})


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(protocol_version="2.0"),
    lambda b: b.update(intent="shell.exec"),
    lambda b: b.update(task_id="not-a-uuid"),
    lambda b: b.update(task_id=TASK.upper()),
    lambda b: b.update(parameters="health.check"),
    lambda b: b["parameters"].update(action_name="rm -rf /"),
    lambda b: b["parameters"].update(accelerator="x" * 5),
])
def test_control_rejects_malformed(mutate):
    body = req()
    mutate(body)
    with pytest.raises(ControlRejected):
        ControlPlane().dispatch(body)


def test_task_cache_expires_and_bounds():
    now = [0.0]
    cache = TaskCache(ttl_s=10, max_items=2, clock=lambda: now[0])
    cache.put("a", "d", {"v": 1})
    now[0] = 11
    assert cache.get("a", "d") is None
    for k in ("b", "c", "e"):
        cache.put(k, "d", {})
    assert len(cache) == 2 and cache.get("b", "d") is None
