# OSIRIS Keyboard Interception Layer — OSIRIS-IME-INTERCEPTION-001

**Status:** DRAFT proposal, 2026-10-17. Extends OSIRIS-ANDROID-SPEC-001 §6 (Smart Keyboard).
Nothing here is ratified until the operator merges it.

## 1. What this is

The "Sovereign Interception Layer" blueprint (v1.0, and the v1.1 revision of it) describes
a split keyboard for the Node Alpha foldable that sits between the operator and every app:
an OSIRIS intent bar above ChatGPT, Gemini or Claude, an AST-linked clipboard, ✨ Auto Enhance
and ≫ Auto Advance chips, a hinge "Center Spine" of OSIRIS hotkeys, a DevOps bridge, and an
assistant/omnichannel contact.

This document keeps the parts that can be built and tested now, builds the Termux side of
them in `osiris_mobile/ime/`, fixes the defects in the v1.0 reference code, and records what
stays gated and why. Everything marked TESTED below has a test in this repository that CI
runs. Everything else is a design, labelled as one.

## 2. Authority model

The keyboard has two output channels, and neither executes anything.

| Channel | Carries | Transport | Authority |
| :--- | :--- | :--- | :--- |
| 1. Text | Characters for the focused field (Termux stdin, a chat box) | `InputConnection.commitText` / `sendKeyEvent` | None. Text appears in the field and the host app decides what it means. |
| 2. Control | Explicit captures, intent compilation, hinge-spine actions | Signed HTTP over loopback to `osiris-ime-bridge` (§4) | Read-only actions run on this channel; anything that starts compute answers `REQUIRES_GRANT` and goes through the SYS-021 grant path (`android_bridge.py`). |

The rules that follow from it:

1. **The operator dispatches.** `/v1/intent/intercept` returns text. The keyboard commits
   it into the host app only on an operator tap. Every response says
   `requires_operator_dispatch: true`.
2. **Auto Advance stages, it never submits.** Follow-up turns come back as a bounded queue
   (`MAX_ADVANCE_DEPTH = 5` turns in total). Each one needs its own tap. Steps that prepare
   something pushable are flagged `irreversible` and need a second, distinct confirmation.
   v1.0 had the loop "auto-submit until convergence". An agent loop proposes; it never authorizes.
3. **There is no passive capture.** The daemon accepts four provenance labels
   (`explicit_copy`, `share_target`, `selection_menu`, `assist_snapshot`) and refuses any
   other, so background clipboard watching cannot get in, even if a client tries to send it.
   Captured nodes are `learnable: false`.
4. **Secrets are redacted before hashing.** Captures are redacted first (GitHub, `sk-`,
   Google, Slack and AWS keys, JWTs, private-key blocks, database URL passwords,
   `password=` style assignments), and the journal digest is taken over the redacted text.
   The chain never commits to secret bytes.
5. **Password fields suppress everything.** Requests built for a password field carry
   `sensitive_field: true`, and the daemon answers `409 SENSITIVE_FIELD` without compiling
   anything (Spec §6.3). `ImeBridgeProtocol.isSensitiveInputType` makes the call on the
   Android side.
6. **OSIRIS-authored labels are guarded.** HUD and status strings that OSIRIS writes pass
   `labels.guard_label`, which rejects θ_lock / 51.843°, τ₀ ≈ 46 μs, Φ = 0.7734, Γ floor or
   threshold values and "11D CRSM" mechanism claims (GEMINI.md, Evidence and claims). Text
   the operator types is theirs and passes through untouched.
7. **Nothing leaves the device.** The daemon never calls a model, an API or a shell.

## 3. Implementation status

| Blueprint element | Where | Evidence | Status |
| :--- | :--- | :--- | :--- |
| AST clipboard: typed nodes, provenance, redaction | `osiris_mobile/ime/clipboard.py`, `redact.py` | `tests/test_ime_core.py` (clipboard, redaction) | TESTED |
| Provenance journal (hash chain, verify, resume, flock) | `osiris_mobile/ime/ledger.py` | `tests/test_ime_core.py` (journal) | TESTED |
| Dual-bar interception: rough intent → delineated host prompt | `osiris_mobile/ime/engine.py`, `POST /v1/intent/intercept` | `tests/test_ime_core.py` (engine), `tests/test_ime_server.py` | TESTED |
| ✨ Auto Enhance / ≫ Auto Advance | `engine.IntentEngine.compile` | `test_advance_stages_but_never_submits`, `test_advance_is_bounded` | TESTED |
| Host-app matrix (ChatGPT, Gemini, Google AI Mode, Claude, Termux, GitHub, Cloud Console, Messages, Gmail) | `engine.HOST_PROFILES` | `test_unknown_host_gets_standard_profile`, `test_llm_hosts_match_engine_profiles` | TESTED |
| Hinge-spine control plane: allowlist, idempotent `task_id`, honest states | `osiris_mobile/ime/control.py`, `POST /v1/control/dispatch` | `tests/test_ime_core.py` (control), `test_control_dispatch_idempotent_and_journaled_once` | TESTED |
| HUD label guard | `osiris_mobile/ime/labels.py` | `test_label_guard_*`, `test_osiris_authored_strings_pass_the_guard` | TESTED |
| Signed loopback daemon `osiris-ime-bridge` | `osiris_mobile/ime/server.py` | `tests/test_ime_server.py` (real socket on 127.0.0.1) | TESTED |
| Kotlin wire contract: signing, reply check, UUIDv7, `ControlRequest`, password detection | `android/.../ime/ImeBridgeProtocol.kt` | `ImeBridgeProtocolTest.kt` (JVM), `tests/test_ime_protocol_parity.py` (golden vectors, allowlist drift) | TESTED (JVM, not on device) |
| Loopback-only cleartext policy | `res/xml/network_security_config.xml` | none, APK not built in CI | NOT VERIFIED |
| `InputMethodService` UI: split layout, Center Spine, intent bar, chips | not built | — | DESIGN (§6) |
| Share target and `ACTION_PROCESS_TEXT` activity | not built | — | DESIGN (§6) |
| `VoiceInteractionService` assistant, screen snapshot | not built | — | GATED (§7) |
| DevOps bridge (git/gh/gcloud from the keyboard) | not built | — | GATED (§7) |
| SMS, email and voice-call contact | not built | — | GATED (§7) |

Two figures from the v1.0 design are not implemented as described:

- **Local zero-cost planning by qwen2.5-coder:7b on the phone.** The planner here is a
  deterministic template (`planner: "template"` in every response): it works with no model
  running and its output is reproducible. A model-backed planner can sit behind the same
  contract later; the `planner` field must then name the model, and the response stays
  text-only.
- **"Deterministic UUIDv7" task ids.** UUIDv7 is time-ordered, not deterministic.
  Idempotency comes from the client reusing the same id on retry (`ControlRequest` holds it)
  and the daemon caching per `task_id` for 15 minutes.

## 4. Wire protocol (v1.0)

Base URL: `http://127.0.0.1:8420`. The daemon refuses to bind anything except
127.0.0.1, ::1 or localhost.

**Pairing.** `osiris-ime-bridge --pair` writes a 32-byte key to
`$OSIRIS_HOME/ime/pairing.key` (mode 0600), prints it once, and exits. The operator enters it
in the keyboard, which should keep it in the Android Keystore. The daemon will not start
without the key, and it refuses a key file that group or other can read. Re-running `--pair`
rotates the key.

**Request signature.** Every request carries:

```
X-Osiris-Timestamp: <epoch ms>
X-Osiris-Signature: v1=<hex HMAC-SHA256(key, METHOD "\n" PATH "\n" TIMESTAMP "\n" hex SHA256(body))>
```

Requests more than 60 s off the daemon's clock are refused. The key itself never crosses
the socket. On Android, loopback is shared by every app on the device, so being on loopback
proves nothing about the caller. The signature does.

**Reply signature.** Every reply carries `X-Osiris-Signature: v1=<hex HMAC-SHA256(key, body)>`,
so the keyboard can tell the paired daemon from anything else listening on the port.

| Endpoint | Body | Success |
| :--- | :--- | :--- |
| `GET /v1/health` | — | `status`, `component`, `node`, `protocol_version`, `planner`, `ledger {entries, head, chain_ok}` |
| `POST /v1/ast/ingest` | `text`, `provenance` (required); `source_package` | `{status: "ingested", node}` |
| `POST /v1/intent/intercept` | `intent` (required); `host_package`, `auto_enhance`, `auto_advance`, `iteration`, `sensitive_field`, `context_nodes` (0–8) | `compiled_host_prompt`, `prompt_sha256`, `staged_next[]`, `irreversible`, `requires_operator_dispatch` |
| `POST /v1/control/dispatch` | `protocol_version: "1.0"`, `task_id` (canonical UUID), `intent: "tui.dispatch_card"`, `parameters {action_name, accelerator}` | `state` ∈ `EXECUTED`, `REQUIRES_GRANT`, `UNSUPPORTED`, `FAILED`; `replayed` |

Allowlisted actions: `health.check` and `ledger.verify` (executed here), `nclm.status`
(read-only, but this node has no handler for it yet, so it answers `UNSUPPORTED`), and
`mentor.benchmark` and `ledger.check_all` (`REQUIRES_GRANT`).

Errors are JSON `{error, detail}`, never a traceback: `401 UNSIGNED | BAD_TIMESTAMP |
STALE_REQUEST | BAD_SIGNATURE`, `400 BAD_JSON | MISSING_FIELD | BAD_FIELD_TYPE |
FIELD_TOO_LONG | BAD_FIELD_VALUE | BAD_INTENT`, `409 SENSITIVE_FIELD | TASK_ID_CONFLICT`,
`411`, `413 BODY_TOO_LARGE` (256 KiB), `422 INGEST_REJECTED | CONTROL_REJECTED`,
`404 NO_ROUTE`, `405`. JSON booleans must be booleans: the string `"false"` is rejected,
not read as true.

**Journal.** The daemon writes to `$OSIRIS_HOME/ime/journal.jsonl`, with one line per
captured node, compiled intent and control dispatch. For an intent it records the prompt's
digest, never the prompt text. `osiris-ime-bridge --verify` walks the chain. This is Node
Alpha's local journal: records are staged for review on Node Beta, and nothing here promotes
anything.

## 5. Corrections

### 5.1 Defects in the v1.0 reference code

| v1.0 | Effect | Now |
| :--- | :--- | :--- |
| `bool(body.get("auto_advance", False))` | The string `"false"` turned Auto Advance **on** | Typed fields; wrong type is `400 BAD_FIELD_TYPE` |
| Any successful `ast.parse` meant "Python" | A bare word like `hello` was classified as code | Python only if it defines or imports something |
| No authentication on 127.0.0.1:8420 | Any app on the phone could drive the daemon | HMAC-signed requests and replies |
| Uncaught `json.loads`, no body limit, single-threaded server | Tracebacks to the client, unbounded reads, one slow client blocks all | Fail-closed 4xx, 256 KiB limit, threaded server, 10 s socket timeout |
| Substrate probe and ledger opened at class-definition time | Importing the module touched the filesystem | Built once in `Bridge(...)` at start-up |
| Raw clipboard text appended to plain JSONL | Secrets kept on disk; edits undetectable | Redact, then hash; append-only hash chain |
| Auto Advance auto-submits until convergence | Agent loop acting as authorization | Staged queue; one tap per turn; irreversible steps flagged |
| Clip listener registered in `onCreate` for the IME's lifetime | Watches every copy while the keyboard is installed | Client rule: register only while the chip is on and the keyboard is visible. Daemon rule: provenance labels (§2.3) |
| `usesCleartextTraffic="true"` app-wide | Cleartext allowed to any host | `network_security_config.xml`: cleartext to 127.0.0.1 only |

### 5.2 Defects in this repository fixed alongside

- `android_bridge.NodeAlphaTermuxBridge` shipped a default token (`node-alpha-local-token`)
  and compared tokens with `!=`. The token is now required, and the comparison is
  constant-time (`test_bridge_requires_explicit_token`).
- `IntentPreviewFirewall` previews for `/ignite` and `/learn` printed θ_lock = 51.843° and
  Γ_floor = 0.0920 as if they were live parameters. They now describe the action only
  (`firewallPreviewsCarryNoRefutedConstants`).
- `containsUnsafeChaining` stopped one character early, so a trailing `;`, `|` or backtick
  was never examined (`testTrailingOperatorRejected`, which fails on the old loop bound).
- CI never compiled or ran the Kotlin. `android/jvm-check/` builds the platform-free sources
  on the JVM, and CI's new `kotlin-jvm` job runs their 23 tests. The first run found
  `testChainedCommandRejected` failing on `main`: its input `/ignite && rm -rf /` trips the
  denylist before the chaining check. The test now uses a chain with no denylisted token.

### 5.3 Claims in the v1.0 narrative

| v1.0 said | The repositories show | Here |
| :--- | :--- | :--- |
| "Galaxy Fold7" | osiris-governance and osiris-cli 4.5.4 name Node Alpha a Pixel 10 Pro Fold; OSIRIS-ANDROID-SPEC-001 says both "Pixel Fold" and "Fold7" | Use `NODE_ALPHA` as the node id (`OSIRIS_NODE_ID`); fix the device name in one place |
| HUD shows "pytest 177/177", "coverage 92.4%", commit `36d9948`, branch `feat/rqc-60` | None of these strings appears in any of the 13 repos, apart from an unrelated 92.4 % in an osiris-cli assessment | The HUD shows only what `/v1/health` returns, and each figure there is computed when requested |
| AST nodes stamped against Zenodo `10.5281/zenodo.23241223` for "preflight auditing" | That DOI is the RQC S2 preregistration (osiris-cli `RELEASE_NOTES_v4.5.4.md`) | Not referenced; keyboard captures have no bearing on S2 |
| Telemetry strip: "Substrate nominal (11D CRSM)", Γ values | Refuted or unregistered (GEMINI.md) | Rejected by `guard_label` |

## 6. Next steps (Node Beta builds, Node Alpha runs)

1. `OsirisImeService : InputMethodService`, built on Node Beta with the Android SDK,
   consuming `ImeBridgeProtocol`:
   - Channel 1 typing on the split layout. `WindowInfoTracker` puts the Center Spine over
     the hinge.
   - The intent bar opens for `ImeBridgeProtocol.LLM_HOSTS`, never on password fields.
   - Spine keys build one `ControlRequest` per press and resend that same instance on retry.
   - Every reply is checked with `verifyReply`. On failure the bar shows `IPC: OFFLINE`
     and disables Channel 2 rather than guessing.
2. Share target (`ACTION_SEND`) and selection menu (`ACTION_PROCESS_TEXT`) activity, sending
   `share_target` / `selection_menu` captures.
3. Pairing UX: enter the hex key once and keep it in the Android Keystore. Re-pair on 401.
4. On-device acceptance tests mapped to AT-IME-01..07. The JVM tests here do not replace
   them.
5. The termux.properties single-row extra-keys bar from the blueprint is a stand-alone
   Termux change. It belongs in `config/` once someone has tried it on the device.

## 7. Gated

| Item | Why it waits | Opens when |
| :--- | :--- | :--- |
| Any automatic submission (Auto Advance, voice, assistant) | Payload-bound operator authorization (SYS-021) | Never by default; per-action grant only |
| `VoiceInteractionService` with view-tree snapshots | Reads every app's screen | Operator ratifies the permission; snapshots stay `assist_snapshot`, explicit invocation only |
| DevOps mutations from the keyboard (push, merge, gcloud changes) | Node Alpha holds no cloud credentials; the human commits | Keyboard may only *draft* (branch name, PR text); execution stays on Node Beta |
| SMS / email / voice-call contact, Twilio-style webhooks | Leaves the device; inbound messages are requests, never authorization | TLS, an enrolled node key (dual-node Phase 5), and a written review |
| Model-backed planner | Must not change the authority model | Same contract, `planner` names the model, still text-only |

## 8. Open decisions for the operator

1. Node Alpha's device name of record (Pixel 10 Pro Fold or Pixel Fold). The node id stays `NODE_ALPHA`.
2. Whether `nclm.status` gets a read-only handler wired to osiris-cli when it is installed (full tier).
3. Whether the keyboard client should also sign with an enrolled node key (Phase 5) in
   addition to the pairing key, so journal entries can name the device that made them.
