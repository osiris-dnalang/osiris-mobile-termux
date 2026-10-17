# osiris-mobile-termux

Android/Termux execution harness for the OSIRIS research stack — a Pixel Fold as a
self-contained research lab: open-ended ALife, the dna::}{::lang front end, the
neuro-symbolic chat bridge, LivLM and NCLM, with local inference and no cloud.

This repo is **harness only**. The science lives in `dnalang-core`, `organism_sim`,
`osiris-cli` and `bridge`, which are cloned as siblings and installed editable. Nothing
is forked or patched for mobile, so a number measured on the phone is comparable to the
same number measured on the desktop.

## Install

```bash
pkg install git
git clone https://github.com/osiris-dnalang/osiris-mobile-termux
cd osiris-mobile-termux
bash bootstrap_termux.sh                 # lite tier: numpy only, ~5 min + llama.cpp build
```

Tiers: `--tier lite` (default, numpy only) · `--tier full` (+ scipy, the unified `osiris`
package, LivLM/qbyte/NCLM) · `--tier quantum` (+ qiskit/qiskit-aer, a 30–60 min on-device
Rust build; only needed for `bridge/` and Aer ground truth).

Other flags: `--model-size 1.5b|3b|none` · `--skip-llama` · `--local-src DIR` (install from
checkouts already on the device instead of cloning) · `--no-upgrade` · `--force` (run the
non-Termux stages on another Linux host).

Re-running is safe; the script is idempotent and never deletes anything.

Both shell scripts carry the canonical Termux shebang, which does not exist on a desktop
host; there, invoke them as `bash bootstrap_termux.sh …`.

### Termux:API is two things

`pkg install termux-api` gives you the CLI. It does nothing until the **Termux:API APK**
is installed from F-Droid (it must carry the same signature as Termux itself) and granted
battery and notification permissions. Without it the power governor fails open and long
runs are not throttled. `bootstrap_termux.sh` probes for this and says so.

## The fold-aware lab

```bash
./launch_fold.sh              # create or attach; layout follows the current fold state
./launch_fold.sh --status     # print layout state without attaching
./launch_fold.sh --kill       # end the session
```

Unfolded (>= 100 cols) the lab is one window split side-by-side: REPL left, live
telemetry right. Folded, the monitor moves to its own window (prefix+T). A session-scoped
`client-resized` hook relays out live, moving panes with `join-pane`/`break-pane` rather
than restarting them, so opening the phone never interrupts a run.

Inside: prefix+R relayout, prefix+T toggle monitor, prefix+r reload config.

## The unified REPL

```bash
osiris-mobile                                    # interactive
osiris-mobile --once "run the mux benchmark phase B"
osiris-mobile --dry --trace --once "auto advance"  # show the route and command, run nothing
```

Routing is deterministic regex scoring, not model inference -- it works before
llama-server is up, is unit-tested without a device, and a misroute can cost four hours
of battery, so it should never be a sampling outcome. Two dimensions are extracted:
*domain* (which subsystem) and *mode* (explain vs execute). `explain the mux benchmark`
goes to the coding agent; `run the mux benchmark` goes to a power-gated execution route.
Domain keywords alone never start a job.

Heavy routes pass the power governor first. Default policy: pause when **on battery AND
below 20%**, resume at 35% (hysteresis -- percentage jitters under load and a bare
threshold flaps). `OSIRIS_REQUIRE_PLUGGED=1` gives the strict "or unplugged" reading.
With Termux:API absent the governor fails open; `OSIRIS_POWER_FAIL_OPEN=0` inverts that
for unattended runs.

## The keyboard bridge

```bash
osiris-ime-bridge --pair      # once: writes $OSIRIS_HOME/ime/pairing.key (0600), prints it for the keyboard
osiris-ime-bridge             # serve on 127.0.0.1:8420 (python -m osiris_mobile.ime works too)
osiris-ime-bridge --verify    # walk the journal's hash chain
```

The Termux end of the OSIRIS keyboard's second channel: explicit captures become typed,
redacted, hash-chained nodes; rough intent becomes a delineated prompt for the focused app;
hinge-spine keys map to an allowlist of idempotent actions. Every request and reply is
HMAC-signed with the pairing key, because Android's loopback is shared by every app. The
daemon never calls a model, an API or a shell, and nothing it returns is dispatched until
the operator taps. Protocol, status and what stays gated:
[`docs/OSIRIS-IME-INTERCEPTION-001.md`](docs/OSIRIS-IME-INTERCEPTION-001.md).

## Layout, tiers, and the qiskit question

See [`docs/STRUCTURE.md`](docs/STRUCTURE.md). Short version: `dnalang/qc_ir.py:63` imports
qiskit lazily, so the entire ALife + bridge track runs with numpy alone.

## Mobile survival rules

- `termux-wake-lock` before any long run, or Doze suspends it.
- `setsid nohup …` — plain `nohup` dies with the Termux session.
- Checkpoint per seed. All durable state under `~/.osiris/`.
- Bound `AuditChain` (`OSIRIS_AUDIT_WINDOW`, default 512). Unbounded chains with 16 live
  N=4000 agents exceed 8 GB and the Android lowmemorykiller takes the process.
- Default model is 1.5B-Q4, not the desktop's `qwen2.5:7b`; a 7B Q4 is ~4.7 GB resident
  and is reaped on the first foreground app switch.

## Benchmarks and the research ladder

```bash
python bench/nclm_harness.py train --steps 500 --corpus $OSIRIS_SRC/organism_sim
python bench/nclm_harness.py infer --prompt "def evolve("
python bench/livlm_perplexity.py --seeds 300 301 302 303 304   # judged; other seeds refused
python bench/livlm_perplexity.py --arm random --seeds 300 301 302 303 304
python -m osiris_mobile.ladder.advance status
python -m osiris_mobile.ladder.advance auto --dry
```

`nclm_harness` trains `SovereignTransformerV2` on a byte corpus in pure NumPy — `osiris.nclm`
already has autograd, AdamW and a byte dataset, so torch would be ~250 MB of aarch64 wheels
for nothing. It adds what the desktop trainer lacks: per-step telemetry into the fold pane,
power gating, an RSS ceiling, and exact-resume checkpoints (weights *and* optimizer moments)
written atomically. It is instrumentation, not an experiment, and claims nothing.

`ladder.advance` **stages** a rung with no committed criterion — writing a `TODO` template it
cannot complete itself — and **launches** only a pre-registered one, under `setsid` with a
wake lock. Verified against the live ladder while M3c ran on five workers: it stepped over
M3c and staged M4.

## Results in this release

Both criteria were committed to `docs/PRE_REGISTRATION.md` before their runs; the single
amendment was recorded before any evaluation seed executed.

| experiment | verdict | number |
|---|---|---|
| LivLM-PPL-1 — 72 angles beat uniform? | **PASS** (criterion confounded) | median PPL 125.26 vs 256.0, 5/5 |
| LivLM-PPL-1 diagnostic — circuit alone | — | median raw-Born PPL 17 855 (≈ 70× worse than uniform) |
| LivLM-PPL-2 — evolved beats random? | **FAIL** | 0/5, median ratio 1.401 vs threshold 0.95 |

LivLM-PPL-1 met its criterion and is recorded PASS, because a criterion committed in advance
is not rewritten afterwards. Its diagnostic shows the criterion measured the **decoder's**
printable-byte smoothing, not the 72 evolved gate angles. LivLM-PPL-2 supplied the control
the first experiment lacked: evolved genomes are worse than random ones on every seed, by
~40 %. The kill criterion fires and the branch closes.

A mechanism consistent with this — the fitness term Ξ rewards peaked distributions while
log-loss punishes confident errors — is offered in `RESEARCH_PAPER.md` but was **not** tested
and would need its own pre-registration.

No hardware was involved and no physical claim is made. See `RESEARCH_PAPER.md` for scope.

## Research-program discipline

Unchanged from the desktop. Every experiment is pre-registered: the criterion is committed
to `organism_sim/docs/PROGRAM.md` *before* the run, the result is recorded PASS or FAIL,
and nothing is re-tuned on evaluation seeds. `auto advance` refuses to launch a rung that
has no pre-registration block.

---

Copyright (c) 2026 Devin Phillip Davis / Agile Defense Systems LLC.
OSIRIS Source-Available Dual License v1.0.
