"""Guard for strings OSIRIS itself puts on the keyboard HUD or in a status reply.

The claims register marks θ_lock = 51.843°, τ₀ ≈ 46 μs and Φ = 0.7734 refuted or
artifacts, and the two Γ thresholds (≤ 0.092 provisional, 0.95 "verified") are not yet
one registered definition (GEMINI.md, Evidence and claims). A status pill that prints
any of them reads as a live measurement, so OSIRIS-authored labels are checked here and
refused rather than shown.

This guards OSIRIS's own output only. Text the operator typed is theirs and passes
through untouched.
"""

import re
from typing import List, Pattern, Tuple

__all__ = ["LabelRejected", "label_violations", "guard_label"]

_MARKERS: Tuple[Tuple[str, Pattern], ...] = (
    ("theta_lock", re.compile(r"(?i)(θ|theta)[ _]?lock|51\.843")),
    ("tau_0", re.compile(r"(?i)τ₀|tau_?0\s*[≈=~]|46\s*[μu]s")),
    ("phi_0.7734", re.compile(r"0\.7734")),
    ("gamma_threshold", re.compile(r"(?i)(Γ|gamma)[ _]?(floor|crit|threshold)|0\.0920\b")),
    ("crsm_mechanism", re.compile(r"(?i)\b11\s*-?\s*D\s*-?\s*CRSM\b")),
)


class LabelRejected(ValueError):
    """An OSIRIS-authored label carries a refuted or unregistered quantity."""


def label_violations(text: str) -> List[str]:
    return [name for name, pattern in _MARKERS if pattern.search(text)]


def guard_label(text: str) -> str:
    hits = label_violations(text)
    if hits:
        raise LabelRejected("label carries unregistered quantities (%s): %r" % (", ".join(hits), text))
    return text
