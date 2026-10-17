"""Termux side of the OSIRIS keyboard interception layer.

The keyboard (Android ``InputMethodService``) has two output channels. Channel 1 is
ordinary text into the focused field. Channel 2 is this package: a signed loopback
protocol for explicit captures, intent compilation and allowlisted control actions.
Neither channel executes anything on its own. See ``docs/OSIRIS-IME-INTERCEPTION-001.md``.
"""

from .clipboard import ASTClipboard, IngestRejected, Provenance
from .control import Action, ControlPlane, State, TaskCache
from .engine import HOST_PROFILES, IntentEngine, SensitiveField
from .labels import LabelRejected, guard_label, label_violations
from .ledger import HashChainLedger
from .redact import redact
from .server import Bridge, make_server, sign_reply, sign_request

__all__ = [
    "ASTClipboard", "IngestRejected", "Provenance",
    "Action", "ControlPlane", "State", "TaskCache",
    "HOST_PROFILES", "IntentEngine", "SensitiveField",
    "LabelRejected", "guard_label", "label_violations",
    "HashChainLedger", "redact",
    "Bridge", "make_server", "sign_reply", "sign_request",
]
