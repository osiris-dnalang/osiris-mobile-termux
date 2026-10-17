"""Secret redaction applied before any captured text is hashed, stored or echoed.

A SHA-256 over a payload proves the payload did not change; it says nothing about
whether the payload was safe to keep. Archives that passed integrity checks have
carried live tokens before, so redaction runs first and the ledger digest is taken
over the *redacted* text: the chain never commits to secret bytes.

The patterns are deliberately conservative -- a false positive costs a ``<REDACTED>``
marker in a preview, a false negative costs a credential rotation.
"""

import re
from typing import Callable, List, Pattern, Tuple, Union

__all__ = ["REDACTED", "redact"]

REDACTED = "<REDACTED>"

_Replacement = Union[str, Callable[["re.Match[str]"], str]]


def _keep_key(match: "re.Match[str]") -> str:
    # "password = hunter22" -> "password = <REDACTED>": the key name stays readable.
    return match.group(1) + match.group(2) + REDACTED


_PATTERNS: Tuple[Tuple[str, Pattern, _Replacement], ...] = (
    ("private_key", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     REDACTED),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
     REDACTED),
    ("api_key_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), REDACTED),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), REDACTED),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),
    ("db_url_password", re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:@/]+:)[^\s@/]+@"),
     lambda m: m.group(1) + REDACTED + "@"),
    ("assignment", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)"
        r"(\s*[:=]\s*[\"']?)[^\s\"',;]{6,}"),
     _keep_key),
)


def redact(text: str) -> Tuple[str, List[str]]:
    """Return ``(redacted_text, kinds)``; ``kinds`` names each pattern that fired, once."""
    kinds: List[str] = []
    for kind, pattern, replacement in _PATTERNS:
        text, n = pattern.subn(replacement, text)
        if n:
            kinds.append(kind)
    return text, kinds
