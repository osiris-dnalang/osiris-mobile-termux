"""AST-linked clipboard: explicit captures become typed, provenance-stamped nodes.

There is no "passive clipboard" provenance label, and ``ingest`` refuses any label it
does not know, so background clipboard watching has no way in. The Android side
registers its clip listener only while the operator has the context chip on; this side
makes the same rule hold even if the client gets it wrong.

Every node is ``learnable=False``. Captured text is context for the next prompt, not
training data; making it learnable is a separate, explicit decision.
"""

import ast
import collections
import hashlib
import time
from typing import Any, Deque, Dict, List, Optional

from .ledger import HashChainLedger
from .redact import redact

__all__ = ["Provenance", "PayloadType", "IngestRejected", "ASTClipboard"]

#: Upper bound on characters handed to ``ast.parse``; deep or huge input can exhaust
#: the parser's stack long before it produces anything useful for a preview.
MAX_PARSE_CHARS = 64 * 1024
PREVIEW_CHARS = 500


class Provenance(object):
    EXPLICIT_COPY = "explicit_copy"      # copy with the context chip on
    SHARE_TARGET = "share_target"        # ACTION_SEND / ACTION_SEND_MULTIPLE
    SELECTION_MENU = "selection_menu"    # ACTION_PROCESS_TEXT
    ASSIST_SNAPSHOT = "assist_snapshot"  # explicit assistant invocation only

    ALL = (EXPLICIT_COPY, SHARE_TARGET, SELECTION_MENU, ASSIST_SNAPSHOT)


class PayloadType(object):
    PYTHON = "python_ast"
    SHELL = "shell_cmd"
    CHAT_LOG = "chat_log"
    TEXT = "unstructured_text"


_SHELL_HEADS = frozenset((
    "git", "gh", "gcloud", "pytest", "python", "python3", "pip", "pip3", "osiris",
    "osiris-mobile", "adb", "tmux", "pkg", "apt", "bash", "sh", "make", "ollama",
))

# Hosts whose copied text is another model's output. Kept in sync with
# ``engine.HOST_PROFILES`` by test, not by import, so either can change deliberately.
LLM_HOSTS = frozenset((
    "com.openai.chatgpt",
    "com.google.android.apps.bard",
    "com.anthropic.claude",
    "com.google.android.googlequicksearchbox",
))

_DEFINITIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)


class IngestRejected(ValueError):
    """Capture refused: empty, oversized, or carrying an unknown provenance label."""


def _python_symbols(text: str) -> Optional[List[str]]:
    """Symbols if ``text`` is recognisably Python, else ``None``.

    A bare sentence such as ``hello`` is a valid Python expression, so a successful
    parse alone proves nothing; a definition or an import does.
    """
    if len(text) > MAX_PARSE_CHARS:
        return None
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    symbols: List[str] = []
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, _DEFINITIONS):
            continue
        found = True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.append("fn:" + node.name)
        elif isinstance(node, ast.ClassDef):
            symbols.append("class:" + node.name)
        else:
            names = [a.name for a in node.names]
            module = getattr(node, "module", None)
            symbols.extend("import:" + (module + "." + n if module else n) for n in names)
    return symbols if found else None


def classify(text: str, source_package: str) -> Dict[str, Any]:
    symbols = _python_symbols(text)
    if symbols is not None:
        shown = ", ".join(symbols[:5])
        return {"payload_type": PayloadType.PYTHON, "symbols": symbols,
                "summary": "Python (%d symbols: %s)" % (len(symbols), shown)}
    head = text.split(None, 1)[0] if text.split() else ""
    if head in _SHELL_HEADS or head.startswith("termux-"):
        return {"payload_type": PayloadType.SHELL, "symbols": [],
                "summary": "Command: " + text.splitlines()[0][:80]}
    if source_package in LLM_HOSTS:
        return {"payload_type": PayloadType.CHAT_LOG, "symbols": [],
                "summary": "Model output (%s): %s" % (source_package, " ".join(text.split())[:80])}
    return {"payload_type": PayloadType.TEXT, "symbols": [],
            "summary": " ".join(text.split())[:120]}


class ASTClipboard(object):
    """Typed capture store backed by the hash-chained journal."""

    def __init__(self, ledger: HashChainLedger, recent: int = 32, max_chars: int = 256 * 1024) -> None:
        self.ledger = ledger
        self.max_chars = max_chars
        self._recent: Deque[Dict[str, Any]] = collections.deque(maxlen=recent)

    def ingest(self, text: str, source_package: str, provenance: str) -> Dict[str, Any]:
        if provenance not in Provenance.ALL:
            raise IngestRejected("unknown provenance %r; expected one of %s"
                                 % (provenance, ", ".join(Provenance.ALL)))
        if not isinstance(text, str) or not text.strip():
            raise IngestRejected("empty capture")
        if len(text) > self.max_chars:
            raise IngestRejected("capture of %d chars exceeds %d" % (len(text), self.max_chars))

        clean, redactions = redact(text.strip())
        digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()
        node = {
            "event": "AST_NODE_INGESTED",
            "node_id": "ast_" + digest[:12],
            "sha256": digest,
            "timestamp_utc": time.time(),
            "source_package": source_package[:200],
            "provenance": provenance,
            "redactions": redactions,
            "learnable": False,
            "preview": clean[:PREVIEW_CHARS],
        }
        node.update(classify(clean, source_package))
        sealed = self.ledger.append(node)
        self._recent.append(sealed)
        return sealed

    def recent(self, n: int = 3) -> List[Dict[str, Any]]:
        return list(self._recent)[-n:] if n > 0 else []
