"""Append-only, hash-chained provenance journal for the interception layer.

``store.BoundedJSONL`` compacts by dropping old lines, which is right for telemetry and
wrong for provenance: dropping a line breaks every digest after it. This journal never
rewrites. Each entry carries the previous entry's digest and its own digest over the
canonical JSON of everything else, so ``verify()`` detects an edited, reordered or
truncated-in-the-middle record.

It is Node Alpha's *local journal*, not the canonical ledger. Records here are staged
for review and import on Node Beta; nothing in this module promotes anything.

Concurrency: a process-local lock plus ``fcntl.flock`` where the platform has it, held
across "read tail digest, write entry", so two daemons sharing a file cannot fork the
chain.
"""

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX host
    fcntl = None  # type: ignore[assignment]

__all__ = ["GENESIS", "canonical_json", "HashChainLedger"]

GENESIS = "0" * 64

# Fields the ledger writes itself; a caller's record may not pre-set them.
_RESERVED = ("seq", "prev_digest", "entry_digest")


def canonical_json(obj: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 preserved -- one byte string per value."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


@contextmanager
def _file_lock(fh: Any) -> Iterator[None]:
    if fcntl is None:
        yield
        return
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


def _last_line(fh: Any) -> Optional[bytes]:
    """Read the final non-empty line by seeking backwards, without loading the file."""
    fh.seek(0, os.SEEK_END)
    pos = fh.tell()
    buf = b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        fh.seek(pos)
        buf = fh.read(step) + buf
        stripped = buf.rstrip(b"\n")
        if b"\n" in stripped:
            return stripped.rsplit(b"\n", 1)[1]
    stripped = buf.rstrip(b"\n")
    return stripped or None


class HashChainLedger(object):
    """One JSON object per line; entry *n* commits to entry *n-1*."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Seal ``record`` onto the chain and return the sealed entry."""
        clash = [k for k in _RESERVED if k in record]
        if clash:
            raise ValueError("record may not set ledger-owned fields: %s" % ", ".join(clash))
        with self._lock, open(self.path, "a+b") as fh, _file_lock(fh):
            tail = _last_line(fh)
            if tail is None:
                seq, prev = 0, GENESIS
            else:
                last = json.loads(tail.decode("utf-8"))
                seq, prev = int(last["seq"]) + 1, str(last["entry_digest"])
            body = dict(record)
            body["seq"] = seq
            body["prev_digest"] = prev
            body["entry_digest"] = _digest(body)
            fh.seek(0, os.SEEK_END)
            fh.write((canonical_json(body) + "\n").encode("utf-8"))
            fh.flush()
            os.fsync(fh.fileno())
        return body

    def entries(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def head(self) -> str:
        """Digest of the newest entry, or ``GENESIS`` for an empty journal."""
        if not self.path.exists():
            return GENESIS
        with open(self.path, "rb") as fh:
            tail = _last_line(fh)
        return GENESIS if tail is None else str(json.loads(tail.decode("utf-8"))["entry_digest"])

    def verify(self) -> Tuple[bool, int, Optional[str]]:
        """Walk the whole chain. Returns ``(ok, entries_checked, first_problem)``."""
        prev = GENESIS
        count = 0
        try:
            rows = self.entries()
        except ValueError as exc:
            return False, 0, "unparseable line: %s" % exc
        for expected_seq, entry in enumerate(rows):
            sealed = entry.get("entry_digest")
            body = {k: v for k, v in entry.items() if k != "entry_digest"}
            if entry.get("seq") != expected_seq:
                return False, count, "seq %r at position %d" % (entry.get("seq"), expected_seq)
            if entry.get("prev_digest") != prev:
                return False, count, "broken link at seq %d" % expected_seq
            if _digest(body) != sealed:
                return False, count, "digest mismatch at seq %d" % expected_seq
            prev = str(sealed)
            count += 1
        return True, count, None

    def __len__(self) -> int:
        return len(self.entries())
