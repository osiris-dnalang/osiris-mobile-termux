"""Control plane for the hinge-spine keys: allowlisted actions, idempotent by task id.

The keyboard's second channel. Tapping ``[1] Status`` sends a bounded ``IntentRequest``
instead of typing characters into whatever field has focus. Three rules:

* **Allowlist.** ``action_name`` must be a registered action. Anything else is refused
  before a handler is looked up; there is no path from this channel to a shell string.
* **Honest states.** Only read-only actions execute here. Actions that start compute
  answer ``REQUIRES_GRANT`` (they go through the SYS-021 grant path in
  ``android_bridge``), and actions without a handler on this node answer ``UNSUPPORTED``.
  Nothing reports ``EXECUTED`` that did not run.
* **Idempotency.** A retried ``task_id`` with the same body returns the cached result
  (``replayed: true``) instead of running again; the same ``task_id`` with a different
  body is a conflict, because that is either a client bug or a replay with edits.
"""

import hashlib
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple

from .ledger import canonical_json

__all__ = [
    "PROTOCOL_VERSION", "State", "Action", "ControlRejected", "TaskConflict",
    "TaskCache", "ControlPlane",
]

PROTOCOL_VERSION = "1.0"
INTENT_DISPATCH_CARD = "tui.dispatch_card"


class State(object):
    EXECUTED = "EXECUTED"
    REQUIRES_GRANT = "REQUIRES_GRANT"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"


class Action(object):
    HEALTH_CHECK = "health.check"
    LEDGER_VERIFY = "ledger.verify"
    NCLM_STATUS = "nclm.status"
    MENTOR_BENCHMARK = "mentor.benchmark"
    LEDGER_CHECK_ALL = "ledger.check_all"

    #: Safe to run on this channel: bounded, no side effects beyond a ledger line.
    READ_ONLY = (HEALTH_CHECK, LEDGER_VERIFY, NCLM_STATUS)
    #: Start sustained compute; refused here and routed through a payload-bound grant.
    NEEDS_GRANT = (MENTOR_BENCHMARK, LEDGER_CHECK_ALL)
    ALL = READ_ONLY + NEEDS_GRANT


class ControlRejected(ValueError):
    """Malformed, wrong-protocol or non-allowlisted control request."""


class TaskConflict(ValueError):
    """A ``task_id`` was reused with a different request body."""


class TaskCache(object):
    """Bounded, TTL-expiring map of ``task_id -> (request_digest, result)``."""

    def __init__(self, ttl_s: float = 900.0, max_items: int = 512,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl_s = ttl_s
        self.max_items = max_items
        self._clock = clock
        self._items: "OrderedDict[str, Tuple[float, str, Dict[str, Any]]]" = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        while self._items:
            key, (stamp, _, _) = next(iter(self._items.items()))
            if now - stamp <= self.ttl_s and len(self._items) <= self.max_items:
                break
            del self._items[key]

    def get(self, task_id: str, request_digest: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            self._prune(self._clock())
            hit = self._items.get(task_id)
            if hit is None:
                return None
            if hit[1] != request_digest:
                raise TaskConflict("task_id %s was already used with a different request" % task_id)
            return dict(hit[2])

    def put(self, task_id: str, request_digest: str, result: Dict[str, Any]) -> None:
        with self._lock:
            now = self._clock()
            self._items[task_id] = (now, request_digest, dict(result))
            self._items.move_to_end(task_id)
            self._prune(now)

    def __len__(self) -> int:
        return len(self._items)


def _validate(request: Dict[str, Any]) -> Tuple[str, str, str]:
    if request.get("protocol_version") != PROTOCOL_VERSION:
        raise ControlRejected("protocol_version must be %r" % PROTOCOL_VERSION)
    if request.get("intent") != INTENT_DISPATCH_CARD:
        raise ControlRejected("intent must be %r" % INTENT_DISPATCH_CARD)
    raw_id = request.get("task_id")
    try:
        task_id = str(uuid.UUID(str(raw_id)))
    except (TypeError, ValueError):
        raise ControlRejected("task_id must be a UUID")
    if task_id != raw_id:
        raise ControlRejected("task_id must be in canonical hyphenated form")
    params = request.get("parameters")
    if not isinstance(params, dict):
        raise ControlRejected("parameters must be an object")
    action = params.get("action_name")
    if action not in Action.ALL:
        raise ControlRejected("action_name %r is not allowlisted" % (action,))
    accelerator = params.get("accelerator", "")
    if not isinstance(accelerator, str) or len(accelerator) > 4:
        raise ControlRejected("accelerator must be a string of at most 4 characters")
    return task_id, action, accelerator


class ControlPlane(object):
    """Validates, deduplicates and answers control requests."""

    def __init__(self, handlers: Optional[Dict[str, Callable[[], Dict[str, Any]]]] = None,
                 cache: Optional[TaskCache] = None) -> None:
        unknown = set(handlers or ()) - set(Action.READ_ONLY)
        if unknown:
            raise ValueError("handlers may only be registered for read-only actions: %s"
                             % ", ".join(sorted(unknown)))
        self.handlers = dict(handlers or {})
        self.cache = cache if cache is not None else TaskCache()

    def dispatch(self, request: Dict[str, Any]) -> Dict[str, Any]:
        task_id, action, accelerator = _validate(request)
        digest = hashlib.sha256(canonical_json(request).encode("utf-8")).hexdigest()
        cached = self.cache.get(task_id, digest)
        if cached is not None:
            cached["replayed"] = True
            return cached

        result: Dict[str, Any] = {"task_id": task_id, "action_name": action,
                                  "accelerator": accelerator, "request_sha256": digest,
                                  "replayed": False}
        if action in Action.NEEDS_GRANT:
            result["state"] = State.REQUIRES_GRANT
            result["detail"] = "starts compute; submit through the payload-bound grant path"
        elif action not in self.handlers:
            result["state"] = State.UNSUPPORTED
            result["detail"] = "no handler registered for this action on this node"
        else:
            try:
                result["output"] = self.handlers[action]()
                result["state"] = State.EXECUTED
            except Exception as exc:  # a handler bug must not take the daemon down
                result["state"] = State.FAILED
                result["detail"] = type(exc).__name__
        self.cache.put(task_id, digest, result)
        return result
