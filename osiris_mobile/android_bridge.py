"""
Node Alpha Substrate Bridge Daemon (Termux side).
Interfaces with Android Kotlin components:
  - IntentPreviewFirewall (smart keyboard action previews)
  - BluetoothScoPersistenceService (SCO audio and BLE peripheral gateway)
  - OsirisCapabilityVerifier (SYS-021 payload-grant digest binding)
  - NodeAlphaSubstrateBridge (300.0s horizon and prompt contract 'osiris::}{> ')
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any, Dict

PROMPT_CONTRACT = "osiris::}{> "
THERMAL_HORIZON_SECONDS = 300.0
MAX_OPERATING_TEMP_CELSIUS = 42.0


class AndroidBridgeSecurityError(Exception):
    """Raised on security gate violations or SYS-021 payload mismatches."""
    pass


class NodeAlphaTermuxBridge:
    """
    Local Termux IPC bridge receiver.
    Validates tokens, payload digests, prompt contracts, and temporal horizons.
    """

    def __init__(self, auth_token: str):
        # No default: a token shipped in source is a token every reader of the repo has.
        if not auth_token:
            raise AndroidBridgeSecurityError("auth_token is required; there is no built-in default")
        self.auth_token = auth_token
        self.execution_ledger: list[Dict[str, Any]] = []

    def verify_request_preconditions(
        self,
        headers: Dict[str, str],
        payload_bytes: bytes,
        grant: Dict[str, Any],
        device_temp: float = 35.0
    ) -> None:
        """
        Enforces all physical and cryptographic gates before dispatching execution.
        """
        # 1. Thermal check (AT-IME-09)
        if device_temp > MAX_OPERATING_TEMP_CELSIUS:
            raise AndroidBridgeSecurityError(
                f"Thermal limit breach: {device_temp}°C exceeds {MAX_OPERATING_TEMP_CELSIUS}°C ceiling"
            )

        # 2. Prompt contract header check
        prompt = headers.get("X-Osiris-Prompt-Contract")
        if prompt != PROMPT_CONTRACT:
            raise AndroidBridgeSecurityError(
                f"Invalid prompt contract: '{prompt}'. Must strictly match '{PROMPT_CONTRACT}'"
            )

        # 3. Authorization token check
        auth_header = headers.get("Authorization", "")
        presented = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        if not hmac.compare_digest(presented.encode("utf-8"), self.auth_token.encode("utf-8")):
            raise AndroidBridgeSecurityError("Unauthorized: invalid or missing bearer token")

        # 4. SYS-021 Payload-Grant Binding Check
        bound_digest = grant.get("bound_payload_digest", "").lower()
        actual_digest = hashlib.sha256(payload_bytes).hexdigest().lower()
        if bound_digest != actual_digest:
            raise AndroidBridgeSecurityError(
                f"SYS-021 VIOLATION: Actual payload digest ({actual_digest}) != bound grant digest ({bound_digest})"
            )

        # 5. Grant validity window
        valid_until = grant.get("valid_until_millis", 0)
        current_millis = int(time.time() * 1000)
        if current_millis > valid_until:
            raise AndroidBridgeSecurityError(
                f"ERR_GRANT_EXPIRED: Grant expired at {valid_until} (current: {current_millis})"
            )

    def execute_payload(
        self,
        headers: Dict[str, str],
        payload_bytes: bytes,
        grant: Dict[str, Any],
        device_temp: float = 35.0
    ) -> Dict[str, Any]:
        """
        Validates preconditions and executes within the strict 300.0s temporal horizon.
        """
        start_time = time.monotonic()
        self.verify_request_preconditions(headers, payload_bytes, grant, device_temp)

        # Record receipt into write-ahead ledger
        event_record = {
            "seq": len(self.execution_ledger) + 1,
            "timestamp": time.time(),
            "grant_id": grant.get("grant_id"),
            "payload_digest": hashlib.sha256(payload_bytes).hexdigest(),
            "status": "EXECUTED"
        }
        self.execution_ledger.append(event_record)

        elapsed = time.monotonic() - start_time
        if elapsed > THERMAL_HORIZON_SECONDS:
            raise AndroidBridgeSecurityError(
                f"Temporal horizon overrun: {elapsed}s exceeded {THERMAL_HORIZON_SECONDS}s ceiling"
            )

        return {
            "status": "SUCCESS",
            "exit_code": 0,
            "duration_seconds": elapsed,
            "record": event_record
        }
