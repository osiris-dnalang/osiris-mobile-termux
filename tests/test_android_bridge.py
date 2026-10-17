"""
Unit tests for the Node Alpha Android-Termux Bridge and physical substrate invariants.
Verifies:
  - PROMPT_CONTRACT ('osiris::}{> ')
  - THERMAL_HORIZON_SECONDS (300.0s)
  - MAX_OPERATING_TEMP_CELSIUS (42.0°C)
  - SYS-021 cryptographic payload-grant digest binding
  - Grant expiration and bearer token authentication
"""

import hashlib
import time

import pytest

from osiris_mobile.android_bridge import (
    MAX_OPERATING_TEMP_CELSIUS,
    PROMPT_CONTRACT,
    THERMAL_HORIZON_SECONDS,
    AndroidBridgeSecurityError,
    NodeAlphaTermuxBridge,
)


@pytest.fixture
def bridge():
    return NodeAlphaTermuxBridge(auth_token="test-secret-token")


@pytest.fixture
def valid_grant():
    payload = b"quantum-ast-payload-bytes"
    digest = hashlib.sha256(payload).hexdigest()
    valid_until = int((time.time() + 300) * 1000)
    return {
        "grant_id": "GRANT-W8L-002",
        "bound_payload_digest": digest,
        "valid_until_millis": valid_until,
    }


def test_bridge_constants():
    assert PROMPT_CONTRACT == "osiris::}{> "
    assert THERMAL_HORIZON_SECONDS == 300.0
    assert MAX_OPERATING_TEMP_CELSIUS == 42.0


def test_valid_request_execution(bridge, valid_grant):
    payload = b"quantum-ast-payload-bytes"
    headers = {
        "Authorization": "Bearer test-secret-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    result = bridge.execute_payload(headers, payload, valid_grant, device_temp=36.5)
    assert result["status"] == "SUCCESS"
    assert result["exit_code"] == 0
    assert len(bridge.execution_ledger) == 1
    assert bridge.execution_ledger[0]["grant_id"] == "GRANT-W8L-002"


def test_thermal_overrun_rejection(bridge, valid_grant):
    payload = b"quantum-ast-payload-bytes"
    headers = {
        "Authorization": "Bearer test-secret-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    # Device temperature over 42°C ceiling
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, payload, valid_grant, device_temp=43.2)
    assert "Thermal limit breach" in str(exc_info.value)


def test_prompt_contract_mismatch_rejection(bridge, valid_grant):
    payload = b"quantum-ast-payload-bytes"
    headers = {
        "Authorization": "Bearer test-secret-token",
        "X-Osiris-Prompt-Contract": "bash$ ",  # Invalid prompt
    }
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, payload, valid_grant, device_temp=35.0)
    assert "Invalid prompt contract" in str(exc_info.value)


def test_unauthorized_token_rejection(bridge, valid_grant):
    payload = b"quantum-ast-payload-bytes"
    headers = {
        "Authorization": "Bearer bad-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, payload, valid_grant, device_temp=35.0)
    assert "Unauthorized" in str(exc_info.value)


def test_sys021_payload_tamper_rejection(bridge, valid_grant):
    # Altered payload
    tampered_payload = b"quantum-ast-payload-bytes-MUTATED"
    headers = {
        "Authorization": "Bearer test-secret-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, tampered_payload, valid_grant, device_temp=35.0)
    assert "SYS-021 VIOLATION" in str(exc_info.value)


def test_grant_expired_rejection(bridge):
    payload = b"payload"
    digest = hashlib.sha256(payload).hexdigest()
    expired_grant = {
        "grant_id": "GRANT-EXPIRED",
        "bound_payload_digest": digest,
        "valid_until_millis": int((time.time() - 10) * 1000),  # Expired 10s ago
    }
    headers = {
        "Authorization": "Bearer test-secret-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, payload, expired_grant, device_temp=35.0)
    assert "ERR_GRANT_EXPIRED" in str(exc_info.value)


def test_bridge_requires_explicit_token():
    with pytest.raises(AndroidBridgeSecurityError):
        NodeAlphaTermuxBridge(auth_token="")
    with pytest.raises(TypeError):
        NodeAlphaTermuxBridge()


def test_missing_bearer_prefix_rejected(bridge, valid_grant):
    headers = {
        "Authorization": "test-secret-token",
        "X-Osiris-Prompt-Contract": PROMPT_CONTRACT,
    }
    with pytest.raises(AndroidBridgeSecurityError) as exc_info:
        bridge.execute_payload(headers, b"quantum-ast-payload-bytes", valid_grant, device_temp=35.0)
    assert "Unauthorized" in str(exc_info.value)
