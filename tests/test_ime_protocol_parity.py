"""Keep the Python daemon and the Kotlin keyboard on one wire contract.

The golden vectors are repeated in ImeBridgeProtocolTest.kt; the allowlists are read
straight out of ImeBridgeProtocol.kt, so drift on either side fails here.
"""

import re
from pathlib import Path

from osiris_mobile.ime.clipboard import LLM_HOSTS
from osiris_mobile.ime.control import PROTOCOL_VERSION, Action
from osiris_mobile.ime.server import DEFAULT_PORT, sign_reply, sign_request

KT = (Path(__file__).resolve().parent.parent / "android" / "app" / "src" / "main" / "kotlin"
      / "ai" / "osiris" / "android" / "ime" / "ImeBridgeProtocol.kt")

KEY = bytes(range(32))
BODY = b'{"a":1}'


def _kotlin_set(name):
    match = re.search(r"val %s: Set<String> = setOf\((.*?)\)" % name, KT.read_text(encoding="utf-8"), re.S)
    assert match, "%s not found in %s" % (name, KT.name)
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def _kotlin_const(name):
    match = re.search(r"const val %s = (\S+)" % name, KT.read_text(encoding="utf-8"))
    assert match, name
    return match.group(1).strip('"')


def test_request_signature_golden_vector():
    assert sign_request(KEY, "post", "/v1/control/dispatch", 1792103040000, BODY) == \
        "v1=85e7d70df2d953abe96f49f4c06b547d6ee8cbe1dbeeee46df5d8d12ac2efa87"


def test_reply_signature_golden_vector():
    assert sign_reply(KEY, BODY) == "v1=b4cebde30982443ec36c18fa99ad10a70e705bba779f57c37e84decb64ae50fb"


def test_allowlists_match_kotlin():
    assert _kotlin_set("ALLOWED_ACTIONS") == set(Action.ALL)
    assert _kotlin_set("LLM_HOSTS") == set(LLM_HOSTS)


def test_constants_match_kotlin():
    assert _kotlin_const("PROTOCOL_VERSION") == PROTOCOL_VERSION
    assert int(_kotlin_const("DEFAULT_PORT")) == DEFAULT_PORT
