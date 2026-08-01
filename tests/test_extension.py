"""Extension wire format tests — Sections 4 & 5 of the spec."""

import pytest

from txauthagent import cbor
from txauthagent.extension import (
    ALG_EDDSA,
    EXTENSION_ID,
    build_extension_input,
    build_extension_output,
    decode_output_cbor,
    encode_output_cbor,
    parse_extension_output,
)


def test_extension_input_registration_shape():
    ext = build_extension_input(
        agent_identity={"aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
                        "agent_name": "Sovereign"},
        challenge="QSef74gcLRf8amSn8nwFR7v4C9Z1Cl0n",
    )
    assert EXTENSION_ID in ext
    assert "action" not in ext[EXTENSION_ID]
    assert ext[EXTENSION_ID]["challenge"] == "QSef74gcLRf8amSn8nwFR7v4C9Z1Cl0n"


def test_extension_input_auth_shape():
    ext = build_extension_input(
        agent_identity={"aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
                        "agent_name": "Sovereign"},
        action={"action_id": "01JSDXQZ3MV8YR9K5WPHKE7N12", "action_type": "contract.sign"},
        prompt="Sign?",
    )
    assert EXTENSION_ID in ext
    assert ext[EXTENSION_ID]["action"]["action_type"] == "contract.sign"
    assert ext[EXTENSION_ID]["prompt"] == "Sign?"


def test_extension_output_roundtrip_cbor():
    entry = build_extension_output(
        agent_action_sig=b"\x01\x02\x03",
        agent_cid=b"\xaa\xbb",
        algorithm=ALG_EDDSA,
        rp_id_hash=b"\x00" * 32,
        up=True,
        uv=False,
    )
    blob = encode_output_cbor({EXTENSION_ID: entry})
    decoded = decode_output_cbor(blob)
    assert decoded[EXTENSION_ID]["agent_action_sig"] == b"\x01\x02\x03"
    assert decoded[EXTENSION_ID]["flags"]["up"] is True


def test_output_parse_missing_extension():
    with pytest.raises(ValueError, match="not present"):
        parse_extension_output({"otherExt": {}})


def test_output_parse_bad_algorithm():
    entry = build_extension_output(
        agent_action_sig=b"x", agent_cid=b"y", algorithm=123, rp_id_hash=b"\x00" * 32, up=True
    )
    with pytest.raises(ValueError, match="unsupported algorithm"):
        parse_extension_output({EXTENSION_ID: entry})


def test_output_parse_missing_flag():
    entry = build_extension_output(
        agent_action_sig=b"x", agent_cid=b"y", algorithm=ALG_EDDSA,
        rp_id_hash=b"\x00" * 32, up=True,
    )
    del entry["flags"]["up"]
    with pytest.raises(ValueError, match="flags"):
        parse_extension_output({EXTENSION_ID: entry})


def test_cbor_is_canonical_wire_format():
    # The spec says output is CBOR — prove the blob is CBOR-parseable
    entry = build_extension_output(
        agent_action_sig=b"\x01", agent_cid=b"\x02", algorithm=ALG_EDDSA,
        rp_id_hash=b"\x00" * 32, up=True,
    )
    blob = encode_output_cbor({EXTENSION_ID: entry})
    assert cbor.loads(blob)[EXTENSION_ID]["agent_cid"] == b"\x02"
