"""Extension wire format tests — Sections 4 & 5 of the txAuthAgent spec (v0.4).

Covers the client inputs (registration + authentication ceremonies) and the
combined client outputs (``sign`` extension result + txAuthAgent audit record).
"""

import pytest

from txauthagent import cbor
from txauthagent.digest import compute_action_digest
from txauthagent.extension import (
    ALG_EDDSA,
    ALG_ES256,
    EXTENSION_ID,
    FLAG_REQUIRE_UP,
    FLAG_REQUIRE_UV,
    PROFILE_TAG,
    SIGN_EXTENSION_ID,
    b64url_decode,
    b64url_encode,
    build_ceremony_input,
    build_profile_output,
    build_registration_input,
    decode_output_cbor,
    encode_output_cbor,
    parse_profile_output,
    parse_sign_output,
)

from helpers import make_payload

AGENT_IDENTITY = {
    "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
    "agent_name": "Sovereign",
}


def test_registration_input_shape():
    ext = build_registration_input(AGENT_IDENTITY, algorithms=[ALG_ES256])
    # sign extension generateKey input
    assert SIGN_EXTENSION_ID in ext
    assert "generateKey" in ext[SIGN_EXTENSION_ID]
    gen = ext[SIGN_EXTENSION_ID]["generateKey"]
    assert gen["algorithms"] == [ALG_ES256]
    assert "tbs" not in gen  # profile signs at authentication, not registration
    # txAuthAgent profile context
    assert ext[EXTENSION_ID]["profile"] == PROFILE_TAG
    assert ext[EXTENSION_ID]["agent_identity"] == AGENT_IDENTITY


def test_registration_input_default_algorithms():
    ext = build_registration_input(AGENT_IDENTITY)
    assert ext[SIGN_EXTENSION_ID]["generateKey"]["algorithms"] == [ALG_ES256, ALG_EDDSA]


def test_ceremony_input_tbs_is_canonical_digest():
    payload = make_payload()
    ext = build_ceremony_input(payload, {"abc": b"\x01\x02\x03"})
    sign_in = ext[SIGN_EXTENSION_ID]["sign"]
    assert sign_in["tbs"] == compute_action_digest(payload)
    assert sign_in["keyHandleByCredential"] == {"abc": b"\x01\x02\x03"}
    assert ext[EXTENSION_ID]["action"] == payload
    assert ext[EXTENSION_ID]["profile"] == PROFILE_TAG


def test_profile_output_shape():
    out = build_profile_output(
        signature=b"\x30" * 64,
        action_digest=b"\xab" * 32,
        agent_cid=b"credential-id",
        algorithm=ALG_ES256,
        rp_id_hash=b"\xcd" * 32,
        up=True,
        uv=False,
    )
    assert out["algorithm"] == ALG_ES256
    assert out["flags"] == {"up": True, "uv": False}
    parsed = parse_profile_output({EXTENSION_ID: out})
    assert parsed["action_digest"] == b"\xab" * 32


def test_parse_sign_output_requires_sign_extension():
    with pytest.raises(ValueError, match="sign"):
        parse_sign_output({})
    with pytest.raises(ValueError, match="sign"):
        parse_sign_output({"txAuthAgent": {}})


def test_parse_sign_output_validation():
    # signature must be bytes
    with pytest.raises(ValueError, match="bytes"):
        parse_sign_output({SIGN_EXTENSION_ID: {"signature": "not-bytes"}})
    # generatedKey shape for registration
    gen = parse_sign_output({SIGN_EXTENSION_ID: {"generatedKey": {"publicKey": b"cose"}}})
    assert gen["generatedKey"]["publicKey"] == b"cose"


def test_parse_profile_output_validation():
    base = dict(
        agent_action_sig=b"\x30" * 64,
        action_digest=b"\xab" * 32,
        agent_cid=b"cid",
        algorithm=ALG_ES256,
        rp_id_hash=b"\xcd" * 32,
        flags={"up": True, "uv": False},
    )
    parse_profile_output({EXTENSION_ID: base})  # ok
    bad = dict(base)
    del bad["action_digest"]
    with pytest.raises(ValueError, match="action_digest"):
        parse_profile_output({EXTENSION_ID: bad})
    bad = dict(base)
    bad["action_digest"] = b"short"
    with pytest.raises(ValueError, match="32 bytes"):
        parse_profile_output({EXTENSION_ID: bad})
    bad = dict(base)
    bad["algorithm"] = 999
    with pytest.raises(ValueError, match="algorithm"):
        parse_profile_output({EXTENSION_ID: bad})
    bad = dict(base)
    bad["flags"] = {"uv": False}  # missing up
    with pytest.raises(ValueError, match="up"):
        parse_profile_output({EXTENSION_ID: bad})


def test_b64url_roundtrip():
    for raw in (b"", b"a", b"\x00\xff\x10", b"credential id bytes\x00"):
        assert b64url_decode(b64url_encode(raw)) == raw
    # WebAuthn identifiers are unpadded
    assert "=" not in b64url_encode(b"\xfb\xff")


def test_cbor_output_roundtrip_with_bytes():
    entry = {
        SIGN_EXTENSION_ID: {"signature": b"\x30" * 64},
        EXTENSION_ID: build_profile_output(
            signature=b"\x30" * 64,
            action_digest=b"\xab" * 32,
            agent_cid=b"cid",
            algorithm=ALG_ES256,
            rp_id_hash=b"\xcd" * 32,
            up=True,
            uv=False,
        ),
    }
    blob = encode_output_cbor(entry)
    decoded = decode_output_cbor(blob)
    assert decoded == entry
    assert isinstance(decoded[SIGN_EXTENSION_ID]["signature"], bytes)


def test_policy_flag_constants():
    assert FLAG_REQUIRE_UP & 0b001
    assert FLAG_REQUIRE_UV & 0b001 and FLAG_REQUIRE_UV & 0b100
