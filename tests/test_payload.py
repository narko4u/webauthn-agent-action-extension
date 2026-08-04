"""Payload schema tests — Section 4.2 of the txAuthAgent spec."""

import secrets

import pytest

from txauthagent.payload import (
    build_action_payload,
    payload_to_canonical_dict,
    validate_action_payload,
)

from helpers import contract_hash, make_payload


def test_build_valid_payload():
    p = make_payload()
    assert p["action_type"] == "contract.sign"
    assert p["agent_identity"]["aci_uri"].startswith("https://")


def test_missing_top_level_field():
    with pytest.raises(ValueError, match="action_id"):
        make_payload()
        del_payload = make_payload()
        del del_payload["action_id"]
        validate_action_payload(del_payload)


def test_invalid_action_type():
    with pytest.raises(ValueError, match="action_type"):
        validate_action_payload({"action_id": "x", "action_type": "Bad Type!", "agent_identity": {}, "action_descriptor": {}})


def test_missing_identity_field():
    p = make_payload()
    del p["agent_identity"]["agent_name"]
    with pytest.raises(ValueError, match="agent_name"):
        validate_action_payload(p)


def test_bad_aci_uri():
    p = make_payload()
    p["agent_identity"]["aci_uri"] = "ftp://not-http"
    with pytest.raises(ValueError, match="aci_uri"):
        validate_action_payload(p)


def test_contract_hash_prefix():
    p = make_payload()
    p["action_descriptor"]["contract_hash"] = "sha256:deadbeef"
    validate_action_payload(p)  # ok
    p["action_descriptor"]["contract_hash"] = "md5:deadbeef"
    with pytest.raises(ValueError, match="contract_hash"):
        validate_action_payload(p)


def test_short_nonce():
    p = make_payload()
    p["action_descriptor"]["nonce"] = "short"
    with pytest.raises(ValueError, match="nonce"):
        validate_action_payload(p)


def test_canonical_stable_and_sorted():
    p = make_payload()
    ca, cb = payload_to_canonical_dict(p), payload_to_canonical_dict(p)
    assert ca == cb
    # Deterministic CBOR sorts map keys, so the canonical dict must produce
    # byte-identical output regardless of encoder insertion order.
    from txauthagent import cbor

    sorted_keys = sorted(payload_to_canonical_dict(p).keys())
    raw = cbor.dumps(payload_to_canonical_dict(p), deterministic=True)
    # RFC 8949 §4.2.1 bytewise sort → shortest key ("prompt") first
    assert raw.startswith(b"\xa5\x66prompt")
    assert sorted_keys[0] == "action_descriptor"
    # canonical output keeps required fields
    assert "prompt" in ca
