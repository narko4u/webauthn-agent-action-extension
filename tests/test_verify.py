"""Verification tests — Section 5.2 of the spec (relying-party side)."""

import pytest

from txauthagent.extension import ALG_EDDSA, ALG_ES256, EXTENSION_ID
from txauthagent.verify import (
    VerificationResult,
    verify_agent_action,
    verify_agent_action_cbor,
)
from txauthagent.virtual import VirtualAuthenticator

from helpers import make_payload


def test_verify_happy_path():
    key = VirtualAuthenticator(rp_id="empirelabs.com.au")
    payload = make_payload()
    result = verify_agent_action_cbor(payload, key.sign_action_cbor(payload),
                                      key.public_key_pem,
                                      expected_rp_id="empirelabs.com.au")
    assert isinstance(result, VerificationResult)
    assert result.up is True
    assert result.algorithm == ALG_ES256  # default algorithm


def test_verify_es256():
    key = VirtualAuthenticator(algorithm=ALG_ES256)
    payload = make_payload()
    result = verify_agent_action_cbor(payload, key.sign_action_cbor(payload),
                                      key.public_key_pem)
    assert result.algorithm == ALG_ES256


def test_verify_tampered_payload_fails():
    key = VirtualAuthenticator()
    payload = make_payload()
    blob = key.sign_action_cbor(payload)
    tampered = dict(payload)
    tampered["action_descriptor"] = dict(payload["action_descriptor"])
    tampered["action_descriptor"]["contract_hash"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_agent_action_cbor(tampered, blob, key.public_key_pem)


def test_verify_wrong_key_fails():
    key1, key2 = VirtualAuthenticator(), VirtualAuthenticator()
    payload = make_payload()
    blob = key1.sign_action_cbor(payload)
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_agent_action_cbor(payload, blob, key2.public_key_pem)


def test_verify_rp_mismatch_fails():
    key = VirtualAuthenticator(rp_id="empirelabs.com.au")
    payload = make_payload()
    with pytest.raises(ValueError, match="rp_id_hash"):
        verify_agent_action_cbor(payload, key.sign_action_cbor(payload),
                                 key.public_key_pem,
                                 expected_rp_id="evil.example.com")


def test_verify_without_rp_check_ok():
    key = VirtualAuthenticator()
    payload = make_payload()
    result = verify_agent_action_cbor(payload, key.sign_action_cbor(payload),
                                      key.public_key_pem)
    assert result.up is True


def test_verify_output_dict_directly():
    key = VirtualAuthenticator()
    payload = make_payload()
    entry = key.sign_action(payload)
    outputs = {EXTENSION_ID: entry}
    result = verify_agent_action(payload, outputs, key.public_key_pem)
    assert result.credential_id == key.credential_id


def test_verify_rejects_non_bytes_signature():
    key = VirtualAuthenticator()
    payload = make_payload()
    entry = key.sign_action(payload)
    entry["agent_action_sig"] = "not-bytes"
    with pytest.raises(ValueError, match="bytes"):
        verify_agent_action(payload, {EXTENSION_ID: entry}, key.public_key_pem)
