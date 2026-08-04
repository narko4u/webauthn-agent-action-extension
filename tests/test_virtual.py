"""Virtual authenticator tests — Section 6 of the spec (software stand-in)."""

import pytest

from txauthagent.extension import ALG_EDDSA, ALG_ES256, EXTENSION_ID, decode_output_cbor
from txauthagent.virtual import VirtualAuthenticator, generate_credential_id

from helpers import make_payload


def test_es256_is_default_algorithm():
    key = VirtualAuthenticator()
    assert key.algorithm == ALG_ES256
    blob = key.sign_action_cbor(make_payload())
    entry = decode_output_cbor(blob)[EXTENSION_ID]
    assert entry["algorithm"] == ALG_ES256
    assert len(entry["agent_action_sig"]) in (64, 70, 71, 72)  # DER-encoded ECDSA


def test_eddsa_signing_produces_extension_output():
    key = VirtualAuthenticator(algorithm=ALG_EDDSA)
    blob = key.sign_action_cbor(make_payload())
    outputs = decode_output_cbor(blob)
    entry = outputs[EXTENSION_ID]
    assert entry["algorithm"] == ALG_EDDSA
    assert entry["flags"]["up"] is True
    assert len(entry["agent_action_sig"]) == 64  # Ed25519 sig size


def test_es256_signing():
    key = VirtualAuthenticator(algorithm=ALG_ES256)
    blob = key.sign_action_cbor(make_payload())
    entry = decode_output_cbor(blob)[EXTENSION_ID]
    assert entry["algorithm"] == ALG_ES256
    assert len(entry["agent_action_sig"]) in (64, 70, 71, 72)  # DER-encoded ECDSA


def test_tap_required():
    key = VirtualAuthenticator()
    with pytest.raises(ValueError, match="tap"):
        key.sign_action(make_payload(), tap=False)


def test_rp_id_hash_is_sha256():
    import hashlib
    key = VirtualAuthenticator(rp_id="empirelabs.com.au")
    entry = key.sign_action(make_payload())
    assert entry["rp_id_hash"] == hashlib.sha256(b"empirelabs.com.au").digest()


def test_uv_flag_optional():
    key = VirtualAuthenticator()
    entry = key.sign_action(make_payload(), user_verified=True)
    assert entry["flags"]["uv"] is True
    entry2 = key.sign_action(make_payload(), user_verified=False)
    assert entry2["flags"]["uv"] is False


def test_credential_id_generation():
    cid = generate_credential_id()
    assert isinstance(cid, bytes)
    assert len(cid) == 32


def test_public_key_pem():
    key = VirtualAuthenticator()
    pem = key.public_key_pem
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
