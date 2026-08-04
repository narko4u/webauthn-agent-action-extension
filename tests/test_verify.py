"""Verification tests — Section 5.2 of the txAuthAgent spec (v0.4).

Any party can verify a hardware-attested agent authorization against the
published signing public key — the pairwise WebAuthn credential is never
involved. These tests exercise that property and its failure modes.
"""

import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

from txauthagent.cose import cose_key_to_pem
from txauthagent.digest import compute_action_digest
from txauthagent.extension import (
    ALG_EDDSA,
    ALG_ES256,
    EXTENSION_ID,
    SIGN_EXTENSION_ID,
)
from txauthagent.verify import (
    parse_sign_attestation,
    parse_sign_generated_key,
    verify_agent_action,
    verify_agent_action_cbor,
    verify_sign_attestation,
)
from txauthagent.virtual import VirtualAuthenticator

from helpers import make_payload

RP_ID = "empirelabs.com.au"


@pytest.fixture
def registered():
    """An authenticator registered under the standard RP, publishing its key."""
    auth = VirtualAuthenticator(rp_id=RP_ID)
    reg_output = auth.register(algorithms=[ALG_ES256])
    generated = parse_sign_generated_key(reg_output)
    return {
        "auth": auth,
        "pem": cose_key_to_pem(generated["publicKey"]),
        "attestation": generated["attestationObject"],
    }


def test_verify_happy_path(registered):
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    result = verify_agent_action(payload, outputs, registered["pem"], expected_rp_id=RP_ID)
    assert result.algorithm == ALG_ES256
    assert result.up is True
    assert result.uv is False
    assert result.action_digest == compute_action_digest(payload)
    assert result.credential_id == registered["auth"].credential_id


def test_verify_wire_format_cbor(registered):
    payload = make_payload()
    blob = registered["auth"].sign_action_cbor(payload)
    result = verify_agent_action_cbor(payload, blob, registered["pem"], expected_rp_id=RP_ID)
    assert result.credential_id == registered["auth"].credential_id


def test_tampered_payload_rejected(registered):
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    tampered = dict(payload)
    tampered["action_descriptor"] = dict(payload["action_descriptor"])
    tampered["action_descriptor"]["nonce"] = "attacker-chosen-nonce-0123456789abcdef"
    with pytest.raises(ValueError, match="action_digest"):
        verify_agent_action(tampered, outputs, registered["pem"], expected_rp_id=RP_ID)


def test_wrong_signing_key_rejected(registered):
    other = VirtualAuthenticator(rp_id=RP_ID)
    other.register(algorithms=[ALG_ES256])
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_agent_action(payload, outputs, other.public_key_pem, expected_rp_id=RP_ID)


def test_wrong_rp_id_rejected(registered):
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    with pytest.raises(ValueError, match="rp_id_hash"):
        verify_agent_action(payload, outputs, registered["pem"], expected_rp_id="evil.example")


def test_require_uv_enforced(registered):
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)  # uv=False
    with pytest.raises(ValueError, match="user verification"):
        verify_agent_action(payload, outputs, registered["pem"], require_uv=True)


def test_uv_verified_when_required():
    auth = VirtualAuthenticator(rp_id=RP_ID, flags=5)  # require-uv
    auth.register(algorithms=[ALG_ES256])
    payload = make_payload()
    outputs = auth.sign_action(payload, tap=True, user_verified=True)
    result = verify_agent_action(payload, outputs, auth.public_key_pem, require_uv=True)
    assert result.uv is True


def test_up_flag_must_be_set():
    auth = VirtualAuthenticator(rp_id=RP_ID, flags=0)  # unattended policy
    auth.register(algorithms=[ALG_ES256])
    payload = make_payload()
    outputs = auth.sign_action(payload, tap=False)
    with pytest.raises(ValueError, match="user presence"):
        verify_agent_action(payload, outputs, auth.public_key_pem)


def test_layering_disagreement_rejected(registered):
    """The raw sign signature must equal the txAuthAgent audit signature."""
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    bad = dict(outputs)
    bad[SIGN_EXTENSION_ID] = {"signature": b"\x00" * 64}
    with pytest.raises(ValueError, match="disagree"):
        verify_agent_action(payload, bad, registered["pem"])


def test_ed25519_verification():
    auth = VirtualAuthenticator(algorithm=ALG_EDDSA, rp_id=RP_ID)
    auth.register(algorithms=[ALG_EDDSA])
    payload = make_payload()
    outputs = auth.sign_action(payload)
    result = verify_agent_action(payload, outputs, auth.public_key_pem, expected_rp_id=RP_ID)
    assert result.algorithm == ALG_EDDSA
    assert result.algorithm_name == "EdDSA (Ed25519)"


def test_verify_does_not_need_the_credential(registered):
    """The entire verification path uses only the published signing key."""
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    # No credential public key, no RP secrets — just the published PEM.
    verify_agent_action(payload, outputs, registered["pem"], expected_rp_id=RP_ID)


# ---------------------------------------------------------------------- #
# Registration / attestation checks
# ---------------------------------------------------------------------- #


def test_parse_generated_key_requires_registration(registered):
    payload = make_payload()
    outputs = registered["auth"].sign_action(payload)
    with pytest.raises(ValueError, match="generatedKey"):
        parse_sign_generated_key(outputs)


def test_attestation_parses_and_binds_signing_key(registered):
    att = parse_sign_attestation(registered["attestation"])
    assert att["fmt"] == "packed"
    assert att["sign_flags"] == 1  # require-up policy
    assert att["rp_id_hash"] == hashlib.sha256(RP_ID.encode()).digest()
    # The attested key in authData must match the published signing key.
    assert cose_key_to_pem(att["signing_cose_key"]) == registered["pem"]
    # Empty credential id — the signing key is attested, not a credential.
    assert att["credential_id"] == b""
    assert att["aaguid"] == b"\x00" * 16  # software authenticator


def _registration_client_data_hash() -> bytes:
    """The exact clientDataHash the VirtualAuthenticator attested to."""
    import json

    from txauthagent.extension import b64url_encode

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64url_encode(b"txAuthAgent-registration"),
            "origin": "https://empirelabs.com.au",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(client_data_json).digest()


def test_attestation_signature_verifies_with_credential_key(registered):
    client_data_hash = _registration_client_data_hash()
    # Correct credential key + correct hash → passes
    parsed = verify_sign_attestation(
        registered["attestation"],
        registered["auth"].credential_public_key_pem,
        expected_rp_id=RP_ID,
        client_data_hash=client_data_hash,
    )
    assert parsed["fmt"] == "packed"
    # Wrong credential key → fails
    other = VirtualAuthenticator(rp_id=RP_ID)
    other.register(algorithms=[ALG_ES256])
    with pytest.raises(ValueError, match="attestation signature"):
        verify_sign_attestation(
            registered["attestation"],
            other.credential_public_key_pem,
            client_data_hash=client_data_hash,
        )
    # Wrong client data hash → fails
    with pytest.raises(ValueError, match="attestation signature"):
        verify_sign_attestation(
            registered["attestation"],
            registered["auth"].credential_public_key_pem,
            client_data_hash=hashlib.sha256(b"wrong-client-data").digest(),
        )
    # Wrong RP id → fails
    with pytest.raises(ValueError, match="rp_id_hash"):
        verify_sign_attestation(
            registered["attestation"],
            registered["auth"].credential_public_key_pem,
            expected_rp_id="evil.example",
            client_data_hash=client_data_hash,
        )
