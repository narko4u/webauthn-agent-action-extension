"""End-to-end tests — Section 7 of the txAuthAgent spec (v0.4).

Full lifecycle: registration (create attested signing key) → publish signing
public key → agent action signing ceremony → third-party verification.
Also cross-checks our deterministic CBOR against cbor2 (canonical=True) when
available — the interop anchor for the digest-as-tbs requirement.
"""

import hashlib

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from txauthagent import cbor
from txauthagent.cose import cose_key_to_pem
from txauthagent.digest import canonical_cbor, compute_action_digest
from txauthagent.extension import (
    ALG_EDDSA,
    ALG_ES256,
    EXTENSION_ID,
    SIGN_EXTENSION_ID,
    build_ceremony_input,
    build_registration_input,
    parse_profile_output,
)
from txauthagent.verify import (
    parse_sign_attestation,
    parse_sign_generated_key,
    verify_agent_action_cbor,
    verify_sign_attestation,
)
from txauthagent.virtual import VirtualAuthenticator

from helpers import make_payload

RP_ID = "empirelabs.com.au"


def _full_lifecycle(algorithm, algorithms):
    """Registration → publish → sign → verify for one algorithm."""
    auth = VirtualAuthenticator(algorithm=algorithm, rp_id=RP_ID)
    reg_output = auth.register(algorithms=algorithms)
    generated = parse_sign_generated_key(reg_output)
    published_pem = cose_key_to_pem(generated["publicKey"])

    payload = make_payload()
    blob = auth.sign_action_cbor(payload, tap=True)
    result = verify_agent_action_cbor(payload, blob, published_pem, expected_rp_id=RP_ID)
    return auth, generated, published_pem, payload, blob, result


def test_e2e_es256():
    auth, generated, pem, payload, blob, result = _full_lifecycle(ALG_ES256, [ALG_ES256])
    assert result.algorithm == ALG_ES256
    assert result.up is True
    assert result.action_digest == compute_action_digest(payload)
    # Full wire format survives the round trip
    outputs = cbor.loads(blob)
    assert parse_profile_output(outputs)["agent_cid"] == auth.credential_id


def test_e2e_eddsa():
    auth, generated, pem, payload, blob, result = _full_lifecycle(ALG_EDDSA, [ALG_EDDSA])
    assert result.algorithm == ALG_EDDSA
    assert len(parse_profile_output(cbor.loads(blob))["agent_action_sig"]) == 64


def test_e2e_attestation_chain():
    """The registration record binds the signing key and policy end-to-end."""
    auth = VirtualAuthenticator(rp_id=RP_ID, flags=1)
    reg_output = auth.register(algorithms=[ALG_ES256])
    generated = parse_sign_generated_key(reg_output)

    att = parse_sign_attestation(generated["attestationObject"])
    # Attested key == generated key == key we verify with
    assert cose_key_to_pem(att["signing_cose_key"]) == cose_key_to_pem(generated["publicKey"])
    assert att["sign_flags"] == 1

    payload = make_payload()
    blob = auth.sign_action_cbor(payload, tap=True)
    verify_agent_action_cbor(payload, blob, cose_key_to_pem(generated["publicKey"]), expected_rp_id=RP_ID)


def test_ceremony_input_wiring_e2e():
    """build_ceremony_input produces a tbs the authenticator signs unaltered."""
    auth = VirtualAuthenticator(rp_id=RP_ID)
    reg_output = auth.register(algorithms=[ALG_ES256])
    generated = parse_sign_generated_key(reg_output)
    payload = make_payload()

    from txauthagent.cose import decode_cose_key
    from txauthagent.extension import b64url_encode

    ceremony = build_ceremony_input(
        payload,
        {b64url_encode(auth.credential_id): auth.key_handle.cose_key_ref},
    )
    tbs = ceremony[SIGN_EXTENSION_ID]["sign"]["tbs"]
    assert tbs == compute_action_digest(payload)

    blob = auth.sign_action_cbor(payload, tap=True)
    record = parse_profile_output(cbor.loads(blob))
    # The signature is over exactly that tbs — recompute and verify.
    public_key, _ = decode_cose_key(generated["publicKey"])
    assert isinstance(public_key, ec.EllipticCurvePublicKey)  # ES256 registration
    public_key.verify(record["agent_action_sig"], tbs, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------- #
# Interop: our deterministic CBOR vs cbor2 (canonical=True)
# ---------------------------------------------------------------------- #

cbor2 = pytest.importorskip("cbor2")


def test_digest_payload_cbor_matches_cbor2_canonical():
    payload = make_payload()
    ours = canonical_cbor(payload)
    theirs = cbor2.dumps(payload, canonical=True)
    assert ours == theirs


def test_cose_key_matches_cbor2_canonical():
    auth = VirtualAuthenticator(rp_id=RP_ID)
    reg_output = auth.register(algorithms=[ALG_ES256])
    cose_bytes = parse_sign_generated_key(reg_output)["publicKey"]
    # Re-encoding the decoded map canonically must reproduce the bytes.
    assert cbor2.dumps(cbor.loads(cose_bytes), canonical=True) == cose_bytes


def test_extension_outputs_cbor_roundtrip_cbor2():
    auth = VirtualAuthenticator(rp_id=RP_ID)
    auth.register(algorithms=[ALG_ES256])
    blob = auth.sign_action_cbor(make_payload())
    # Our output must parse with cbor2 too (wire compatibility).
    decoded = cbor2.loads(blob)
    assert SIGN_EXTENSION_ID in decoded
    assert EXTENSION_ID in decoded
