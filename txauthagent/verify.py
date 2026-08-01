"""Agent action signature verification (Section 5.2 of the txAuthAgent spec).

Any relying party can verify a hardware-attested agent authorization WITHOUT
interacting with the agent:

1. Parse the extension output and confirm the CBOR shape.
2. Verify the signature over the recomputed canonical action digest using the
   credential's registered public key.
3. Confirm the RP id hash matches the expected relying party.
4. Confirm the `up` flag (physical gesture) is set.

The caller supplies the registered credential public key (from the WebAuthn
registration record) — this module never touches private material.
"""

from __future__ import annotations

from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from .digest import compute_action_digest
from .extension import ALG_EDDSA, ALG_ES256, parse_extension_output

__all__ = [
    "verify_agent_action",
    "verify_agent_action_cbor",
    "load_public_key_pem",
    "VerificationResult",
]

ALGORITHM_NAMES = {ALG_EDDSA: "EdDSA (Ed25519)", ALG_ES256: "ES256 (P-256)"}


class VerificationResult:
    """Result of a successful verification, with the checked fields."""

    def __init__(
        self,
        *,
        algorithm: int,
        rp_id_hash: bytes,
        up: bool,
        uv: bool,
        credential_id: bytes,
    ) -> None:
        self.algorithm = algorithm
        self.rp_id_hash = rp_id_hash
        self.up = up
        self.uv = uv
        self.credential_id = credential_id

    @property
    def algorithm_name(self) -> str:
        return ALGORITHM_NAMES.get(self.algorithm, f"COSE {self.algorithm}")

    def __repr__(self) -> str:
        return (
            f"VerificationResult(algorithm={self.algorithm_name}, up={self.up}, "
            f"uv={self.uv}, credential_id={self.credential_id.hex()[:16]}...)"
        )


def load_public_key_pem(pem: bytes, algorithm: int):
    """Load a SubjectPublicKeyInfo PEM into the right key object."""
    key = serialization.load_pem_public_key(pem)
    if algorithm == ALG_EDDSA:
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("algorithm EdDSA requires an Ed25519 public key")
        return key
    if algorithm == ALG_ES256:
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise ValueError("algorithm ES256 requires an EC public key")
        if key.curve.name != "secp256r1":
            raise ValueError("algorithm ES256 requires P-256 (secp256r1)")
        return key
    raise ValueError(f"unsupported algorithm: {algorithm}")


def verify_agent_action(
    payload: Dict[str, Any],
    extension_output: Dict[str, Any],
    public_key_pem: bytes,
    *,
    expected_rp_id: str | None = None,
) -> VerificationResult:
    """Verify a txAuthAgent extension output against a payload and public key.

    Raises ValueError on any verification failure. Returns a VerificationResult
    on success.
    """
    entry = parse_extension_output(extension_output)
    expected_digest = compute_action_digest(payload)
    public_key = load_public_key_pem(public_key_pem, entry["algorithm"])
    signature = entry["agent_action_sig"]

    try:
        if entry["algorithm"] == ALG_EDDSA:
            public_key.verify(signature, expected_digest)
        else:
            public_key.verify(signature, expected_digest, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("agent action signature verification failed") from exc

    if expected_rp_id is not None:
        import hashlib

        expected_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
        if entry["rp_id_hash"] != expected_hash:
            raise ValueError("rp_id_hash does not match expected relying party")

    if entry["flags"].get("up") is not True:
        raise ValueError("user presence flag (up) not set — no physical gesture")

    return VerificationResult(
        algorithm=entry["algorithm"],
        rp_id_hash=entry["rp_id_hash"],
        up=entry["flags"]["up"],
        uv=bool(entry["flags"].get("uv", False)),
        credential_id=entry["agent_cid"],
    )


def verify_agent_action_cbor(
    payload: Dict[str, Any],
    cbor_blob: bytes,
    public_key_pem: bytes,
    *,
    expected_rp_id: str | None = None,
) -> VerificationResult:
    """Verify a raw CBOR extension output blob (authenticator wire format)."""
    from .extension import decode_output_cbor

    outputs = decode_output_cbor(cbor_blob)
    return verify_agent_action(
        payload,
        outputs,
        public_key_pem,
        expected_rp_id=expected_rp_id,
    )
