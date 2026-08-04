"""Minimal COSE_Key codec for the txAuthAgent profile (RFC 9052/9053 subset).

The ``sign`` extension returns the generated signing public key as a COSE_Key
structure and the reference implementation's registration record carries that
same structure. This module encodes/decodes the two key types FIDO2 hardware
supports for signing:

- EC2 (kty=2) P-256 / ES256 (COSE alg -7) — YubiKey 5, Ledger FIDO2 app,
  Nitrokey 3
- OKP (kty=1) Ed25519 / EdDSA (COSE alg -8) — Nitrokey 3, newer devices

It also converts COSE_Key bytes to/from the PEM SubjectPublicKeyInfo form used
by the verifier (``verify.py``).

Note: RFC 9053 COSE_Key label constants — kty=1, kid=2, alg=3, crv=-1, x=-2,
y=-3; key types: OKP=1, EC2=2; curves: P-256=1, Ed25519=6.
"""

from __future__ import annotations

from typing import Any, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from .extension import ALG_EDDSA, ALG_ES256

__all__ = [
    "encode_cose_key",
    "decode_cose_key",
    "cose_key_to_pem",
    "COSE_KEY_KTY_EC2",
    "COSE_KEY_KTY_OKP",
    "COSE_KEY_CRV_P256",
    "COSE_KEY_CRV_ED25519",
]

# RFC 9053 labels
COSE_KEY_KTY_EC2 = 2
COSE_KEY_KTY_OKP = 1
COSE_KEY_CRV_P256 = 1
COSE_KEY_CRV_ED25519 = 6


def _public_bytes(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def encode_cose_key(public_key, algorithm: int) -> bytes:
    """Encode a cryptography public-key object as a COSE_Key byte string.

    Args:
        public_key: An ``Ed25519PublicKey`` or ``EllipticCurvePublicKey``
            (P-256 only) instance.
        algorithm: COSE algorithm identifier (ALG_EDDSA or ALG_ES256) — used
            to disambiguate key types and set the COSE ``alg`` label.
    """
    if algorithm == ALG_EDDSA:
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("algorithm EdDSA requires an Ed25519 public key")
        x = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        cose_key: Dict[int, Any] = {
            1: COSE_KEY_KTY_OKP,
            3: algorithm,
            -1: COSE_KEY_CRV_ED25519,
            -2: x,
        }
        # COSE_Key maps are canonical: sort by deterministic key encoding.
        from .cbor import dumps

        return dumps(cose_key, deterministic=True)

    if algorithm == ALG_ES256:
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("algorithm ES256 requires an EC public key")
        if public_key.curve.name != "secp256r1":
            raise ValueError("algorithm ES256 requires P-256 (secp256r1)")
        numbers = public_key.public_numbers()
        x_len = (public_key.curve.key_size + 7) // 8
        cose_key: Dict[int, Any] = {
            1: COSE_KEY_KTY_EC2,
            3: algorithm,
            -1: COSE_KEY_CRV_P256,
            -2: numbers.x.to_bytes(x_len, "big"),
            -3: numbers.y.to_bytes(x_len, "big"),
        }
        from .cbor import dumps

        return dumps(cose_key, deterministic=True)

    raise ValueError(f"unsupported algorithm: {algorithm}")


def decode_cose_key(blob: bytes):
    """Decode a COSE_Key byte string into a cryptography public-key object."""
    from .cbor import loads

    key = loads(blob)
    if not isinstance(key, dict):
        raise ValueError("COSE_Key must be a CBOR map")

    kty = key.get(1)
    alg = key.get(3)
    if kty == COSE_KEY_KTY_OKP and key.get(-1) == COSE_KEY_CRV_ED25519:
        x = key.get(-2)
        if not isinstance(x, bytes) or len(x) != 32:
            raise ValueError("invalid Ed25519 COSE_Key: x must be 32 bytes")
        return ed25519.Ed25519PublicKey.from_public_bytes(x), ALG_EDDSA
    if kty == COSE_KEY_KTY_EC2 and key.get(-1) == COSE_KEY_CRV_P256:
        x = key.get(-2)
        y = key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise ValueError("invalid P-256 COSE_Key: x/y must be bytes")
        x_int = int.from_bytes(x, "big")
        y_int = int.from_bytes(y, "big")
        return (
            ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1()).public_key(),
            ALG_ES256,
        )
    raise ValueError(f"unsupported COSE_Key (kty={kty}, crv={key.get(-1)}, alg={alg})")


def cose_key_to_pem(cose_blob: bytes) -> bytes:
    """Convert COSE_Key bytes to SubjectPublicKeyInfo PEM (for verify.py)."""
    public_key, _ = decode_cose_key(cose_blob)
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
