"""Agent action signature verification (Section 5.2 of the txAuthAgent spec, v0.4).

Any relying party — or independent auditor, regulator or counterparty — can
verify a hardware-attested agent authorization WITHOUT interacting with the
agent and WITHOUT any secret validation server:

1. Recompute the canonical action digest from the action payload.
2. Verify the raw signature (the ``sign`` extension output) against the
   *signing public key* published at registration — never the pairwise
   WebAuthn credential. This is the property that keeps the design compatible
   with WebAuthn's core privacy feature: credentials are pairwise to the RP
   that created them, so third-party verification must use the separate,
   attested signing key the ``sign`` extension provides.
3. Confirm the RP id hash matches the expected relying party.
4. Confirm the user-presence flag (physical gesture) is set; optionally
   require user verification (PIN/biometric) for high-value actions.

The caller supplies the signing public key (from the registration record —
e.g. the ``generatedKey.publicKey`` COSE_Key converted via
``cose_key_to_pem``). This module never touches private material.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from . import cbor
from .digest import compute_action_digest
from .extension import (
    ALG_EDDSA,
    ALG_ES256,
    EXTENSION_ID,
    SIGN_EXTENSION_ID,
    parse_profile_output,
    parse_sign_output,
)

__all__ = [
    "verify_agent_action",
    "verify_agent_action_cbor",
    "load_public_key_pem",
    "parse_sign_generated_key",
    "parse_sign_attestation",
    "verify_sign_attestation",
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
        action_digest: bytes,
    ) -> None:
        self.algorithm = algorithm
        self.rp_id_hash = rp_id_hash
        self.up = up
        self.uv = uv
        self.credential_id = credential_id
        self.action_digest = action_digest

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
    extension_outputs: Dict[str, Any],
    signing_public_key_pem: bytes,
    *,
    expected_rp_id: str | None = None,
    require_uv: bool = False,
) -> VerificationResult:
    """Verify a sign-extension + txAuthAgent output against a payload.

    Raises ValueError on any verification failure. Returns a VerificationResult
    on success.
    """
    record = parse_profile_output(extension_outputs)
    sign_entry = parse_sign_output(extension_outputs)

    # Cross-check the layering: the raw sign signature must be exactly the
    # signature the txAuthAgent audit record carries.
    raw_signature = sign_entry.get("signature")
    if raw_signature is not None and raw_signature != record["agent_action_sig"]:
        raise ValueError("sign output and txAuthAgent record disagree on signature")

    expected_digest = compute_action_digest(payload)
    if record["action_digest"] != expected_digest:
        raise ValueError("action_digest does not match the recomputed canonical digest")

    public_key = load_public_key_pem(signing_public_key_pem, record["algorithm"])
    signature = record["agent_action_sig"]

    try:
        if record["algorithm"] == ALG_EDDSA:
            public_key.verify(signature, expected_digest)
        else:
            public_key.verify(signature, expected_digest, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("agent action signature verification failed") from exc

    if expected_rp_id is not None:
        expected_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
        if record["rp_id_hash"] != expected_hash:
            raise ValueError("rp_id_hash does not match expected relying party")

    if record["flags"].get("up") is not True:
        raise ValueError("user presence flag (up) not set — no physical gesture")
    if require_uv and record["flags"].get("uv") is not True:
        raise ValueError("user verification flag (uv) not set — required for this action")

    return VerificationResult(
        algorithm=record["algorithm"],
        rp_id_hash=record["rp_id_hash"],
        up=record["flags"]["up"],
        uv=bool(record["flags"].get("uv", False)),
        credential_id=record["agent_cid"],
        action_digest=record["action_digest"],
    )


def verify_agent_action_cbor(
    payload: Dict[str, Any],
    cbor_blob: bytes,
    signing_public_key_pem: bytes,
    *,
    expected_rp_id: str | None = None,
    require_uv: bool = False,
) -> VerificationResult:
    """Verify a raw CBOR client-extension-outputs blob (wire format)."""
    from .extension import decode_output_cbor

    outputs = decode_output_cbor(cbor_blob)
    return verify_agent_action(
        payload,
        outputs,
        signing_public_key_pem,
        expected_rp_id=expected_rp_id,
        require_uv=require_uv,
    )


def parse_sign_generated_key(extension_outputs: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the registration output of the ``sign`` extension.

    Returns ``{"publicKey": <COSE_Key bytes>, "algorithm": int,
    "attestationObject": <CBOR bytes>}``.
    """
    sign_entry = parse_sign_output(extension_outputs)
    generated = sign_entry.get("generatedKey")
    if not isinstance(generated, dict):
        raise ValueError("sign output has no generatedKey (this was not a registration ceremony)")
    for field in ("publicKey", "algorithm", "attestationObject"):
        if field not in generated:
            raise ValueError(f"generatedKey missing field: {field}")
    if not isinstance(generated["publicKey"], bytes):
        raise ValueError("generatedKey.publicKey must be bytes (COSE_Key)")
    return generated


def parse_sign_attestation(attestation_object: bytes) -> Dict[str, Any]:
    """Parse a signing-key attestation object.

    The attestation object has the standard shape ``{fmt, authData, attStmt}``.
    For the signing key pair its authData carries the signing public key as
    the attested credential public key (empty credential ID) and a ``sign``
    extension entry with the key policy flags.

    Returns a dict with keys: fmt, auth_data (bytes), att_stmt (dict),
    rp_id_hash (bytes), flags (authData flags byte), signing_cose_key (bytes),
    sign_flags (int policy) — the policy is None if absent.
    """
    att = cbor.loads(attestation_object)
    if not isinstance(att, dict):
        raise ValueError("attestation object must be a CBOR map")
    fmt = att.get("fmt")
    auth_data = att.get("authData")
    att_stmt = att.get("attStmt")
    if not isinstance(fmt, str) or not isinstance(auth_data, bytes) or not isinstance(att_stmt, dict):
        raise ValueError("malformed attestation object")

    if len(auth_data) < 37:
        raise ValueError("authData too short")
    rp_id_hash = auth_data[:32]
    flags_byte = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")

    # attestedCredentialData (if AT bit set):
    # aaguid(16) || credIdLen(2) || credId || publicKey(CBOR)
    pos = 37
    signing_cose_key = None
    aaguid = b""
    cred_id = b""
    if flags_byte & 0x40:
        aaguid = auth_data[pos : pos + 16]
        pos += 16
        cred_id_len = int.from_bytes(auth_data[pos : pos + 2], "big")
        pos += 2
        cred_id = auth_data[pos : pos + cred_id_len]
        pos += cred_id_len
        signing_cose_value, consumed = _decode_cbor_item(auth_data[pos:])
        pos += consumed
        # Re-encode canonically so callers get the exact COSE_Key bytes.
        signing_cose_key = cbor.dumps(signing_cose_value, deterministic=True)

    # extensions (if ED bit set)
    sign_flags = None
    if flags_byte & 0x80 and pos < len(auth_data):
        extensions, _ = _decode_cbor_item(auth_data[pos:])
        if isinstance(extensions, dict):
            sign_entry = extensions.get("sign")
            if isinstance(sign_entry, dict) and isinstance(sign_entry.get("flags"), int):
                sign_flags = sign_entry["flags"]

    return {
        "fmt": fmt,
        "auth_data": auth_data,
        "att_stmt": att_stmt,
        "rp_id_hash": rp_id_hash,
        "flags": flags_byte,
        "sign_count": sign_count,
        "aaguid": aaguid,
        "credential_id": cred_id,
        "signing_cose_key": signing_cose_key,
        "sign_flags": sign_flags,
    }


def verify_sign_attestation(
    attestation_object: bytes,
    credential_public_key_pem: bytes,
    *,
    expected_rp_id: str | None = None,
    client_data_hash: bytes | None = None,
) -> Dict[str, Any]:
    """Verify a signing-key attestation (packed format, self-signed by the credential).

    Checks that:

    - the authData RP ID hash matches ``expected_rp_id`` (if given),
    - the attested credential public key parses as a COSE_Key,
    - for ``fmt == "packed"`` with a ``sig``: the signature over
      ``authData || clientDataHash`` verifies with the credential public key.

    The packed self-attestation is what the reference implementation's
    VirtualAuthenticator produces; real devices use their certified
    attestation format, which the caller validates via the FIDO metadata
    service (MDS). Returns the parsed attestation dict (see
    ``parse_sign_attestation``).
    """
    parsed = parse_sign_attestation(attestation_object)
    if expected_rp_id is not None:
        expected_hash = hashlib.sha256(expected_rp_id.encode("utf-8")).digest()
        if parsed["rp_id_hash"] != expected_hash:
            raise ValueError("attestation rp_id_hash does not match expected relying party")

    if parsed["fmt"] == "packed":
        att_stmt = parsed["att_stmt"]
        sig = att_stmt.get("sig")
        if isinstance(sig, bytes):
            if client_data_hash is None:
                raise ValueError(
                    "packed attestation signature present — client_data_hash required to verify"
                )
            credential_key = serialization.load_pem_public_key(credential_public_key_pem)
            if not isinstance(credential_key, ec.EllipticCurvePublicKey):
                raise ValueError("packed attestation requires an EC credential key")
            to_be_signed = parsed["auth_data"] + client_data_hash
            try:
                credential_key.verify(sig, to_be_signed, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature as exc:
                raise ValueError("signing-key attestation signature verification failed") from exc
    return parsed


def _decode_cbor_item(data: bytes) -> tuple[Any, int]:
    """Decode a single CBOR item, returning (value, bytes_consumed)."""
    decoder = _LengthDecoder(data)
    value = decoder.decode()
    return value, decoder.pos


class _LengthDecoder:
    """Minimal wrapper exposing decode() + consumed position from cbor.py."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        if len(chunk) != n:
            raise ValueError("truncated CBOR data")
        self.pos += n
        return chunk

    def _arg(self, extra: int) -> int:
        if extra < 24:
            return extra
        if extra == 24:
            return self._take(1)[0]
        if extra == 25:
            return int.from_bytes(self._take(2), "big")
        if extra == 26:
            return int.from_bytes(self._take(4), "big")
        if extra == 27:
            return int.from_bytes(self._take(8), "big")
        raise ValueError(f"invalid additional info: {extra}")

    def decode(self) -> Any:
        if self.pos >= len(self.data):
            raise ValueError("empty CBOR data")
        initial = self._take(1)[0]
        major = initial >> 5
        extra = initial & 0x1F
        if major in (0, 1):
            n = self._arg(extra)
            return -1 - n if major == 1 else n
        if major == 2:
            return self._take(self._arg(extra))
        if major == 3:
            return self._take(self._arg(extra)).decode("utf-8")
        if major == 4:
            return [self.decode() for _ in range(self._arg(extra))]
        if major == 5:
            out = {}
            for _ in range(self._arg(extra)):
                k = self.decode()
                out[k] = self.decode()
            return out
        if major == 7:
            if extra == 20:
                return False
            if extra == 21:
                return True
            if extra == 22:
                return None
            raise ValueError(f"unsupported simple value: {extra}")
        raise ValueError(f"unsupported major type: {major}")
