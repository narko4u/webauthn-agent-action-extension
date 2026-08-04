"""Software authenticator implementing the WebAuthn ``sign`` extension (v0.4).

Real deployments use a CTAP 2.2+ hardware authenticator (YubiKey 5, Ledger
FIDO2 app, Nitrokey 3) running the ``sign`` extension proposed in
w3c/webauthn PR #2078. This module simulates the authenticator behaviour so
the txAuthAgent profile can be exercised without hardware:

- the WebAuthn **credential key pair** (ES256) — used only for the ceremony
  wrapper and the signing-key attestation, exactly as in the extension spec;
- a **signing key pair** that is *separate* from the credential key pair and
  deterministically re-derived from the per-credential authenticator secret,
  the key policy and the auxiliary input — so the authenticator can stay
  stateless (only a key handle travels);
- the key-handle encoding from the extension spec: a COSE_Key_Ref wrapping an
  HMAC-SHA-256-protected ``kid`` (macKey, kidParams || "sign" || rpIdHash);
- UP/UV policy enforcement fixed at key creation (require-up / require-uv);
- a packed-format attestation object for the signing key pair, self-signed by
  the credential key (real hardware uses its certified attestation format).

It is deliberately simple and NOT a substitute for hardware attestation in
production — the spec requires the private keys to never leave the device.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

from . import cbor
from .cose import encode_cose_key
from .digest import compute_action_digest
from .extension import (
    ALG_EDDSA,
    ALG_ES256,
    EXTENSION_ID,
    FLAG_REQUIRE_UP,
    FLAG_REQUIRE_UV,
    FLAG_NAMES,
    SIGN_EXTENSION_ID,
    b64url_decode,
    b64url_encode,
    build_profile_output,
)
from .payload import validate_action_payload

__all__ = [
    "VirtualAuthenticator",
    "generate_credential_id",
    "SignKeyHandle",
]

# Authenticator-level constants (RFC 9053 COSE_Key labels, see cose.py)
_KTY_EC2 = 2
_KTY_OKP = 1


def generate_credential_id(prefix: bytes = b"txaa") -> bytes:
    """Deterministic-length credential id (32 bytes)."""
    return prefix + os.urandom(32 - len(prefix))


class SignKeyHandle:
    """A COSE_Key_Ref for a signing key pair (the spec's ``keyHandleByCredential`` value).

    Carries the opaque ``kid`` the authenticator uses to re-derive the signing
    private key, plus the algorithm the key was created for.
    """

    def __init__(self, cose_key_ref: bytes) -> None:
        self.cose_key_ref = cose_key_ref

    @property
    def kid(self) -> bytes:
        """The authenticator-specific key identifier inside the COSE_Key_Ref."""
        ref = cbor.loads(self.cose_key_ref)
        kid = ref.get(2)
        if not isinstance(kid, bytes):
            raise ValueError("COSE_Key_Ref missing 'kid'")
        return kid


def _derive_seed(mac_key: bytes, alg: int, flags: int, aux_ikm: bytes, rp_id_hash: bytes) -> bytes:
    """Deterministically derive a 32-byte private-key seed for a signing key pair.

    The extension spec derives the signing key from three seeds: the
    per-credential authenticator secret, the key policy (``signFlags``) and
    auxiliary input. We mirror that with HMAC-SHA-256 domain-separated by the
    sign extension identifier and the RP ID hash.
    """
    return hmac.new(
        mac_key,
        b"sign-key-derive" + bytes([alg & 0xFF, flags]) + aux_ikm + rp_id_hash,
        hashlib.sha256,
    ).digest()


def _private_key_from_seed(seed: bytes, alg: int):
    if alg == ALG_EDDSA:
        return ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    if alg == ALG_ES256:
        return ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    raise ValueError(f"unsupported signing algorithm: {alg}")


class VirtualAuthenticator:
    """A software stand-in for a hardware security key with the sign extension.

    Args:
        algorithm: Default COSE algorithm for signing keys — ALG_ES256 (-7,
            default; P-256 is universally supported by FIDO2 hardware) or
            ALG_EDDSA (-8, Ed25519).
        rp_id: The relying-party identifier the credential is bound to.
        flags: Default signing-key policy — FLAG_REQUIRE_UP (physical gesture
            required) or FLAG_REQUIRE_UV (gesture + user verification).
    """

    def __init__(
        self,
        algorithm: int = ALG_ES256,
        rp_id: str = "empirelabs.com.au",
        flags: int = FLAG_REQUIRE_UP,
    ) -> None:
        self.algorithm = algorithm
        self.rp_id = rp_id
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.credential_id = generate_credential_id()

        # The WebAuthn credential key pair — ES256 for the ceremony wrapper and
        # the signing-key attestation (YubiKey 5 etc. sign ES256 only).
        self._credential_key = ec.generate_private_key(ec.SECP256R1())

        # Per-credential authenticator secret (never leaves the device).
        self._mac_key = os.urandom(32)

        # Set by register(): chosen signing algorithm + policy + aux input.
        self._sign_alg: Optional[int] = None
        self._sign_flags: Optional[int] = None
        self._aux_ikm: Optional[bytes] = None
        self._sign_public_key = None  # cryptography public key object
        self._key_handle: Optional[SignKeyHandle] = None

    # ------------------------------------------------------------------ #
    # Registration (sign extension generateKey)
    # ------------------------------------------------------------------ #

    @property
    def credential_public_key_pem(self) -> bytes:
        """PEM of the WebAuthn credential public key (attestation verification)."""
        return self._credential_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def public_key_pem(self) -> bytes:
        """PEM of the *signing* public key — the key verifiers use.

        Only available after ``register()``. This is the key a relying party
        records at registration and publishes so any third party can verify
        agent action signatures without touching the pairwise credential.
        """
        if self._sign_public_key is None:
            raise ValueError("no signing key yet — call register() first")
        return self._sign_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def key_handle(self) -> SignKeyHandle:
        """The signing key handle (COSE_Key_Ref) for this credential."""
        if self._key_handle is None:
            raise ValueError("no signing key yet — call register() first")
        return self._key_handle

    def register(
        self,
        algorithms: list[int] | None = None,
        flags: int | None = None,
        origin: str = "https://empirelabs.com.au",
        challenge: bytes = b"txAuthAgent-registration",
    ) -> Dict[str, Any]:
        """Run the registration ceremony: create a signing key pair.

        Returns the ``sign`` extension client output entry::

            {"generatedKey": {
                "publicKey": <COSE_Key bytes>,
                "algorithm": <COSE alg>,
                "attestationObject": <CBOR attestation object bytes>,
            }}

        The publicKey is also available as ``self.public_key_pem`` and the
        key handle as ``self.key_handle``.
        """
        if algorithms is None:
            algorithms = [ALG_ES256, ALG_EDDSA]
        if flags is None:
            flags = self.flags
        if flags not in FLAG_NAMES:
            raise ValueError(f"invalid signing-key policy flags: {flags}")

        chosen_alg = None
        for candidate in algorithms:
            if candidate in (ALG_EDDSA, ALG_ES256):
                chosen_alg = candidate
                break
        if chosen_alg is None:
            raise ValueError(f"no supported algorithm in {algorithms}")

        self._sign_alg = chosen_alg
        self._sign_flags = flags
        self._aux_ikm = os.urandom(16)

        seed = _derive_seed(self._mac_key, chosen_alg, flags, self._aux_ikm, self.rp_id_hash)
        private_key = _private_key_from_seed(seed, chosen_alg)
        self._sign_public_key = private_key.public_key()

        cose_pub = encode_cose_key(self._sign_public_key, chosen_alg)
        att_obj = self._build_attestation_object(cose_pub, origin, challenge)

        self._key_handle = SignKeyHandle(
            self._build_key_handle_cose_ref(chosen_alg, flags, self._aux_ikm)
        )

        # Return the extension output keyed by extension id, matching the
        # AuthenticationExtensionsClientOutputsJSON convention.
        return {
            SIGN_EXTENSION_ID: {
                "generatedKey": {
                    "publicKey": cose_pub,
                    "algorithm": chosen_alg,
                    "attestationObject": att_obj,
                }
            }
        }

    # ------------------------------------------------------------------ #
    # Authentication (sign extension sign)
    # ------------------------------------------------------------------ #

    def sign_action(
        self,
        payload: Dict[str, Any],
        *,
        tap: bool = True,
        user_verified: bool = False,
        key_handle: SignKeyHandle | None = None,
    ) -> Dict[str, Any]:
        """Sign an agent action (authentication ceremony with the sign extension).

        Enforces the signing-key policy fixed at registration: ``require-up``
        demands the physical gesture (``tap=True``); ``require-uv`` demands
        user verification (``user_verified=True``) as well.

        Returns the combined client extension outputs::

            {
              "sign": {"signature": <raw signature over the action digest>},
              "txAuthAgent": { <audit record — see build_profile_output> },
            }

        The signature is over the canonical action digest **unaltered** —
        unlike a WebAuthn assertion signature, it does not wrap the data in
        authenticatorData/clientDataJSON. That is what makes it verifiable by
        any party with the signing public key.
        """
        if self._sign_alg is None or self._sign_public_key is None:
            raise ValueError("no signing key yet — call register() first")
        validate_action_payload(payload)

        handle = key_handle if key_handle is not None else self._key_handle
        if handle is None:
            raise ValueError("no signing key handle provided — call register() first")
        alg, flags = self._resolve_key_handle(handle)

        # Policy enforcement (CTAP2_ERR_UP_REQUIRED / CTAP2_ERR_PUAT_REQUIRED).
        if flags & 0b001 and not tap:
            raise ValueError("user presence required (CTAP2_ERR_UP_REQUIRED): tap the key")
        if flags & 0b100 and not user_verified:
            raise ValueError("user verification required (CTAP2_ERR_PUAT_REQUIRED): PIN/biometric")

        digest = compute_action_digest(payload)
        signature = self._sign_raw(digest, alg)

        return {
            SIGN_EXTENSION_ID: {"signature": signature},
            EXTENSION_ID: build_profile_output(
                signature=signature,
                action_digest=digest,
                agent_cid=self.credential_id,
                algorithm=alg,
                rp_id_hash=self.rp_id_hash,
                up=bool(flags & 0b001),
                uv=bool(flags & 0b100),
            ),
        }

    def sign_action_cbor(
        self,
        payload: Dict[str, Any],
        *,
        tap: bool = True,
        user_verified: bool = False,
    ) -> bytes:
        """Return the full CBOR client-extension-outputs blob (wire format)."""
        outputs = self.sign_action(payload, tap=tap, user_verified=user_verified)
        return cbor.dumps(outputs)

    # ------------------------------------------------------------------ #
    # Internals — sign-extension authenticator processing
    # ------------------------------------------------------------------ #

    def _sign_raw(self, data: bytes, alg: int) -> bytes:
        """Raw signature over ``data`` with the re-derived signing private key."""
        assert self._sign_flags is not None
        assert self._aux_ikm is not None
        seed = _derive_seed(self._mac_key, alg, self._sign_flags, self._aux_ikm, self.rp_id_hash)
        private_key = _private_key_from_seed(seed, alg)
        if alg == ALG_EDDSA:
            return private_key.sign(data)
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def _encode_kid(self, alg: int, flags: int, aux_ikm: bytes) -> bytes:
        """Spec example encoding: kid = HMAC-SHA-256(macKey, kidParams||"sign"||rpIdHash) || kidParams."""
        kid_params = cbor.dumps([alg, flags, aux_ikm], deterministic=True)
        mac = hmac.new(
            self._mac_key,
            kid_params + b"sign" + self.rp_id_hash,
            hashlib.sha256,
        ).digest()
        return mac + kid_params

    def _decode_kid(self, kid: bytes) -> tuple[int, int, bytes]:
        """Reverse of ``_encode_kid`` with integrity verification."""
        mac = kid[:32]
        kid_params = kid[32:]
        expected = hmac.new(
            self._mac_key,
            kid_params + b"sign" + self.rp_id_hash,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("signing key handle was not generated by this authenticator")
        alg, flags, aux_ikm = cbor.loads(kid_params)
        if not isinstance(alg, int) or not isinstance(flags, int) or not isinstance(aux_ikm, bytes):
            raise ValueError("malformed signing key handle")
        return alg, flags, aux_ikm

    def _build_key_handle_cose_ref(self, alg: int, flags: int, aux_ikm: bytes) -> bytes:
        """Construct a COSE_Key_Ref from a COSE_Key per the spec's procedure."""
        kid = self._encode_kid(alg, flags, aux_ikm)
        kty = _KTY_EC2 if alg == ALG_ES256 else _KTY_OKP
        ref: Dict[int, Any] = {1: kty, 2: kid, 3: alg}
        return cbor.dumps(ref, deterministic=True)

    def _resolve_key_handle(self, handle: SignKeyHandle) -> tuple[int, int]:
        """Decode a COSE_Key_Ref: verify integrity, extract alg + policy flags."""
        ref = cbor.loads(handle.cose_key_ref)
        if not isinstance(ref, dict):
            raise ValueError("COSE_Key_Ref must be a map")
        kid = ref.get(2)
        if not isinstance(kid, bytes):
            raise ValueError("COSE_Key_Ref missing 'kid'")
        alg, flags, _ = self._decode_kid(kid)
        ref_alg = ref.get(3)
        if ref_alg is not None and ref_alg != alg:
            raise ValueError("COSE_Key_Ref algorithm does not match signing key")
        if alg != self._sign_alg:
            raise ValueError("signing key algorithm mismatch")
        return alg, flags

    def _build_attestation_object(
        self, signing_cose_key: bytes, origin: str, challenge: bytes
    ) -> bytes:
        """Packed-format attestation for the signing key pair, self-signed by the credential key.

        Per the extension spec the signing-key attestation signs over the same
        RP ID, authData flags, AAGUID and clientData hash as the credential's
        attestation, with ``signCount = 0``, an empty credential ID, the
        signing public key as the attested credential public key, and a
        ``sign`` extension entry carrying the key policy flags.
        """
        client_data_json = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": b64url_encode(challenge),
                "origin": origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        client_data_hash = hashlib.sha256(client_data_json).digest()

        aaguid = b"\x00" * 16  # software authenticator — no certified AAGUID
        # Registration authData flags: UP | UV | AT (attested credential data
        # present) | ED (extension data present).
        flags_byte = 0x05 | 0x40 | 0x80
        sign_count = 0
        attested_credential_data = (
            aaguid
            + (0).to_bytes(2, "big")
            + b""
            + signing_cose_key
        )
        extensions = cbor.dumps({"sign": {"flags": self._sign_flags}}, deterministic=True)
        auth_data = (
            self.rp_id_hash
            + bytes([flags_byte])
            + sign_count.to_bytes(4, "big")
            + attested_credential_data
            + extensions
        )

        # Packed self-attestation: sig over authData || clientDataHash with the
        # credential key (real hardware uses its certified attestation format).
        att_stmt_sig = self._credential_key.sign(
            auth_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )
        att_stmt = {"alg": ALG_ES256, "sig": att_stmt_sig}
        return cbor.dumps(
            {
                "fmt": "packed",
                "authData": auth_data,
                "attStmt": att_stmt,
            },
            deterministic=True,
        )
