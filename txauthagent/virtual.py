"""Software authenticator for development & testing (Section 6 note of the spec).

Real deployments use a CTAP 2.2+ hardware authenticator (YubiKey 5, Ledger
FIDO2 app, Nitrokey 3). This module simulates the authenticator behaviour so
the wire format and verification logic can be exercised without hardware:

- stores an Ed25519 keypair (acting as the "hardware" credential)
- simulates the physical user-presence gesture via `tap=True`
- returns the same CBOR extension output a real key would produce

It is deliberately simple and NOT a substitute for hardware attestation in
production — the spec requires the private key to never leave the device.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ec

from . import cbor
from .digest import compute_action_digest
from .extension import ALG_EDDSA, ALG_ES256, EXTENSION_ID, build_extension_output
from .payload import validate_action_payload

__all__ = ["VirtualAuthenticator", "generate_credential_id"]


def generate_credential_id(prefix: bytes = b"txaa") -> bytes:
    """Deterministic-length credential id (spec uses 258 bytes; we use 32)."""
    return prefix + os.urandom(32 - len(prefix))


class VirtualAuthenticator:
    """A software stand-in for a hardware security key.

    Args:
        algorithm: COSE algorithm for signing — ALG_EDDSA (-8, default) or ALG_ES256 (-7).
    """

    def __init__(self, algorithm: int = ALG_EDDSA, rp_id: str = "empirelabs.com.au") -> None:
        self.algorithm = algorithm
        self.rp_id = rp_id
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.credential_id = generate_credential_id()
        if algorithm == ALG_EDDSA:
            self._signing_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm == ALG_ES256:
            self._signing_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"unsupported algorithm: {algorithm}")

    @property
    def public_key_pem(self) -> bytes:
        if self.algorithm == ALG_EDDSA:
            return self._signing_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_action(
        self,
        payload: Dict[str, Any],
        *,
        tap: bool = True,
        user_verified: bool = False,
    ) -> Dict[str, Any]:
        """Simulate the hardware signing flow: digest -> physical tap -> signature.

        Returns the txAuthAgent extension output *entry* (the value that sits under
        the ``txAuthAgent`` key in an AuthenticationExtensionsClientOutputsJSON).
        """
        validate_action_payload(payload)
        if not tap:
            raise ValueError("hardware declined: user presence (tap) required")

        digest = compute_action_digest(payload)
        if self.algorithm == ALG_EDDSA:
            signature = self._signing_key.sign(digest)
        else:
            signature = self._signing_key.sign(
                digest, ec.ECDSA(hashes.SHA256())
            )

        return build_extension_output(
            agent_action_sig=signature,
            agent_cid=self.credential_id,
            algorithm=self.algorithm,
            rp_id_hash=self.rp_id_hash,
            up=True,
            uv=user_verified,
        )

    def sign_action_cbor(self, payload: Dict[str, Any], *, tap: bool = True) -> bytes:
        """Return the full CBOR extension output blob (authenticator wire format)."""
        entry = self.sign_action(payload, tap=tap)
        return cbor.dumps({EXTENSION_ID: entry})
