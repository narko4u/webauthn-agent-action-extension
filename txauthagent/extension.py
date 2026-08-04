"""txAuthAgent profile wire format (Sections 4 & 5 of the spec, v0.4).

txAuthAgent is an *application profile* defined on top of the WebAuthn
``sign`` extension (w3c/webauthn PR #2078, "Add sign extension"). The ``sign``
extension provides the cryptographic primitive — an attested, hardware-bound
signing key pair that is separate from the WebAuthn credential key pair and
signs arbitrary data unaltered. txAuthAgent defines:

- the agent action payload schema (see payload.py),
- the canonical action digest (see digest.py) — the exact bytes passed as the
  ``sign`` extension's ``tbs`` input,
- the ceremony wiring: registration requests ``sign.generateKey``,
  authentication requests ``sign.sign``,
- the verification semantics: any party can verify a raw signature against
  the *signing public key* published at registration — never the pairwise
  WebAuthn credential (this is the privacy property a reviewer flagged in
  v0.3: WebAuthn credentials are pairwise to their relying party by design).

This module implements the JSON dictionary shapes:

- AuthenticationExtensionsClientInputsJSON — the *input* the client sends to
  the authenticator inside navigator.credentials.create()/get().
- AuthenticationExtensionsClientOutputsJSON — the *output* returned by the
  authenticator (CBOR at the transport layer), containing the ``sign``
  extension result and the txAuthAgent audit record.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict

from . import cbor
from .digest import compute_action_digest

__all__ = [
    "EXTENSION_ID",
    "SIGN_EXTENSION_ID",
    "ALG_ES256",
    "ALG_EDDSA",
    "FLAG_UNATTENDED",
    "FLAG_REQUIRE_UP",
    "FLAG_REQUIRE_UV",
    "FLAG_NAMES",
    "PROFILE_TAG",
    "b64url_encode",
    "b64url_decode",
    "build_registration_input",
    "build_ceremony_input",
    "build_profile_output",
    "parse_sign_output",
    "parse_profile_output",
    "encode_output_cbor",
    "decode_output_cbor",
]

EXTENSION_ID = "txAuthAgent"
SIGN_EXTENSION_ID = "sign"

# Profile version tag embedded in the client input so verifiers can pin the
# digest/verification rules that apply to a record.
PROFILE_TAG = "txauthagent/sign/v1"

# COSE algorithm identifiers
ALG_ES256 = -7
ALG_EDDSA = -8

# Sign-extension signing-key policies (authenticator-level ``flags`` value):
#   unattended  (0b000) — no user presence/verification required
#   require-up  (0b001) — physical gesture required, no PIN/biometric
#   require-uv  (0b101) — physical gesture AND user verification required
FLAG_UNATTENDED = 0
FLAG_REQUIRE_UP = 1
FLAG_REQUIRE_UV = 5

FLAG_NAMES = {
    FLAG_UNATTENDED: "unattended",
    FLAG_REQUIRE_UP: "require-up",
    FLAG_REQUIRE_UV: "require-uv",
}


def b64url_encode(data: bytes) -> str:
    """Base64url (no padding) encode — the WebAuthn identifier encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Base64url (no padding) decode."""
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def build_registration_input(
    agent_identity: Dict[str, Any],
    algorithms: list[int] | None = None,
    tbs: bytes | None = None,
) -> Dict[str, Any]:
    """Build the extension inputs for a registration ceremony.

    Requests the ``sign`` extension to generate a signing key pair for the new
    credential (per PR #2078, ``generateKey`` input) and attaches the
    txAuthAgent profile context.

    The signing-key policy (require-up / require-uv) is expressed by the
    client through ``authenticatorSelection.userVerification`` per the sign
    extension spec — it is not a client input here.

    Args:
        agent_identity: ACI identity declaration (aci_uri, agent_name, ...).
        algorithms: Preferred COSE algorithms for the signing key, most
            preferred first. Defaults to [ES256, EdDSA] (ES256 primary — the
            universally supported FIDO2 algorithm).
        tbs: Optional data to be signed by the newly generated key during
            registration (per the extension's ``generateKey.tbs`` member).
            The txAuthAgent profile signs the canonical action digest, so
            this is normally omitted at registration.
    """
    if algorithms is None:
        algorithms = [ALG_ES256, ALG_EDDSA]
    generate_key: Dict[str, Any] = {"algorithms": algorithms}
    if tbs is not None:
        generate_key["tbs"] = tbs
    return {
        SIGN_EXTENSION_ID: {"generateKey": generate_key},
        EXTENSION_ID: {
            "profile": PROFILE_TAG,
            "agent_identity": dict(agent_identity),
        },
    }


def build_ceremony_input(
    payload: Dict[str, Any],
    key_handle_by_credential: Dict[str, bytes],
) -> Dict[str, Any]:
    """Build the extension inputs for an authentication (action-signing) ceremony.

    Per the sign extension, the client requests ``sign.sign`` with:

    - ``tbs``: the canonical action digest (SHA-256("txAuthAgent" || 0x00 ||
      deterministic-CBOR(payload))) — signed by the authenticator **unaltered**,
    - ``keyHandleByCredential``: a map from base64url-encoded credential ID to
      the signing key handle (COSE_Key_Ref) to use for that credential.

    The txAuthAgent client input carries the structured action payload as the
    application-layer context (what the client displays and what the digest
    covers).

    Args:
        payload: A validated agent action payload (see payload.py).
        key_handle_by_credential: map of base64url credential ID -> key handle
            bytes. Must contain exactly one entry per entry in
            ``allowCredentials``.
    """
    tbs = compute_action_digest(payload)
    return {
        SIGN_EXTENSION_ID: {
            "sign": {
                "tbs": tbs,
                "keyHandleByCredential": {
                    cid: handle for cid, handle in key_handle_by_credential.items()
                },
            }
        },
        EXTENSION_ID: {
            "profile": PROFILE_TAG,
            "action": payload,
        },
    }


def build_profile_output(
    *,
    signature: bytes,
    action_digest: bytes,
    agent_cid: bytes,
    algorithm: int,
    rp_id_hash: bytes,
    up: bool,
    uv: bool,
) -> Dict[str, Any]:
    """Build the txAuthAgent audit record (the ``txAuthAgent`` output entry).

    This is the application-layer record a relying party or independent
    auditor consumes: it pairs the raw ``sign`` signature with the exact
    digest that was signed, the signing-key algorithm, the credential binding
    and the observed user-presence / user-verification state.

    The raw signature itself is carried under the ``sign`` extension output;
    ``signature`` here is the same value (kept for self-contained audit).
    """
    return {
        "agent_action_sig": signature,
        "action_digest": action_digest,
        "agent_cid": agent_cid,
        "algorithm": algorithm,
        "rp_id_hash": rp_id_hash,
        "flags": {"up": up, "uv": uv},
    }


def parse_sign_output(outputs: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and validate the ``sign`` extension output from client outputs.

    Returns the raw entry — e.g. ``{"signature": <bytes>}`` for an
    authentication ceremony or ``{"generatedKey": {...}}`` for a registration
    ceremony.
    """
    if SIGN_EXTENSION_ID not in outputs:
        raise ValueError(f"extension {SIGN_EXTENSION_ID!r} not present in outputs")
    entry = outputs[SIGN_EXTENSION_ID]
    if not isinstance(entry, dict):
        raise ValueError("sign output must be a dict")
    if "signature" in entry and not isinstance(entry["signature"], bytes):
        raise ValueError("sign.signature must be bytes")
    return entry


def parse_profile_output(outputs: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and validate the txAuthAgent audit record from client outputs."""
    if EXTENSION_ID not in outputs:
        raise ValueError(f"extension {EXTENSION_ID!r} not present in outputs")
    entry = outputs[EXTENSION_ID]
    if not isinstance(entry, dict):
        raise ValueError("txAuthAgent output must be a dict")
    for field in ("agent_action_sig", "action_digest", "agent_cid", "algorithm", "rp_id_hash", "flags"):
        if field not in entry:
            raise ValueError(f"txAuthAgent output missing field: {field}")
    if not isinstance(entry["agent_action_sig"], bytes):
        raise ValueError("agent_action_sig must be bytes")
    if not isinstance(entry["action_digest"], bytes) or len(entry["action_digest"]) != 32:
        raise ValueError("action_digest must be 32 bytes (SHA-256)")
    if not isinstance(entry["agent_cid"], bytes):
        raise ValueError("agent_cid must be bytes")
    if entry["algorithm"] not in (ALG_EDDSA, ALG_ES256):
        raise ValueError(f"unsupported algorithm: {entry['algorithm']}")
    flags = entry["flags"]
    if not isinstance(flags, dict) or "up" not in flags:
        raise ValueError("flags must be a dict with 'up'")
    return entry


def encode_output_cbor(entry: Dict[str, Any]) -> bytes:
    """CBOR-encode a combined client-extension-outputs dict (authenticator side)."""
    return cbor.dumps(entry)


def decode_output_cbor(blob: bytes) -> Dict[str, Any]:
    """Decode a CBOR client-extension-outputs blob (client/RP side)."""
    value = cbor.loads(blob)
    if not isinstance(value, dict):
        raise ValueError("decoded CBOR must be a map")
    return value
