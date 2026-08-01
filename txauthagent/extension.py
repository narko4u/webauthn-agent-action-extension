"""WebAuthn extension wire format for txAuthAgent (Sections 4 & 5 of the spec).

Implements the two JSON shapes defined by WebAuthn L3 / FIDO2:

- AuthenticationExtensionsClientInputsJSON — the *input* the client sends to
  the authenticator inside navigator.credentials.create()/get().
- AuthenticationExtensionsClientOutputsJSON — the *output* the authenticator
  returns, containing the signed action payload.

The authenticator output is CBOR-encoded at the transport layer; this module
provides encode/decode helpers plus the JSON dictionary shapes.
"""

from __future__ import annotations

from typing import Any, Dict

from . import cbor

__all__ = [
    "EXTENSION_ID",
    "build_extension_input",
    "build_extension_output",
    "parse_extension_output",
    "encode_output_cbor",
    "decode_output_cbor",
]

EXTENSION_ID = "txAuthAgent"

# COSE algorithm identifiers
ALG_EDDSA = -8
ALG_ES256 = -7


def build_extension_input(
    agent_identity: Dict[str, Any],
    action: Dict[str, Any] | None = None,
    challenge: str | None = None,
    prompt: str | None = None,
) -> Dict[str, Any]:
    """Build an AuthenticationExtensionsClientInputsJSON entry.

    For registration (navigator.credentials.create()) omit ``action`` and pass
    a ``challenge``. For authentication/action-signing pass ``action``.
    """
    ext: Dict[str, Any] = {"agent_identity": dict(agent_identity)}
    if action is not None:
        ext["action"] = dict(action)
    if challenge is not None:
        ext["challenge"] = challenge
    if prompt is not None:
        ext["prompt"] = prompt
    return {EXTENSION_ID: ext}


def build_extension_output(
    *,
    agent_action_sig: bytes,
    agent_cid: bytes,
    algorithm: int,
    rp_id_hash: bytes,
    up: bool,
    uv: bool = False,
) -> Dict[str, Any]:
    """Build the txAuthAgent extension output *entry*.

    The returned dict is the value that sits under the ``txAuthAgent`` key in
    an AuthenticationExtensionsClientOutputsJSON. Wrap it yourself when you
    need the full outputs object: ``{EXTENSION_ID: entry}``.
    """
    return {
        "agent_action_sig": agent_action_sig,
        "agent_cid": agent_cid,
        "algorithm": algorithm,
        "rp_id_hash": rp_id_hash,
        "flags": {"up": up, "uv": uv},
    }


def parse_extension_output(outputs: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and validate the txAuthAgent entry from extension outputs."""
    if EXTENSION_ID not in outputs:
        raise ValueError(f"extension {EXTENSION_ID!r} not present in outputs")
    entry = outputs[EXTENSION_ID]
    if not isinstance(entry, dict):
        raise ValueError("txAuthAgent output must be a dict")
    for field in ("agent_action_sig", "agent_cid", "algorithm", "rp_id_hash", "flags"):
        if field not in entry:
            raise ValueError(f"txAuthAgent output missing field: {field}")
    if not isinstance(entry["agent_action_sig"], bytes):
        raise ValueError("agent_action_sig must be bytes")
    if not isinstance(entry["agent_cid"], bytes):
        raise ValueError("agent_cid must be bytes")
    if entry["algorithm"] not in (ALG_EDDSA, ALG_ES256):
        raise ValueError(f"unsupported algorithm: {entry['algorithm']}")
    flags = entry["flags"]
    if not isinstance(flags, dict) or "up" not in flags:
        raise ValueError("flags must be a dict with 'up'")
    return entry


def encode_output_cbor(entry: Dict[str, Any]) -> bytes:
    """CBOR-encode a txAuthAgent extension output entry (authenticator side)."""
    return cbor.dumps(entry)


def decode_output_cbor(blob: bytes) -> Dict[str, Any]:
    """Decode a CBOR txAuthAgent extension output (client/RP side)."""
    value = cbor.loads(blob)
    if not isinstance(value, dict):
        raise ValueError("decoded CBOR must be a map")
    return value
