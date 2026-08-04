"""Canonical action digest computation (Section 5.3 of the txAuthAgent draft spec).

The authenticator signs a single digest over the action payload. The digest
must be canonical so any party can recompute it identically:

    digest = SHA-256( "txAuthAgent" || 0x00 || deterministic-CBOR(payload) )

where deterministic-CBOR follows RFC 8949 §4.2.1: map keys sorted in the
bytewise lexicographic order of their deterministic encodings (for the
text-string keys of the action payload this is the length-first order of
§4.2.3), definite-length headers, no floating point. This replaces
the earlier canonical-JSON formulation (sorted keys, whitespace-free) — JSON
string canonicalisation is underspecified across implementations, while
deterministic CBOR is normatively defined in RFC 8949.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from . import cbor
from .payload import payload_to_canonical_dict

__all__ = [
    "compute_action_digest",
    "compute_action_digest_from_dict",
    "canonical_cbor",
    "DIGEST_CONTEXT",
]

DIGEST_CONTEXT = b"txAuthAgent\x00"


def _canonical_cbor(obj: Any) -> bytes:
    return cbor.dumps(obj, deterministic=True)


def compute_action_digest_from_dict(canonical: Dict[str, Any]) -> bytes:
    """SHA-256 over context + deterministic CBOR of an already-canonical dict."""
    return hashlib.sha256(DIGEST_CONTEXT + _canonical_cbor(canonical)).digest()


def compute_action_digest(payload: Dict[str, Any]) -> bytes:
    """Compute the action digest for a validated payload dict."""
    canonical = payload_to_canonical_dict(payload)
    return compute_action_digest_from_dict(canonical)


def canonical_cbor(payload: Dict[str, Any]) -> bytes:
    """Return the exact deterministic CBOR bytes for a payload (useful for tests)."""
    return _canonical_cbor(payload_to_canonical_dict(payload))
