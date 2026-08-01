"""Canonical action digest computation (Section 5 of the txAuthAgent draft spec).

The authenticator signs a single digest over the action payload. The digest
must be canonical so any party can recompute it identically:

    digest = SHA-256( "txAuthAgent" || 0x00 || canonical-JSON(payload) )

where canonical-JSON is produced by payload_to_canonical_dict() serialized
with sorted keys, no whitespace (deterministic byte-for-byte).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from .payload import payload_to_canonical_dict

__all__ = ["compute_action_digest", "compute_action_digest_from_dict", "DIGEST_CONTEXT"]

DIGEST_CONTEXT = b"txAuthAgent\x00"


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_action_digest_from_dict(canonical: Dict[str, Any]) -> bytes:
    """SHA-256 over context + canonical JSON of an already-canonical dict."""
    return hashlib.sha256(DIGEST_CONTEXT + _canonical_json(canonical)).digest()


def compute_action_digest(payload: Dict[str, Any]) -> bytes:
    """Compute the action digest for a validated payload dict."""
    canonical = payload_to_canonical_dict(payload)
    return compute_action_digest_from_dict(canonical)


def canonical_json(payload: Dict[str, Any]) -> bytes:
    """Return the exact canonical JSON bytes for a payload (useful for tests)."""
    return _canonical_json(payload_to_canonical_dict(payload))
