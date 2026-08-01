"""Agent action payload schema (Section 4.2 of the txAuthAgent draft spec).

An *agent action payload* describes an autonomous action an agent wants
authorized. The authenticator signs the canonical digest of this payload
(see digest.py); any relying party can verify the signature without
touching the agent.

Fields:
    action_id        — unique action identifier (e.g. ULID/random id)
    action_type      — machine-readable action category (e.g. "contract.sign")
    agent_identity   — dict with aci_uri / agent_name / agent_id / aip_endpoint
    action_descriptor — dict with counterparty / contract_hash / timestamp / nonce
    prompt           — optional human-readable prompt shown by the authenticator
"""

from __future__ import annotations

import re
from typing import Any, Dict

__all__ = [
    "ACTION_TYPE_RE",
    "build_action_payload",
    "validate_action_payload",
    "payload_to_canonical_dict",
]

ACTION_TYPE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

REQUIRED_TOP_LEVEL = ("action_id", "action_type", "agent_identity", "action_descriptor")
REQUIRED_IDENTITY = ("aci_uri", "agent_name")
REQUIRED_DESCRIPTOR = ("contract_hash", "timestamp", "nonce")


def build_action_payload(
    *,
    action_id: str,
    action_type: str,
    agent_identity: Dict[str, Any],
    action_descriptor: Dict[str, Any],
    prompt: str | None = None,
) -> Dict[str, Any]:
    """Build and validate an agent action payload."""
    payload: Dict[str, Any] = {
        "action_id": action_id,
        "action_type": action_type,
        "agent_identity": dict(agent_identity),
        "action_descriptor": dict(action_descriptor),
    }
    if prompt is not None:
        payload["prompt"] = prompt
    validate_action_payload(payload)
    return payload


def validate_action_payload(payload: Dict[str, Any]) -> None:
    """Validate a payload against the spec. Raises ValueError on failure."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")
    for field in REQUIRED_TOP_LEVEL:
        if field not in payload:
            raise ValueError(f"missing required field: {field}")

    action_id = payload["action_id"]
    if not isinstance(action_id, str) or not action_id.strip():
        raise ValueError("action_id must be a non-empty string")

    action_type = payload["action_type"]
    if not isinstance(action_type, str) or not ACTION_TYPE_RE.match(action_type):
        raise ValueError(
            f"action_type must match {ACTION_TYPE_RE.pattern!r}, got {action_type!r}"
        )

    identity = payload["agent_identity"]
    if not isinstance(identity, dict):
        raise ValueError("agent_identity must be a dict")
    for field in REQUIRED_IDENTITY:
        if field not in identity:
            raise ValueError(f"agent_identity missing required field: {field}")
    if not isinstance(identity.get("aci_uri"), str) or not identity["aci_uri"].startswith(("https://", "http://")):
        raise ValueError("agent_identity.aci_uri must be an http(s) URL")
    if "agent_did" in identity and not isinstance(identity["agent_did"], str):
        raise ValueError("agent_identity.agent_did must be a string")

    descriptor = payload["action_descriptor"]
    if not isinstance(descriptor, dict):
        raise ValueError("action_descriptor must be a dict")
    for field in REQUIRED_DESCRIPTOR:
        if field not in descriptor:
            raise ValueError(f"action_descriptor missing required field: {field}")
    contract_hash = descriptor["contract_hash"]
    if not isinstance(contract_hash, str) or not contract_hash.startswith("sha256:"):
        raise ValueError("action_descriptor.contract_hash must be 'sha256:<hex>'")
    timestamp = descriptor["timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError("action_descriptor.timestamp must be an ISO-8601 string")
    nonce = descriptor["nonce"]
    if not isinstance(nonce, str) or len(nonce) < 16:
        raise ValueError("action_descriptor.nonce must be a string of >= 16 chars")

    if "prompt" in payload and not isinstance(payload["prompt"], str):
        raise ValueError("prompt must be a string")


def payload_to_canonical_dict(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical, insertion-stable dict used for digest computation."""
    canonical = {
        "action_id": payload["action_id"],
        "action_type": payload["action_type"],
        "agent_identity": {
            "aci_uri": payload["agent_identity"]["aci_uri"],
            "agent_name": payload["agent_identity"]["agent_name"],
        },
        "action_descriptor": {
            "contract_hash": payload["action_descriptor"]["contract_hash"],
            "timestamp": payload["action_descriptor"]["timestamp"],
            "nonce": payload["action_descriptor"]["nonce"],
        },
    }
    identity = payload["agent_identity"]
    for opt in ("agent_id", "agent_did", "aip_endpoint"):
        if opt in identity:
            canonical["agent_identity"][opt] = identity[opt]
    descriptor = payload["action_descriptor"]
    for opt in ("counterparty", "amount", "currency", "memo"):
        if opt in descriptor:
            canonical["action_descriptor"][opt] = descriptor[opt]
    if "prompt" in payload:
        canonical["prompt"] = payload["prompt"]
    return canonical
