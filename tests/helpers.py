"""Shared test helpers for txauthagent."""

import hashlib
import secrets

from txauthagent.payload import build_action_payload


def contract_hash(text: str = "Empire Labs <-> SpotBot Trading: services agreement v1") -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_payload(**overrides):
    base = dict(
        action_id="01JSDXQZ3MV8YR9K5WPHKE7N12",
        action_type="contract.sign",
        agent_identity={
            "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
            "agent_name": "Sovereign",
            "agent_did": "did:key:z6Mk...",
        },
        action_descriptor={
            "counterparty": {
                "aci_uri": "https://spotbottrading.com.au/.well-known/aci/identity.json"
            },
            "contract_hash": contract_hash(),
            "timestamp": "2026-08-02T09:30:00Z",
            "nonce": secrets.token_urlsafe(32),
        },
        prompt="Sidebar: agent authorised — sign for SoverBot",
    )
    base.update(overrides)
    return build_action_payload(**base)
