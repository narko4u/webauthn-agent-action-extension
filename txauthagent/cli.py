"""Command-line demo of the txAuthAgent flow.

Shows the full loop without hardware:

    agent builds action payload
        -> virtual authenticator "taps" and signs
        -> CBOR extension output produced
        -> verifier recomputes digest and checks signature
        -> (tampered payload fails)

Usage:
    python -m txauthagent.cli
    txauthagent           (if installed)
"""

from __future__ import annotations

import hashlib
import secrets
import sys

from .digest import compute_action_digest, canonical_json
from .extension import EXTENSION_ID, decode_output_cbor
from .payload import build_action_payload
from .verify import verify_agent_action, verify_agent_action_cbor
from .virtual import VirtualAuthenticator


def _contract_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def demo() -> int:
    print("=" * 70)
    print("txAuthAgent — WebAuthn Agent Authorization Extension (reference impl)")
    print("=" * 70)

    # 1. Build the agent action payload
    payload = build_action_payload(
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
            "contract_hash": _contract_hash("Empire Labs <-> SpotBot Trading: services agreement v1"),
            "timestamp": "2026-08-02T09:30:00Z",
            "nonce": secrets.token_urlsafe(32),
        },
        prompt="Sidebar: agent authorised — sign for SoverBot",
    )
    print("\n[1] Agent action payload")
    print(f"    action_id    : {payload['action_id']}")
    print(f"    action_type  : {payload['action_type']}")
    print(f"    agent        : {payload['agent_identity']['agent_name']} "
          f"({payload['agent_identity']['aci_uri']})")
    digest = compute_action_digest(payload)
    print(f"    digest       : sha256:{digest.hex()[:32]}...")
    print(f"    canonical    : {canonical_json(payload).decode()[:120]}...")

    # 2. Virtual authenticator signs (simulates hardware tap)
    key = VirtualAuthenticator(rp_id="empirelabs.com.au")
    print("\n[2] Authenticator (virtual hardware key)")
    print(f"    algorithm    : {key.algorithm} (EdDSA)")
    print(f"    credential   : {key.credential_id.hex()[:16]}...")
    cbor_blob = key.sign_action_cbor(payload)
    outputs = decode_output_cbor(cbor_blob)
    entry = outputs[EXTENSION_ID]
    print(f"    signature    : {entry['agent_action_sig'].hex()[:32]}... ({len(entry['agent_action_sig'])} bytes)")
    print(f"    flags        : up={entry['flags']['up']} uv={entry['flags']['uv']}")
    print(f"    CBOR blob    : {len(cbor_blob)} bytes")

    # 3. Verify (relying party side)
    print("\n[3] Verification (relying party)")
    result = verify_agent_action_cbor(
        payload,
        cbor_blob,
        key.public_key_pem,
        expected_rp_id="empirelabs.com.au",
    )
    print(f"    status       : ✅ PASS  ({result.algorithm_name}, up={result.up})")

    # 4. Tamper detection
    tampered = dict(payload)
    tampered["action_descriptor"] = dict(payload["action_descriptor"])
    tampered["action_descriptor"]["contract_hash"] = _contract_hash("MALICIOUS REWRITE")
    try:
        verify_agent_action_cbor(tampered, cbor_blob, key.public_key_pem)
        print("    tamper test  : ❌ FAIL (signature accepted on tampered payload!)")
        return 1
    except ValueError as exc:
        print(f"    tamper test  : ✅ PASS  ({exc})")

    print("\n" + "=" * 70)
    print("Flow complete. Hardware key never exposed private material.")
    print("Spec + docs: github.com/narko4u/webauthn-agent-action-extension")
    print("=" * 70)
    return 0


def main() -> int:
    try:
        return demo()
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
