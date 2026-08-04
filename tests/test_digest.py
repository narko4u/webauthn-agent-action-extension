"""Digest tests — canonical SHA-256 action digest (Section 5.3 of the spec).

The digest is defined as:

    digest = SHA-256( "txAuthAgent" || 0x00 || deterministic-CBOR(payload) )

where deterministic-CBOR follows RFC 8949 §4.2.1 (sorted map keys).
"""

import hashlib

from txauthagent import cbor
from txauthagent.digest import (
    DIGEST_CONTEXT,
    canonical_cbor,
    compute_action_digest,
)

from helpers import make_payload


def test_digest_is_sha256_32_bytes():
    payload = make_payload()
    d = compute_action_digest(payload)
    assert len(d) == 32
    assert d == hashlib.sha256(DIGEST_CONTEXT + canonical_cbor(payload)).digest()


def test_digest_deterministic():
    # Same payload object must always produce the same digest
    payload = make_payload()
    assert compute_action_digest(payload) == compute_action_digest(payload)


def test_digest_independent_of_key_insertion_order():
    # RFC 8949 §4.2.1: map keys are sorted, so identical payloads with
    # different key insertion order MUST hash identically.
    p1 = make_payload()
    p2 = make_payload()
    # Rebuild p2's nested dicts in reverse insertion order
    p2["agent_identity"] = {k: p1["agent_identity"][k] for k in reversed(list(p1["agent_identity"]))}
    p2["action_descriptor"] = {k: p1["action_descriptor"][k] for k in reversed(list(p1["action_descriptor"]))}
    assert compute_action_digest(p2) == compute_action_digest(p1)


def test_digest_changes_with_any_field():
    base = make_payload()
    d0 = compute_action_digest(base)

    # Change contract hash
    p = make_payload()
    p["action_descriptor"]["contract_hash"] = "sha256:" + "0" * 64
    assert compute_action_digest(p) != d0

    # Change timestamp
    p = make_payload()
    p["action_descriptor"]["timestamp"] = "2026-08-03T00:00:00Z"
    assert compute_action_digest(p) != d0

    # Change action id
    p = make_payload()
    p["action_id"] = "01JSDXQZ3MV8YR9K5WPHKE7N99"
    assert compute_action_digest(p) != d0


def test_canonical_cbor_is_deterministic_and_sorted():
    raw = canonical_cbor(make_payload())
    # Deterministic CBOR is parseable...
    value = cbor.loads(raw)
    assert isinstance(value, dict)
    assert value["action_type"] == "contract.sign"
    # ...and the top-level map is bytewise-sorted per RFC 8949 §4.2.1
    # (shortest key first: "prompt" is 6 chars, "action_id" is 9, ...).
    assert raw.startswith(b"\xa5\x66prompt")


def _fixed_payload():
    """Payload with a fixed nonce — used by the golden digest vector."""
    from txauthagent.payload import build_action_payload

    from helpers import contract_hash

    return build_action_payload(
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
            "nonce": "fixed-test-nonce-0123456789abcdef",
        },
        prompt="Sidebar: agent authorised — sign for SoverBot",
    )


def test_golden_cbor_vector():
    """Cross-implementation anchor: exact deterministic CBOR bytes.

    Reproduce these bytes in any conforming RFC 8949 §4.2.1 encoder
    (e.g. cbor2 with canonical=True) and the digest must match.
    """
    expected_cbor = (
        "a56670726f6d7074782f536964656261723a206167656e7420617574686f726973656420e28094"
        "207369676e20666f7220536f766572426f7469616374696f6e5f6964781a30314a534458515a33"
        "4d56385952394b355750484b45374e31326b616374696f6e5f747970656d636f6e74726163742e"
        "7369676e6e6167656e745f6964656e74697479a3676163695f757269783768747470733a2f2f65"
        "6d706972656c6162732e636f6d2e61752f2e77656c6c2d6b6e6f776e2f6163692f6964656e7469"
        "74792e6a736f6e696167656e745f6469646f6469643a6b65793a7a364d6b2e2e2e6a6167656e74"
        "5f6e616d6569536f7665726569676e71616374696f6e5f64657363726970746f72a4656e6f6e63"
        "65782166697865642d746573742d6e6f6e63652d30313233343536373839616263646566697469"
        "6d657374616d7074323032362d30382d30325430393a33303a30305a6c636f756e746572706172"
        "7479a1676163695f757269783b68747470733a2f2f73706f74626f7474726164696e672e636f6d"
        "2e61752f2e77656c6c2d6b6e6f776e2f6163692f6964656e746974792e6a736f6e6d636f6e7472"
        "6163745f6861736878477368613235363a66623336323566626539376465616239343561663939"
        "38323836376139633436363765643735316564396661663565623934653665393864323030623263"
        "6336"
    )
    assert canonical_cbor(_fixed_payload()).hex() == expected_cbor


def test_golden_digest_vector():
    """Cross-implementation anchor: exact digest bytes for the fixed payload."""
    assert compute_action_digest(_fixed_payload()).hex() == (
        "c5a37c0940a89c91272b74c0729f73fb22938fdf3162f440f0b99b28f1c0814f"
    )
