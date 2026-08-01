"""Digest tests — canonical SHA-256 action digest (Section 5 of the spec)."""

import hashlib

from txauthagent.digest import (
    DIGEST_CONTEXT,
    canonical_json,
    compute_action_digest,
)

from helpers import make_payload


def test_digest_is_sha256_32_bytes():
    payload = make_payload()
    d = compute_action_digest(payload)
    assert len(d) == 32
    assert d == hashlib.sha256(DIGEST_CONTEXT + canonical_json(payload)).digest()


def test_digest_deterministic():
    # Same payload object must always produce the same digest
    payload = make_payload()
    assert compute_action_digest(payload) == compute_action_digest(payload)


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


def test_canonical_json_no_whitespace_sorted():
    raw = canonical_json(make_payload())
    # No pretty-printing: no newlines, no separator spaces outside string values
    assert b"\n" not in raw
    assert b'", "' not in raw
    assert b'": "' not in raw
    assert raw.startswith(b'{"action_descriptor":')
