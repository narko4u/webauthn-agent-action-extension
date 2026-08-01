"""End-to-end test: the full txAuthAgent flow, both algorithms, tamper path."""

import pytest

from txauthagent.digest import compute_action_digest
from txauthagent.extension import ALG_EDDSA, ALG_ES256
from txauthagent.verify import verify_agent_action_cbor
from txauthagent.virtual import VirtualAuthenticator

from helpers import make_payload


@pytest.mark.parametrize("algorithm", [ALG_EDDSA, ALG_ES256])
def test_end_to_end_flow(algorithm):
    key = VirtualAuthenticator(algorithm=algorithm, rp_id="empirelabs.com.au")
    payload = make_payload()
    digest = compute_action_digest(payload)
    assert len(digest) == 32

    blob = key.sign_action_cbor(payload)
    assert len(blob) > 0

    result = verify_agent_action_cbor(
        payload, blob, key.public_key_pem, expected_rp_id="empirelabs.com.au"
    )
    assert result.up is True
    assert result.algorithm == algorithm


def test_end_to_end_tamper_detection():
    key = VirtualAuthenticator()
    payload = make_payload()
    blob = key.sign_action_cbor(payload)
    tampered = dict(payload)
    tampered["action_id"] = "01JSDXQZ3MV8YR9K5WPHKE7N99"
    with pytest.raises(ValueError):
        verify_agent_action_cbor(tampered, blob, key.public_key_pem)
