"""txauthagent — Reference implementation of the txAuthAgent agent-authorization profile.

Hardware-backed authorization for AI agent actions. txAuthAgent is an application profile
built on the WebAuthn `sign` extension (w3c/webauthn PR #2078, an open draft — not ours and
not yet ratified). The profile's own client-extension identifier, `txAuthAgent`, is NOT
registered in the IANA WebAuthn Extension Identifiers registry; treat it as profile-local.

The extension lets a hardware authenticator (YubiKey, Ledger, Nitrokey, ...) sign an
*agent action payload* — the agent's identity (ACI URI), the action to be performed,
and a timestamped nonce — producing a cryptographically verifiable, human-consented
audit trail. This package is a self-contained, dependency-free implementation of the
wire format and verification logic described in the draft specification.

Public API:
    payload    — build and validate agent action payloads
    digest     — canonical action digest (what actually gets signed)
    extension  — encode/decode WebAuthn extension input/output JSON
    cbor       — minimal CBOR codec (RFC 8949 subset used by the spec)
    virtual    — software authenticator for development/testing
    verify     — verify an agent action signature
"""

__version__ = "0.2.0"
__all__ = ["payload", "digest", "extension", "cbor", "virtual", "verify"]
