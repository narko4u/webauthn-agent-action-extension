# txAuthAgent — WebAuthn Agent Authorization Extension

**Hardware-backed authorization for AI agent actions.**

`txAuthAgent` is a proposed WebAuthn extension (for IANA registration under
RFC 8809) that lets a hardware authenticator — YubiKey, Ledger, Nitrokey —
sign an *agent action payload*. The result is a cryptographically verifiable,
human-consented audit trail for autonomous agent actions, satisfying the EU
AI Act's tamper-evident logging (Art. 12) and human oversight (Art. 14)
requirements in hardware, not in policy.

This repository is the open **reference implementation** of the draft spec.
It is dependency-free, testable without hardware, and demonstrates the full
flow: agent builds action → hardware key taps and signs → any relying party
verifies.

## Status

- Draft spec: `spec/webauthn-agent-authorization-extension-draft-v0.2.md`
- Reference implementation: this repo (MIT licensed)
- Submitted to `public-webauthn@w3.org` for expert review (Aug 2, 2026)

## Why

The IANA WebAuthn Extension Identifiers registry has 15 entries —
authentication, human transaction confirmation, credential management,
device properties — and **zero for agent action authorization**. With the EU
AI Act's high-risk provisions enforceable from August 2, 2026, autonomous
agents need a standards-based way to prove a human consented, in hardware,
to each action they take. `txAuthAgent` fills that gap.

**Why a new extension identifier?** WebAuthn already ships transaction-auth
extensions (`txAuthSimple`/`txAuthGeneric`) and a plain assertion can carry a
digest as the challenge. Those mechanisms fall short of a *verifiable agent
authorization standard* — the full gap analysis (and the bootstrap path that
works on today's hardware) is in spec §3.1.

## How it works

```
┌──────────────┐   action payload   ┌──────────────────┐   tap!   ┌───────────────┐
│  AI Agent    │ ─────────────────▶ │  Hardware Key     │ ───────▶ │    Signs      │
│ (ACI/AIP)    │                    │ (CTAP 2.2+,      │          │  (ES256/      │
└──────────────┘                    │  ES256/EdDSA)    │          │   EdDSA)      │
        ▲                           └──────────────────┘          └──────┬────────┘
        │                                                                │
        │                  CBOR extension output (signed digest)          ▼
        └───────────────────────────────────────────────  Relying Party verifies
                                                          (no secret server)
```

1. Agent constructs an action payload: `action_id`, `action_type`,
   `agent_identity` (ACI URI), `action_descriptor` (contract hash, timestamp,
   nonce).
2. Agent invokes `navigator.credentials.get()` with the `txAuthAgent`
   extension input carrying the payload.
3. The authenticator presents the action to the human and requires a physical
   gesture (press/tap) before signing.
4. The authenticator returns a CBOR extension output: ES256/EdDSA signature
   over the canonical action digest plus UP/UV flags.
5. Any relying party verifies the signature against the registered credential
   — no interaction with the agent, no secret validation server.

## Quickstart

```bash
# Run the demo (no install required)
python3 -m txauthagent.cli

# Run the test suite
python3 -m pytest tests/ -q

# Use the library
python3
>>> from txauthagent.payload import build_action_payload
>>> from txauthagent.virtual import VirtualAuthenticator
>>> from txauthagent.verify import verify_agent_action_cbor
>>>
>>> payload = build_action_payload(
...     action_id="01JSDXQZ3MV8YR9K5WPHKE7N12",
...     action_type="contract.sign",
...     agent_identity={"aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
...                     "agent_name": "Sovereign"},
...     action_descriptor={"contract_hash": "sha256:ab12...", "timestamp": "2026-08-02T09:30:00Z",
...                        "nonce": "z7GkqLm9pTvR2XbN"},
... )
>>>
>>> key = VirtualAuthenticator(rp_id="empirelabs.com.au")
>>> blob = key.sign_action_cbor(payload)          # simulates the tap
>>> result = verify_agent_action_cbor(payload, blob, key.public_key_pem,
...                                   expected_rp_id="empirelabs.com.au")
>>> print(result.up, result.algorithm_name)
True ES256 (P-256)
```

## Wire format (summary)

Extension input (`AuthenticationExtensionsClientInputsJSON`):

```json
{
  "txAuthAgent": {
    "agent_identity": {
      "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
      "agent_name": "Sovereign"
    },
    "action": {
      "action_id": "01JSDXQZ3MV8YR9K5WPHKE7N12",
      "action_type": "contract.sign",
      "action_descriptor": {
        "contract_hash": "sha256:4a84c...",
        "timestamp": "2026-08-02T09:30:00Z",
        "nonce": "z7GkqLm9pTvR2XbN..."
      }
    }
  }
}
```

Extension output (CBOR, wrapped in `AuthenticationExtensionsClientOutputsJSON`):

```
txAuthAgent: {
    agent_action_sig: bytes,   // ES256/EdDSA signature over action digest
    agent_cid: bytes,          // credential id
    algorithm: -7 | -8,        // COSE — ES256 or EdDSA
    rp_id_hash: bytes,         // SHA-256 of RP ID
    flags: { up: true, uv: bool }
}
```

Action digest: `SHA-256("txAuthAgent" || 0x00 || deterministic-CBOR(payload))`,
where deterministic-CBOR is RFC 8949 §4.2.1 (map keys sorted bytewise by their
deterministic encodings, definite lengths) — byte-for-byte identical across
implementations.

## Hardware

| Component | Minimum |
|-----------|---------|
| Authenticator | CTAP 2.2+ with resident key + signature extension |
| Algorithm | ES256 (COSE -7) primary — universally supported; EdDSA (COSE -8) where device-supported |
| Transport | USB-C, NFC, BLE |

Confirmed working with Ledger Flex/Stax/Nano X/S Plus (FIDO2 app, ES256),
YubiKey 5 Series (CTAP 2.2 attested — **ES256 only**, no Ed25519), Nitrokey 3
(ES256/EdDSA). For development without hardware,
use the `VirtualAuthenticator` (this repo) or the FIDO2 MDS virtual
authenticator.

### Hardware demo (real device)

`examples/hardware_demo.py` signs an agent action on a physical FIDO2 device
and prints a verifiable attestation evidence block — the device tap is the
human-consent proof (EU AI Act Art. 12/14):

```bash
pip install fido2 cryptography
python examples/hardware_demo.py              # real device over USB (CTAP2)
python examples/hardware_demo.py --simulate   # no hardware needed
python examples/hardware_demo.py --output evidence.json --json
```

You will be prompted to tap the key twice: once to register a fresh
credential, once to sign the action digest. Real authenticator firmware does
not implement the `txAuthAgent` extension yet, so the canonical action digest
is carried as the WebAuthn challenge; the extension wire format itself is
proven by the `VirtualAuthenticator`. Both halves together form the complete
hardware attestation story.

## EU AI Act mapping

| Article | Requirement | txAuthAgent |
|---------|-------------|-------------|
| Art. 12 | Tamper-evident logging | Hardware signature over `agent_id + action_id + timestamp + contract_hash`; any field change breaks the signature |
| Art. 14 | Human oversight evidence | `flags.up = 1` — physical gesture on the key at signing time; optional `flags.uv` biometric/PIN |
| Art. 15 | Cybersecurity | Private key never leaves the device; agent cannot forge or replay |

## Repo layout

```
spec/                    Draft specification (v0.2)
txauthagent/
  cbor.py                Minimal CBOR codec (RFC 8949 subset)
  payload.py             Agent action payload schema + validation
  digest.py              Canonical action digest
  extension.py           WebAuthn extension input/output wire format
  virtual.py             Software authenticator for dev/testing
  verify.py              Relying-party signature verification
  cli.py                 End-to-end demo
tests/                   pytest suite (75 tests)
```

## License

MIT — specification text and reference implementation. Explanatory material
CC BY 4.0. Built by **Empire Labs Pty Ltd** as part of the **Empire Stack**
(ACI / AIP / AJSON) — three open specifications for autonomous agent commerce.

www.empirelabs.com.au
