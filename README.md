# txAuthAgent — Agent Authorization Profile for the WebAuthn `sign` Extension

**Hardware-backed authorization for AI agent actions.**

**Layer:** Hardware attestation layer for the Empire Stack — above ACI, feeds WitnessOS evidence.

`txAuthAgent` is an **application profile** on top of the W3C WebAuthn
**`sign` extension** (w3c/webauthn PR #2078). The sign extension gives the
cryptographic primitive — a hardware-bound **signing key pair, separate from
the WebAuthn credential**, that signs arbitrary data unaltered. txAuthAgent
defines what an agent authorization *is*: the action payload schema, the
canonical digest passed as the `tbs`, the ceremony wiring, and the
verification rules.

The result is a cryptographically verifiable, human-consented audit trail for
autonomous agent actions, satisfying the EU AI Act's tamper-evident logging
(Art. 12) and human oversight (Art. 14) requirements **in hardware, not in
policy** — and verifiable by *any* party against the published signing key,
without breaking WebAuthn's pairwise-credential privacy. The signed action
evidence this profile produces is consumed by **WitnessOS** for governance
and compliance verification.

This repository is the open **reference implementation** of the draft spec.
It is dependency-free, testable without hardware, and demonstrates the full
flow: agent builds action → hardware key taps and signs → any party verifies.

## Status

- Draft spec: `spec/webauthn-agent-authorization-extension-draft-v0.2.md`
  (content **v0.4** — application-profile reframe; file name retained for
  link stability)
- Reference implementation: this repo (MIT licensed)
- W3C review thread: reply to reviewer feedback (Tim Cappalli) in progress —
  spec v0.4 adopts the `sign` extension and drops the pairwise-credential
  verification path

## Why

The EU AI Act's high-risk provisions are enforceable from August 2, 2026.
Autonomous agents need a standards-based way to prove a human consented, **in
hardware**, to each action they take — and counterparties, regulators and
auditors need to verify that proof without a secret validation server.

The `sign` extension is the right primitive but is deliberately generic: it
signs whatever bytes it is given. txAuthAgent answers the three questions an
application must settle for agent authorization to be interoperable:

1. **What is signed** — a canonical digest over a structured agent action
   payload (RFC 8949 §4.2.1 deterministic CBOR), byte-identical across
   implementations.
2. **How verification is anchored** — against the *signing public key*
   attested at registration and published in the registration record. The
   pairwise WebAuthn credential is never used for third-party verification.
3. **What the audit record is** — a self-contained extension output pairing
   the signature, the digest, the credential binding, the algorithm and the
   UP/UV flags.

## How it works

```
┌──────────────┐  action payload   ┌──────────────────┐  tap!   ┌───────────────┐
│  AI Agent    │ ────────────────▶ │  Hardware Key     │ ─────▶ │  Signs tbs    │
│ (ACI/AIP)    │                   │ (sign extension)  │        │  (ES256/      │
└──────────────┘                   └──────────────────┘        │   EdDSA)      │
        ▲                                                       └──────┬────────┘
        │                                                              │
        │        CBOR extension output (raw signature + audit)         ▼
        └────────────────────────────────────────────  Any party verifies
                                                       against published
                                                       signing key
```

1. Agent constructs an action payload: `action_id`, `action_type`,
   `agent_identity` (ACI URI), `action_descriptor` (contract hash, timestamp,
   nonce).
2. Client computes the canonical digest and passes it as `sign.sign.tbs`,
   with `txAuthAgent` carrying the action context.
3. The authenticator requires a physical gesture (press/tap; PIN/biometric if
   the key policy demands it) and signs the `tbs` unaltered with the separate
   signing key.
4. The authenticator returns the raw signature plus the `txAuthAgent` audit
   record.
5. Any party verifies the signature against the **published signing key** and
   the recomputed digest — no interaction with the agent, no secret server.

## Quickstart

```bash
# Run the demo (no install required)
python3 -m txauthagent.cli

# Run the test suite (105 tests)
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

The `VirtualAuthenticator` implements the full sign-extension flow:
registration generates the signing key (attested, policy-fixed), the signing
private key is deterministically re-derived from the key handle (the device
stores nothing), and signatures verify against the published public key.

## Wire format (summary)

Extension input — registration (`navigator.credentials.create()`):

```json
{
  "sign": { "generateKey": { "algorithms": [-7, -8] } },
  "txAuthAgent": {
    "profile": "txauthagent/sign/v1",
    "agent_identity": {
      "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
      "agent_name": "Sovereign"
    }
  }
}
```

Extension input — authentication / action signing (`navigator.credentials.get()`):

```json
{
  "sign": {
    "sign": {
      "tbs": "<canonical action digest bytes>",
      "keyHandleByCredential": {
        "dHhhdXRoQWdlbnQtY3JlZGVudGlhbA": "<COSE_Key_Ref bytes>"
      }
    }
  },
  "txAuthAgent": {
    "profile": "txauthagent/sign/v1",
    "action": {
      "action_id": "01JSDXQZ3MV8YR9K5WPHKE7N12",
      "action_type": "contract.sign",
      "agent_identity": { "aci_uri": "...", "agent_name": "Sovereign" },
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

```text
sign: {
    signature: bytes            // raw signature over tbs (== agent_action_sig)
}
txAuthAgent: {
    agent_action_sig: bytes,    // ES256/EdDSA signature over the action digest
    action_digest: bytes,       // the exact tbs that was signed (32 bytes)
    agent_cid: bytes,           // credential id binding
    algorithm: -7 | -8,         // COSE — ES256 or EdDSA
    rp_id_hash: bytes,          // SHA-256 of RP ID
    flags: { up: true, uv: bool }
}
```

Action digest: `SHA-256("txAuthAgent" || 0x00 || deterministic-CBOR(payload))`,
where deterministic-CBOR is RFC 8949 §4.2.1 (map keys sorted bytewise by their
deterministic encodings, definite lengths) — byte-for-byte identical across
implementations (interop-tested against `cbor2`).

## Privacy: why verification uses a separate signing key

WebAuthn credentials are **pairwise to their relying party** — exposing them
for third-party verification would let signing keys become a global tracking
identifier. The `sign` extension solves this: at registration the
authenticator creates a **separate signing key pair** that is attested,
bound to the same device, and safe to publish. txAuthAgent verifies raw
signatures against that published key — the pairwise credential stays
pairwise. (This is the v0.4 response to W3C reviewer feedback; full rationale
in spec §3.1.)

## Hardware

| Component | Minimum |
|-----------|---------|
| Authenticator | CTAP 2.2+ with the `sign` extension (in W3C ratification, PR #2078) |
| Algorithm | ES256 (COSE -7) primary — universally supported; EdDSA (COSE -8) where device-supported |
| Transport | USB-C, NFC, BLE |

**Until sign-extension firmware ships**, the bootstrap path carries the
canonical action digest as the standard WebAuthn challenge — this works on
today's FIDO2 hardware (YubiKey 5 Series, Ledger FIDO2 app, Nitrokey 3) and
is demonstrated in `examples/hardware_demo.py`. The extension wire format
itself is proven by the `VirtualAuthenticator` in this repo. Both halves
together form the complete hardware attestation story.

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

## EU AI Act mapping

| Article | Requirement | txAuthAgent |
|---------|-------------|-------------|
| Art. 12 | Tamper-evident logging | Hardware signature over the canonical action digest; any field change breaks the digest check and the signature |
| Art. 14 | Human oversight evidence | `flags.up = 1` — physical gesture on the key at signing time; optional `flags.uv` biometric/PIN |
| Art. 15 | Cybersecurity | Signing key never leaves the device; agent cannot forge or replay |

## Repo layout

```
spec/                    Draft specification (v0.4 content)
txauthagent/
  cbor.py                Minimal CBOR codec (RFC 8949 subset)
  payload.py             Agent action payload schema + validation
  digest.py              Canonical action digest
  extension.py           sign-extension + txAuthAgent wire format
  virtual.py             Software authenticator (sign extension, key handles)
  verify.py              Third-party verification + attestation checks
  cli.py                 End-to-end demo
tests/                   pytest suite (105 tests incl. cbor2 interop)
```

## License

MIT — specification text and reference implementation. Explanatory material
CC BY 4.0. Built by **Empire Labs Pty Ltd** as part of the **Empire Stack**
(ACI / AIP / AJSON) — three open specifications for autonomous agent commerce.

www.empirelabs.com.au

---

<sub>Part of the [WitnessOS launch family](https://github.com/narko4u/witnessos): [witnessos-alpha](https://github.com/narko4u/witnessos-alpha) · [witnessos-compliance](https://github.com/narko4u/witnessos-compliance) · [eu-ai-act-compliance-grade](https://github.com/narko4u/eu-ai-act-compliance-grade) · [witnessos-rogue-agent-audit](https://github.com/narko4u/witnessos-rogue-agent-audit) · [witnessos-agent-asset-registry](https://github.com/narko4u/witnessos-agent-asset-registry) · [witnessos-verifier](https://github.com/narko4u/witnessos-verifier) · [agent-interaction-specs](https://github.com/narko4u/agent-interaction-specs) · [aci-spec](https://github.com/narko4u/aci-spec) · [aip-spec](https://github.com/narko4u/aip-spec) · [ajson](https://github.com/narko4u/ajson) — [Empire Labs Pty Ltd](https://www.empirelabs.com.au)</sub>
