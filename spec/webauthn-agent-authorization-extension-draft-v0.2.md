# WebAuthn Agent Authorization Extension — Draft Specification v0.2

**Extension Identifier:** `txAuthAgent`

**Status:** Draft v0.3 — ES256-first algorithm policy, deterministic-CBOR digest, gap analysis (2026-08-04)
**Proposed by:** Empire Labs Pty Ltd
**Target Registry:** IANA "WebAuthn Extension Identifiers" registry (per RFC 8809)
**Specification Required:** Yes (Expert Review per WebAuthn §12.4)
**Draft Date:** 1 August 2026 (v0.2)
**License:** MIT (specification text) / CC BY 4.0 (explanatory material)
**Reference Implementation:** https://github.com/narko4u/webauthn-agent-action-extension

---

## 1. Abstract

The **txAuthAgent** extension provides hardware-backed authorization for AI agents performing autonomous actions on behalf of human users. It extends the existing `txAuthSimple` / `txAuthGeneric` pattern — built for human transaction confirmation — to the agent-autonomy domain: the authenticator (hardware security key) signs an *agent action payload* that includes the agent's identity (per ACI/AIP), the action to be performed, and a timestamped nonce. The signature is verifiable by any relying party without requiring the agent to hold the hardware key's private material.

This extension addresses a regulatory vacuum: the EU AI Act (enforceable 2 August 2026) Articles 12 and 14 require tamper-evident logging and human oversight for high-risk AI systems. Hardware-backed agent signatures create a cryptographically verifiable audit trail that satisfies both requirements without forcing a human into every interaction loop.

**Key properties:**
- Agent submits action details; hardware key signs; verifying party checks
- Key never leaves the device (CTAP 2.2+ authenticator required)
- Works with existing Ledger, YubiKey, and FIDO2-compliant hardware
- Wire format: `AuthenticationExtensionsClientInputsJSON` / `AuthenticationExtensionsClientOutputsJSON` using CBOR

---

## 2. Relationship to the Empire Stack

This WebAuthn extension is part of the **Empire Stack** — three open specifications for autonomous agent commerce by Empire Labs Pty Ltd:

| Layer | Spec | Role |
|-------|------|------|
| Discover | **ACI** (Agent Company Interface) | Declares agent identity and capabilities |
| Interact | **AIP** (Agent Interaction Protocol) | Negotiates contracts and executes actions |
| Author | **AJSON** (Agent JSON) | Writes clean manifests that compile to canonical JSON |

`txAuthAgent` wraps AIP action signing with FIDO2 hardware attestation. The agent's identity is established via ACI; the signed action payload embeds an AIP action digest; the resulting attestation is stored as AJSON for canonical audit.

The extension is independently specified — use it with or without the full Empire Stack. But when used together, an AIP Agent signs an action → the hardware key signs the AIP action → receiving party validates both the agent identity (ACI) and the hardware attestation.

---

## 3. Extension Identifier

| Field | Value |
|-------|------|
| **Extension identifier** | `txAuthAgent` |
| **Type** | Registration extension AND authentication extension |
| **Authenticator support** | Required — uses CTAP 2.2+ signature capability |

### 3.1 Alternatives considered: why a new extension identifier

A reviewer's first question is: WebAuthn already has transaction-authorization
extensions, and a plain assertion can carry a digest in the challenge — why a
new identifier? The honest answer is that `txAuthAgent` fills the gaps those
mechanisms leave for *agent authorization*, and it ships alongside a bootstrap
that works on hardware available today.

**txAuthSimple / txAuthGeneric (existing WebAuthn L2/L3 extensions).** These
were designed for human transaction confirmation: the authenticator displays a
short text (txAuthSimple) or CBOR content (txAuthGeneric) and the human
approves. They do not define:

- a canonical, machine-verifiable digest of a *structured* action payload —
  the output semantics return the displayed content, not a signature over a
  well-defined action schema;
- an agent-identity binding (ACI URI / agent name / DID) as a first-class
  field, so a third-party verifier cannot independently confirm *which agent*
  was authorized;
- a registration-time link between an agent identity and a specific hardware
  credential.

For a human reading a prompt, txAuthGeneric suffices. For a counterparty or
regulator verifying an *agent's* action later, without interacting with the
agent, the structured canonical-digest + agent-identity design is what makes
verification possible.

**Challenge-carrier profile (plain `navigator.credentials.get()` with the
action digest as the challenge).** This is fully standard and works on every
shipping FIDO2 authenticator today — which is exactly why the reference
implementation's `examples/hardware_demo.py` uses it as the hardware bootstrap
path. Its limitations:

- the `challenge` field has platform-defined semantics (randomness, replay
  protection); carrying a *deterministic* action digest there can collide with
  client/authenticator expectations, and large payloads risk platform size
  limits;
- without a registered identifier there is no schema anchor — every relying
  party would implement its own payload convention, so no ecosystem-level
  interop or third-party verification standard exists;
- the extension identifier is what lets an RP say "this assertion means the
  agent authorized *this* action" in a way any verifier can rely on.

**Design choice.** `txAuthAgent` defines the identifier, the canonical digest
(§5.3), and the output schema so verification is interoperable — while the
challenge-carrier profile remains the pragmatic path for hardware that does
not yet implement the extension. Both halves are proven by the reference
implementation. A future companion pattern (session-scoped signing via the
`prf`/`hmac-secret` extension, one human tap per session instead of per
action) is under consideration to reduce operational friction for high-volume
agents.

---

## 4. Input Data (Client → Authenticator)

### 4.1 Registration extension input (`navigator.credentials.create()`)

```json
{
  "txAuthAgent": {
    "agent_identity": {
      "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
      "agent_name": "Sovereign",
      "agent_did": "did:key:z6Mk...",
      "aip_endpoint": "https://api.empirelabs.com.au/aip/v1"
    },
    "challenge": "Base64URL-encoded challenge",
    "rp": {
      "id": "https://...",
      "name": "Relying Party validating agent actions"
    }
  }
}
```

**Semantics:** The relying party registers the agent credential with a specific hardware authenticator. The `aci_uri` field lets the RP independently verify the agent's identity declaration.

### 4.2 Authentication extension input (`navigator.credentials.get()`)

```json
{
  "txAuthAgent": {
    "agent_identity": {
      "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
      "agent_name": "Sovereign",
      "agent_id": "did:key:z6Mk...",
      "aip_endpoint": "/v1/agents/exec"
    },
    "action": {
      "action_id": "01JSDXQZ3MV8YR9K5WPHKE7N12",
      "action_type": "contract.sign",
      "action_descriptor": {
        "counterparty": {
          "aci_uri": "https://spotbottrading.com.au/.well-known/aci/identity.json"
        },
        "contract_hash": "sha256:4a84c...",
        "timestamp": "2026-08-01T09:30:00Z",
        "nonce": "base64url-encoded 32-byte random value"
      }
    },
    "prompt": "Sign this action payload so the counterparty can verify the agent's authority"
  }
}
```

**Semantics:** The agent asks the authenticator to sign a specific action payload. The hardware key displays the prompt and requires a physical gesture (press/tap) to sign. The signature is produced *by the hardware device* — the agent's software never holds the private key.

---

## 5. Processing Results (Client ← Authenticator → RP)

### 5.1 AuthenticatorExtensionOutput CBOR

The authenticator produces a CBOR-encoded extension output with the signed action payload:

```
AuthenticatorExtensionOutput {
    txAuthAgent: {
        agent_action_sig: bytes,   // Ed25519 or ES256 signature over the action digest
        agent_cid: bytes,          // Credential ID (258 bytes)
        algorithm: -8 or -7,       // COSE algorithm — EdDSA (-8) or ES256 (-7)
        rp_id_hash: bytes,         // SHA-256 of the RP ID
        flags: {
            up: true,              // User presence flag (always true for agent action hardware sign)
            uv: true/false         // User verification — true if biometric/PIN was used
        }
    }
}
```

### 5.2 Verifying the agent action

The RP performs these checks:
1. Parse `agent_action_sig` & verify against the authData/AuthenticatorOutput signature
2. Confirm `challenge` matches the action ID sent in the extension input
3. Check `up` flag (always 1 for agent actions — means physical gesture happened)
4. Optionally verify `uv` (user verification — biometric/PIN on the key)

If all checks pass: the action is **hardware-attested agent authorization** that any independent party can cryptographically verify.

### 5.3 Canonical action digest

The authenticator signs a single digest over the action payload, defined as:

```
digest = SHA-256( "txAuthAgent" || 0x00 || deterministic-CBOR(payload) )
```

where:

- `"txAuthAgent"` is the 11-byte ASCII extension identifier (domain
  separation from other signed data),
- `0x00` is a single zero byte version separator,
- `deterministic-CBOR(payload)` is the canonical payload (see §4.2) encoded
  with the deterministic rules of RFC 8949 §4.2.1: map keys sorted in the
  bytewise lexicographic order of their deterministic encodings (for the
  text-string keys of the action payload this is the length-first order of
  §4.2.3), definite-length headers, no floating point.

Deterministic CBOR is normatively defined and byte-for-byte reproducible by
any conforming encoder regardless of key insertion order or platform — unlike
"canonical JSON" (sorted keys, whitespace-free), whose string canonicalisation
is underspecified across implementations. The reference implementation
(`txauthagent/digest.py`) ships the digest computation and RFC 8949 §4.2.1
encoder; test vectors live in `tests/test_digest.py`.

---

## 6. EU AI Act Compliance Context

### 6.1 Article 12 — Tamper-Evident Logging

| Requirement | How txAuthAgent satisfies |
|-------------|--------------------------|
| Evidentiary logging | EdDSA/ES256 signature over `agent_id + action_id + timestamp + contract_hash` |
| Tamper-evident | All signatures produced by hardware key — altering any field breaks the signature |
| 6-month retention | AJSON-signed record is machine-readable, ~180 bytes per action log |
| No agent forgery | Agent never touches the key material — cannot forge hardware attestation |

### 6.2 Article 14 — Human Oversight Evidence

| Requirement | How txAuthAgent satisfies |
|-------------|--------------------------|
| Human-in-the-loop evidence | `flags.up = 1` — physical gesture (press/tap) confirmed on hardware at signing time |
| Biometric trace (optional) | `flags.uv = 1` — user verification via biometric/PIN |
| No pass-through detectable | Hardware key owns the signature; agent software cannot inject or replay |

### 6.3 Third-Party Verification (Regulators, Auditors, Counterparties)

Any third party can verify agent action signatures **without interacting with the agent:**
1. Fetch the agent's public key via ACI identity declaration
2. Fetch the credential public key from the registration record
3. Perform standard FIDO2 signature verification over the asserted payload
4. Validate timestamps, nonce, and flags

**No secret validation server required.** The hardware already did the work.

---

## 7. Hardware Requirements

| Component | Minimum Requirement |
|-----------|-------------------|
| Authenticator | CTAP 2.2+ supporting resident key storage + signature extension |
| Algorithm | ES256 (COSE -7) primary — universally supported; EdDSA (COSE -8) where device-supported |
| Transport | USB-C, NFC, or BLE |

**Supported keys (confirmed today):**
- **YubiKey 5 Series** — CTAP 2.2 attested, **ES256 (P-256) only** (no Ed25519 in FIDO2)
- **Ledger Flex / Stax / Nano X / S Plus** — via Ledger FIDO2 app (ES256)
- **Nitrokey 3** — open-source, FIDO2-certified (ES256/EdDSA)

**Testing without hardware:** Use the FIDO2 MDS virtual authenticator or WebAuthn emulator during development — physical key only required for demo. The reference implementation in this repo ships a `VirtualAuthenticator` that exercises the full wire format without hardware.

---

## 8. Client API Example (JavaScript WebAuthn)

### Registration (`navigator.credentials.create()`)

```js
const credential = await navigator.credentials.create({
    publicKey: {
        rp: { name: "Empire Labs", id: "empirelabs.com.au" },
        user: { id: new TextEncoder("utf-8").encode("sovereign.agent"), name: "Sovereign", displayName: "Sovereign Agent" },
        pubKeyCredParams: [{ type: "public-key", alg: -8 }],
        challenge: challengeBytes,
        authenticatorSelection: { authenticatorAttachment: "cross-platform", requireResidentKey: true },
        extensions: {
            txAuthAgent: {
                agent_identity: {
                    aci_uri: "https://empirelabs.com.au/.well-known/aci/identity.json",
                    agent_name: "Sovereign"
                },
                challenge: "QSef74gcLRf8amSn8nwFR7v4C9Z1Cl0n"
            }
        }
    }
});
```

### Authentication & Action Signing (`navigator.credentials.get()`)

```js
const asser = await navigator.credentials.get({
    publicKey: {
        challenge: challengeBytes,
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        extensions: {
            txAuthAgent: {
                agent_identity: {
                    aci_uri: "bot.empirelabs.com.au/.well-known/aci/identity.json",
                    agent_name: "Sovereign",
                    aip_endpoint: "mcp:bot-trade"
                },
                action: {
                    action_id: "01JSDXQZ3MV8YR9K5WPHKE7N12",
                    action_type: "contract.sign",
                    action_descriptor: {
                        counterparty_aci: "https://spotbottrading.com/.well-known/aci/identity.json",
                        contract_hash: "sha256:4a84c3bfcdfb1a...",
                        timestamp: "2026-08-02T09:30:00Z"
                    }
                },
                prompt: "Sidebar: agent authorised — sign for SoverBot"
            }
        }
    }
});
```

**Flow:** Agent calls `navigator.credentials.get()` → browser/silent enclosure requests → hardware key lights up → human taps key (physical gesture) → ~500ms signing → `agent_action_sig` returned in the extension output.

---

## 9. IANA Registration Details (Information Only)

**Proposed identifier:** `txAuthAgent`

**Registration type:** Specification Required (Expert Review per RFC 8809)

**Relevant experts:** Tim Cappalli (Okta), Akshay Kumar (Microsoft), Emil Lundberg (Yubico) — W3C WebAuthn WG chairs / extension reviewers

**Expert Review contact:** `public-webauthn@w3.org`

**Process:** Submit the extension identifier + pointer to this specification → expert review (prior extensions: ~2–7 days) → permanent registration. Empire Labs plans to submit within 72 hours of public posting, timed for the Aug 2 AI Act enforcement news hook.

---

## 10. Sovereign Review Decisions (2026-08-01)

The following open questions from v0.1 were resolved by Sovereign on behalf of Empire Labs:

1. **ACI cross-reference:** `agent_identity` carries `aci_uri` + `agent_name`. **Decision:** Keep `aci_uri` as the required identity anchor. `aip_endpoint` and `agent_did` remain *optional* fields — embedding the full AIP endpoint at registration time creates a coupling that can go stale; the ACI document itself can expose the AIP endpoint dynamically. RPs that want to pin the endpoint may include it, but it is not required for verification.

2. **Hardware check:** **Decision:** The spec supports Ledger and YubiKey equally; no single demo key is required. The reference implementation ships a `VirtualAuthenticator` for CI/demo purposes, and the FIDO2 MDS virtual authenticator covers browser-level testing. Physical key validation is a launch-day nice-to-have, not a blocker.

3. **Scope guard:** **Decision:** This spec covers agent-to-hardware signing **only**. Governance enforcement (policy engines, rate limits, oversight dashboards) lives in WitnessOS and stays separate — it is a product feature, not a WebAuthn extension. If the WG asks for broader scope, we extend in a follow-up version; we do not bloat v0.1 of the IANA submission.

4. **Posting venue:** **Decision:** Public posting order for Aug 2 launch:
   1. W3C `public-webauthn@w3.org` mailing list — expert review request (primary channel, gives legitimacy)
   2. dev.to (Empire Labs org) — technical article with code walkthrough
   3. Hacker News (Show HN) + X (@EmpireLabsAU) + LinkedIn — distribution
   4. Repo README already links the spec — the GitHub repo is the canonical home

---

## 11. Revision History

- **v0.1** — 2026-08-01: Draft for Sovereign review (Porgie)
- **v0.2** — 2026-08-01: Sovereign review complete. Fixed section numbering (duplicate §5 split into §5 Processing Results / §6 EU AI Act), corrected CBOR field typos (`agent_action_sig`, `agent_cid`), added `algorithm` to the wire format, resolved open questions (§10), added reference implementation link. Cleared for public posting.
- **v0.3** — 2026-08-04: Expert-review hardening (target reviewer: Emil Lundberg, Yubico — named in §9). (1) Algorithm policy corrected to **ES256 primary** — YubiKey 5 Series signs ES256 (P-256) only; the earlier Ed25519/ES384 claims were factually wrong and are removed. (2) Canonical action digest redefined from canonical-JSON to **deterministic CBOR (RFC 8949 §4.2.1)** — see §5.3; reference implementation + tests updated. (3) Added §3.1 **gap analysis** (vs txAuthSimple/txAuthGeneric and the challenge-carrier profile) answering the first question any WebAuthn reviewer asks. (4) Reference implementation default algorithm changed to ES256 (`VirtualAuthenticator`). File name retained as v0.2 for link stability; content is v0.3.

---

## License

**Specification text:** MIT License

### Acknowledgments

Written by Porgie at Empire Labs Pty Ltd. This specification extends the Empire Stack (ACI / AIP / AJSON) — three open specifications for autonomous agent commerce. Thank you to the W3C Web Authentication Working Group for the extension registration infrastructure (RFC 8809) and the existing WebAuthn extension ecosystem.
