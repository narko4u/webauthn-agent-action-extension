# WebAuthn Agent Authorization — Application Profile Specification v0.4

**Profile Tag:** `txauthagent/sign/v1`
**Extension Identifier (underlying):** `sign` (w3c/webauthn PR #2078)

**Status:** Draft v0.4 — application profile on the WebAuthn `sign` extension; addresses reviewer feedback on pairwise credential privacy (2026-08-04)
**Proposed by:** Empire Labs Pty Ltd
**Target:** W3C WebAuthn Working Group (profile of the `sign` extension proposed in PR #2078)
**Specification Required:** Yes (Expert Review per WebAuthn §12.4)
**Draft Date:** 1 August 2026 (v0.2); reframed 4 August 2026 (v0.4)
**License:** MIT (specification text) / CC BY 4.0 (explanatory material)
**Reference Implementation:** https://github.com/narko4u/webauthn-agent-action-extension

---

## 1. Abstract

The **txAuthAgent** profile provides hardware-backed authorization for AI agents performing autonomous actions on behalf of human users. It is defined as an *application profile* on top of the WebAuthn **`sign` extension** (w3c/webauthn PR #2078, proposed by Emil Lundberg / Yubico), which supplies the cryptographic primitive: an attested, hardware-bound **signing key pair that is separate from the WebAuthn credential key pair**, able to sign arbitrary data unaltered.

txAuthAgent defines:

1. the **agent action payload schema** — a structured, machine-verifiable description of what an agent is authorized to do (agent identity per ACI, action type, contract hash, timestamp, nonce);
2. the **canonical action digest** — the exact bytes passed to the `sign` extension as its `tbs` (to-be-signed) input;
3. the **ceremony wiring** — registration requests `sign.generateKey`; authentication requests `sign.sign` with the key handle;
4. the **verification semantics** — any party (relying party, counterparty, regulator, auditor) can verify an agent authorization using only the *signing public key* published at registration and the action payload. **The pairwise WebAuthn credential is never used for third-party verification.**

The profile addresses a regulatory vacuum: the EU AI Act (enforceable 2 August 2026) Articles 12 and 14 require tamper-evident logging and human oversight for high-risk AI systems. Hardware-backed agent signatures create a cryptographically verifiable audit trail that satisfies both requirements without forcing a human into every interaction loop.

**Key properties:**
- Agent submits action details; hardware key signs; any verifying party checks
- Signing key never leaves the device and is attested at registration
- Privacy-preserving by construction: third-party verification does not touch pairwise credential material
- Wire format: `AuthenticationExtensionsClientInputsJSON` / `AuthenticationExtensionsClientOutputsJSON` using CBOR

---

## 2. Relationship to the Empire Stack

This WebAuthn profile is part of the **Empire Stack** — three open specifications for autonomous agent commerce by Empire Labs Pty Ltd:

| Layer | Spec | Role |
|-------|------|------|
| Discover | **ACI** (Agent Company Interface) | Declares agent identity and capabilities |
| Interact | **AIP** (Agent Interaction Protocol) | Negotiates contracts and executes actions |
| Author | **AJSON** (Agent JSON) | Writes clean manifests that compile to canonical JSON |

`txAuthAgent` wraps AIP action signing with FIDO2 hardware attestation. The agent's identity is established via ACI; the signed action payload embeds an AIP action digest; the resulting attestation is stored as AJSON for canonical audit.

The profile is independently specified — use it with or without the full Empire Stack. But when used together, an AIP Agent signs an action → the hardware key signs the action digest via the `sign` extension → the receiving party validates both the agent identity (ACI) and the hardware attestation against the published signing key.

---

## 3. Design Rationale

### 3.1 The pairwise-credential privacy property

A WebAuthn credential is **pairwise to its relying party**: the credential ID and public key are scoped to the RP ID that created them, and the RP cannot be correlated across other relying parties. This is a core privacy design of WebAuthn (and FIDO2) — it is what stops a set of signing keys from becoming a global tracking identifier.

Early drafts of this specification (v0.1–v0.3) proposed an extension whose verification semantics let *any* relying party verify a signature over the agent action. A reviewer (Tim Cappalli, W3C WebAuthn WG) correctly observed that verifying against the **pairwise credential** would break this invariant: a third party cannot verify against a credential it was never meant to see, and exposing credentials broadly would undermine the pairwise design.

**The resolution, adopted in v0.4, is to verify against a different key.** The `sign` extension creates — at registration, alongside the credential — a **separate signing key pair** that is:

- bound to the same physical authenticator and the same RP ID,
- attested at registration (the authenticator certifies the signing public key, its algorithm and its policy),
- **publishable**: there is no privacy cost to a third party learning it, because it is scoped to the signing context, not to the pairwise credential.

txAuthAgent therefore publishes the signing public key (in the registration record, e.g. `generatedKey.publicKey` COSE_Key) and verifies raw signatures against it. The pairwise credential remains pairwise. This answers the reviewer's objection directly and is the architectural change behind v0.4.

### 3.2 Why an application profile on the `sign` extension?

The `sign` extension (w3c/webauthn PR #2078) is the right primitive but is deliberately *generic*: it signs whatever `tbs` the client sends. That generality is its strength — but it leaves three questions open that an application profile must answer for agent authorization to be interoperable:

1. **What exactly is signed?** The extension does not define a payload schema. txAuthAgent defines the agent action payload and the canonical digest, so two implementations produce byte-identical `tbs` for the same action.
2. **How is verification anchored?** The extension returns a raw signature. txAuthAgent defines where the signing public key comes from (the registration `generatedKey` record + attestation), how the digest is recomputed, and which flags (up/uv) must hold.
3. **What is the audit record?** txAuthAgent defines the `txAuthAgent` extension output: a self-contained record pairing the signature, the digest, the credential binding, the algorithm and the observed flags — what an auditor stores and replays.

An application profile also has a practical benefit: it can be specified and deployed **in parallel** with the extension's ratification, and can fall back to a challenge-carrier bootstrap on hardware that has not yet received sign-extension firmware (§3.4).

### 3.3 Why not txAuthSimple / txAuthGeneric?

The existing WebAuthn L2/L3 transaction-authorization extensions (`txAuthSimple`, `txAuthGeneric`) were designed for *human* transaction confirmation: the authenticator displays a short text (or CBOR content) and the human approves. They do not define:

- a canonical, machine-verifiable digest of a *structured* action payload — their output semantics return the displayed content, not a signature over a well-defined action schema;
- an agent-identity binding (ACI URI / agent name / DID) as a first-class field, so a third-party verifier cannot independently confirm *which agent* was authorized;
- a separate, publishable signing key — their signatures bind to the pairwise credential, so third-party verification would hit the privacy problem of §3.1.

For a human reading a prompt, txAuthGeneric suffices. For a counterparty or regulator verifying an *agent's* action later, without interacting with the agent, the signing-key + canonical-digest design is what makes verification possible.

### 3.4 Interim hardware path (challenge-carrier profile)

The `sign` extension is under active iteration in the W3C WG (PR #2078, draft v3; the yubicolabs/webauthn-sign-extension fork). Until firmware support ships, the reference implementation's `examples/hardware_demo.py` demonstrates the **challenge-carrier bootstrap**: a plain `navigator.credentials.get()` with the canonical action digest as the `challenge`. This works on every shipping FIDO2 authenticator today (YubiKey 5, Ledger FIDO2 app, Nitrokey 3) and produces a standard WebAuthn assertion. Its limitation is that the assertion signature binds to the pairwise credential, so third-party verification is limited to the creating RP — which is why the profile's long-term path is the sign extension.

---

## 4. Input Data (Client → Authenticator)

The client input is the standard `AuthenticationExtensionsClientInputsJSON` map with two entries: the `sign` extension input (the primitive) and the `txAuthAgent` input (the application context).

### 4.1 Registration extension input (`navigator.credentials.create()`)

```json
{
  "sign": {
    "generateKey": {
      "algorithms": [-7, -8],
      "tbs": null
    }
  },
  "txAuthAgent": {
    "profile": "txauthagent/sign/v1",
    "agent_identity": {
      "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
      "agent_name": "Sovereign",
      "agent_did": "did:key:z6Mk...",
      "aip_endpoint": "https://api.empirelabs.com.au/aip/v1"
    }
  }
}
```

**Semantics:** The relying party registers the agent credential with a specific hardware authenticator *and* requests generation of a signing key pair for it. Per the sign extension, the client expresses the signing-key policy (require-up / require-uv) through `authenticatorSelection.userVerification`; the authenticator fixes the policy at key creation and attests to it. The `aci_uri` field lets the RP independently verify the agent's identity declaration.

`tbs` is optional at registration (the profile signs at authentication time); if present, the authenticator also returns a signature over it with the new key.

### 4.2 Authentication extension input (`navigator.credentials.get()`)

```json
{
  "sign": {
    "sign": {
      "tbs": "<canonical action digest bytes, see §5.3>",
      "keyHandleByCredential": {
        "dHhhdXRoQWdlbnQtY3JlZGVudGlhbA": "<COSE_Key_Ref bytes for this credential>"
      }
    }
  },
  "txAuthAgent": {
    "profile": "txauthagent/sign/v1",
    "action": {
      "action_id": "01JSDXQZ3MV8YR9K5WPHKE7N12",
      "action_type": "contract.sign",
      "agent_identity": {
        "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
        "agent_name": "Sovereign",
        "agent_did": "did:key:z6Mk..."
      },
      "action_descriptor": {
        "counterparty": {
          "aci_uri": "https://spotbottrading.com.au/.well-known/aci/identity.json"
        },
        "contract_hash": "sha256:4a84c...",
        "timestamp": "2026-08-01T09:30:00Z",
        "nonce": "base64url-encoded 32-byte random value"
      },
      "prompt": "Sign this action payload so the counterparty can verify the agent's authority"
    }
  }
}
```

**Semantics:** The agent asks the authenticator to sign a specific action payload. `sign.sign.tbs` is the canonical digest of `txAuthAgent.action` (computed per §5.3) — the authenticator signs it **unaltered**. `sign.sign.keyHandleByCredential` maps the base64url-encoded credential ID in `allowCredentials` to the signing key handle (COSE_Key_Ref) obtained at registration. The hardware key requires a physical gesture (and, if the policy demands it, PIN/biometric) and returns the raw signature. The agent's software never holds the signing private key.

---

## 5. Processing Results (Client ← Authenticator → RP)

### 5.1 Authenticator extension output (CBOR)

The authenticator returns a CBOR-encoded `AuthenticationExtensionsClientOutputsJSON` map with two entries:

```text
AuthenticationExtensionsClientOutputs {
    sign: {
        signature: bytes        // raw signature over tbs (sign extension result)
        // registration ceremonies instead carry:
        // generatedKey: { publicKey: COSE_Key, algorithm: int, attestationObject: bytes }
    },
    txAuthAgent: {              // application-layer audit record (this profile)
        agent_action_sig: bytes,   // == sign.signature (same value, self-contained audit)
        action_digest: bytes,      // the exact tbs that was signed (32 bytes)
        agent_cid: bytes,          // credential ID binding
        algorithm: -7 or -8,       // COSE algorithm — ES256 (-7) or EdDSA (-8)
        rp_id_hash: bytes,         // SHA-256 of the RP ID
        flags: {
            up: true,              // user presence — physical gesture
            uv: true/false         // user verification — biometric/PIN used
        }
    }
}
```

### 5.2 Verifying the agent action (any party)

A verifier — the relying party, a counterparty, an auditor or a regulator — performs these checks **using only the published signing public key and the payload**:

1. Recompute the canonical digest from the action payload (§5.3); it must equal `txAuthAgent.action_digest`.
2. Verify the raw signature (`sign.signature` / `txAuthAgent.agent_action_sig`) against the **signing public key** from the registration record, over the recomputed digest.
3. Check `rp_id_hash` matches the expected relying party.
4. Check `flags.up == true` — a physical gesture occurred at signing time. For high-value actions, require `flags.uv == true`.
5. (Optional, for strong assurance) Validate the registration-time attestation of the signing key (§5.4) — that the signing public key really is attested to a hardware authenticator.

If all checks pass, the action is **hardware-attested agent authorization**, verifiable by any independent party with no interaction with the agent and no secret validation server. The pairwise credential is never involved in this path.

### 5.3 Canonical action digest

The authenticator signs a single digest over the action payload, defined as:

```text
digest = SHA-256( "txAuthAgent" || 0x00 || deterministic-CBOR(payload) )
```

where:

- `"txAuthAgent"` is the 11-byte ASCII profile identifier (domain separation from other signed data),
- `0x00` is a single zero byte version separator,
- `deterministic-CBOR(payload)` is the canonical payload (see §4.2) encoded with the deterministic rules of RFC 8949 §4.2.1: map keys sorted in the bytewise lexicographic order of their deterministic encodings (for the text-string keys of the action payload this is the length-first order of §4.2.3), definite-length headers, no floating point.

Deterministic CBOR is normatively defined and byte-for-byte reproducible by any conforming encoder regardless of key insertion order or platform — unlike "canonical JSON" (sorted keys, whitespace-free), whose string canonicalisation is underspecified across implementations. The reference implementation (`txauthagent/digest.py`) ships the digest computation and RFC 8949 §4.2.1 encoder; golden test vectors live in `tests/test_digest.py`, and an interop test cross-checks our encoder against `cbor2` (canonical=True) in `tests/test_e2e.py`.

### 5.4 Signing-key attestation at registration

The sign extension returns an attestation object for the signing key at registration, in the standard WebAuthn attestation format (`fmt` / `authData` / `attStmt`). Its `authData` carries the signing public key as the attested credential public key (with an empty credential ID), the RP ID hash, and a `sign` extension entry with the key policy flags (require-up / require-uv). The authenticator's attestation signature (packed / tpm / etc., validated via the FIDO Metadata Service for certified devices) binds the signing public key to the hardware.

The reference implementation's `VirtualAuthenticator` produces a packed-format self-attestation signed by the credential key — structurally identical to what a real device produces, minus the vendor certificate chain. `verify_sign_attestation()` in `txauthagent/verify.py` demonstrates the checks.

---

## 6. EU AI Act Compliance Context

### 6.1 Article 12 — Tamper-Evident Logging

| Requirement | How txAuthAgent satisfies |
|-------------|--------------------------|
| Evidentiary logging | ES256/EdDSA signature over the canonical action digest (agent identity + action + timestamp + contract hash) |
| Tamper-evident | All signatures produced by hardware key — altering any field breaks the digest check and the signature |
| 6-month retention | AJSON-signed record is machine-readable, ~200 bytes per action log |
| No agent forgery | Agent never touches the signing key material — cannot forge hardware attestation |

### 6.2 Article 14 — Human Oversight Evidence

| Requirement | How txAuthAgent satisfies |
|-------------|--------------------------|
| Human-in-the-loop evidence | `flags.up = 1` — physical gesture (press/tap) confirmed on hardware at signing time |
| Biometric trace (optional) | `flags.uv = 1` — user verification via biometric/PIN |
| No pass-through detectable | Hardware key owns the signing key; agent software cannot inject or replay |

### 6.3 Third-Party Verification (Regulators, Auditors, Counterparties)

Any third party can verify agent action signatures **without interacting with the agent**:

1. Fetch the agent's identity declaration via ACI
2. Fetch the **signing public key** from the registration record (published; no privacy cost)
3. Recompute the canonical digest from the payload
4. Verify the raw signature over the digest with the signing key
5. Validate timestamps, nonce, and flags

**No secret validation server required.** The hardware already did the work.

---

## 7. Hardware Requirements

| Component | Minimum Requirement |
|-----------|-------------------|
| Authenticator | CTAP 2.2+ with the `sign` extension (in ratification; PR #2078) |
| Algorithm | ES256 (COSE -7) primary — universally supported; EdDSA (COSE -8) where device-supported |
| Transport | USB-C, NFC, or BLE |

**Current status:** The sign extension is under active iteration in the W3C WG (draft v3; yubicolabs/webauthn-sign-extension fork). Until firmware ships, the challenge-carrier bootstrap (§3.4) runs on today's FIDO2 hardware — YubiKey 5 Series (ES256), Ledger Flex / Stax / Nano X / S Plus (via Ledger FIDO2 app), Nitrokey 3 (ES256/EdDSA).

**Testing without hardware:** The reference implementation ships a `VirtualAuthenticator` that implements the full sign-extension wire format (separate signing key, key-handle re-derivation, UP/UV policy enforcement, packed attestation) so the profile can be exercised end-to-end in CI today.

---

## 8. Client API Example (JavaScript WebAuthn)

### Registration (`navigator.credentials.create()`)

```js
const credential = await navigator.credentials.create({
    publicKey: {
        rp: { name: "Empire Labs", id: "empirelabs.com.au" },
        user: { id: new TextEncoder("utf-8").encode("sovereign.agent"), name: "Sovereign", displayName: "Sovereign Agent" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        challenge: challengeBytes,
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            userVerification: "required"   // sets sign-key policy require-uv
        },
        extensions: {
            sign: { generateKey: { algorithms: [-7] } },
            txAuthAgent: {
                profile: "txauthagent/sign/v1",
                agent_identity: {
                    aci_uri: "https://empirelabs.com.au/.well-known/aci/identity.json",
                    agent_name: "Sovereign"
                }
            }
        }
    }
});
// store credential.response.getClientExtensionResults().sign.generatedKey.publicKey
// as the PUBLISHED signing public key
```

### Authentication & Action Signing (`navigator.credentials.get()`)

```js
const asser = await navigator.credentials.get({
    publicKey: {
        challenge: challengeBytes,
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        extensions: {
            sign: {
                sign: {
                    tbs: actionDigestBytes,   // canonical digest of the action payload
                    keyHandleByCredential: { [b64url(credential.rawId)]: signingKeyHandle }
                }
            },
            txAuthAgent: {
                profile: "txauthagent/sign/v1",
                action: {
                    action_id: "01JSDXQZ3MV8YR9K5WPHKE7N12",
                    action_type: "contract.sign",
                    agent_identity: {
                        aci_uri: "https://empirelabs.com.au/.well-known/aci/identity.json",
                        agent_name: "Sovereign"
                    },
                    action_descriptor: {
                        counterparty_aci: "https://spotbottrading.com/.well-known/aci/identity.json",
                        contract_hash: "sha256:4a84c3bfcdfb1a...",
                        timestamp: "2026-08-02T09:30:00Z",
                        nonce: "..."
                    },
                    prompt: "Sign this action payload so the counterparty can verify the agent's authority"
                }
            }
        }
    }
});
// asser.response.getClientExtensionResults().sign.signature is the raw signature;
// .txAuthAgent is the audit record. Any party can verify with the published key.
```

**Flow:** Agent calls `navigator.credentials.get()` → browser/silent enclosure requests → hardware key lights up → human taps key (physical gesture; PIN/biometric if policy requires) → ~500ms signing → raw `signature` + `txAuthAgent` audit record returned.

---

## 9. Profile Registration & Versioning

**Profile tag:** `txauthagent/sign/v1`

The `sign` extension itself is the W3C-tracked extension (PR #2078); this document specifies the **application profile** layered on it, identified by the `profile` member in the txAuthAgent client input. The profile tag is versioned (`/v1`) so verification rules and payload schemas can evolve without breaking existing audit records.

**Maintainers:** Empire Labs Pty Ltd
**Review channel:** `public-webauthn@w3.org`
**Reference implementation:** https://github.com/narko4u/webauthn-agent-action-extension

---

## 10. Sovereign Review Decisions (2026-08-01 → 2026-08-04)

1. **ACI cross-reference:** `agent_identity` carries `aci_uri` + `agent_name`. **Decision:** Keep `aci_uri` as the required identity anchor. `aip_endpoint` and `agent_did` remain *optional* fields — embedding the full AIP endpoint at registration time creates a coupling that can go stale; the ACI document itself can expose the AIP endpoint dynamically.

2. **Hardware check:** **Decision:** The profile supports Ledger and YubiKey equally; no single demo key is required. The reference implementation ships a `VirtualAuthenticator` for CI/demo purposes, and the FIDO2 MDS virtual authenticator covers browser-level testing. Physical key validation is a launch-day nice-to-have, not a blocker.

3. **Scope guard:** **Decision:** This profile covers agent-to-hardware signing **only**. Governance enforcement (policy engines, rate limits, oversight dashboards) lives in WitnessOS and stays separate — it is a product feature, not a WebAuthn extension.

4. **Reviewer feedback (2026-08-03, Tim Cappalli, W3C WebAuthn WG):** The v0.3 claim that "any relying party can verify the signature" against the pairwise credential conflicts with WebAuthn's pairwise-RP privacy design; reviewer pointed to PR #2078 (`sign` extension) as the right primitive. **Decision (2026-08-04):** Adopt the sign extension as the cryptographic layer and reframe txAuthAgent as its application profile. Verification now targets the separate, attested, publishable signing key (§3.1, §5.2). Standalone-extension claims and the pairwise-credential verification path are removed.

5. **Posting venue:** **Decision:** Public posting order: (1) reply to Tim Cappalli on the W3C list, acknowledging the pairwise point and presenting the v0.4 application-profile design; (2) follow up with Emil Lundberg on the sign extension interop; (3) technical article on dev.to; (4) Hacker News + X distribution. The repo README links this spec — the GitHub repo is the canonical home.

---

## 11. Revision History

- **v0.1** — 2026-08-01: Draft for Sovereign review (Porgie).
- **v0.2** — 2026-08-01: Sovereign review complete. Fixed section numbering, corrected CBOR field typos, added `algorithm` to the wire format, resolved open questions (§10), added reference implementation link. Cleared for public posting.
- **v0.3** — 2026-08-04: Expert-review hardening. (1) Algorithm policy corrected to **ES256 primary** — YubiKey 5 Series signs ES256 only; earlier Ed25519/ES384 claims removed. (2) Canonical digest redefined from canonical-JSON to **deterministic CBOR (RFC 8949 §4.2.1)**. (3) Added §3.1 gap analysis. File name retained as v0.2 for link stability; content is v0.3.
- **v0.4** — 2026-08-04: **Application-profile reframe** in response to reviewer feedback (Tim Cappalli). (1) Adopted the W3C `sign` extension (PR #2078) as the cryptographic layer — separate attested signing key, raw signature over unaltered `tbs`. (2) Added §3.1 pairwise-privacy rationale: verification now targets the published signing key, never the pairwise credential. (3) Reworked §4 input / §5 output wire format (`sign.generateKey` / `sign.sign` + txAuthAgent profile context and audit record). (4) §5.4 signing-key attestation at registration; reference implementation + tests reworked to the sign-based flow (105 tests passing, cbor2 interop vectors). File name retained as v0.2 for link stability; content is v0.4.

---

## License

**Specification text:** MIT License

### Acknowledgments

Written by Porgie at Empire Labs Pty Ltd. This specification extends the Empire Stack (ACI / AIP / AJSON) — three open specifications for autonomous agent commerce. Thank you to the W3C Web Authentication Working Group — in particular Emil Lundberg (Yubico) for the `sign` extension proposal (PR #2078) that this profile builds on, and Tim Cappalli for the pairwise-credential privacy review that shaped v0.4.
