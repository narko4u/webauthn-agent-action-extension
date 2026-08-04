"""txAuthAgent demo — hardware-attested agent authorization via the WebAuthn sign extension.

Usage:  python -m txauthagent.cli

Walkthrough (v0.4 — application profile on w3c/webauthn PR #2078 "sign"):

1. Registration: the agent creates a credential; the ``sign`` extension
   generates a SEPARATE attested signing key pair. The signing public key is
   published — no pairwise credential data leaks.
2. Action signing: the agent builds a canonical action payload; the client
   sends ``sign.sign`` with the digest as ``tbs``; the hardware key signs the
   digest unaltered after a physical tap (and PIN/biometric if required).
3. Verification: ANY party — relying party, counterparty, auditor — verifies
   the raw signature against the published signing public key. No secrets,
   no pairwise credentials involved.
"""

from __future__ import annotations

import hashlib
import json

from . import cbor
from .cose import cose_key_to_pem
from .digest import compute_action_digest
from .extension import (
    ALG_ES256,
    EXTENSION_ID,
    FLAG_REQUIRE_UP,
    FLAG_REQUIRE_UV,
    SIGN_EXTENSION_ID,
    b64url_encode,
    build_ceremony_input,
    build_registration_input,
    parse_profile_output,
    parse_sign_output,
)
from .payload import build_action_payload
from .verify import (
    parse_sign_attestation,
    parse_sign_generated_key,
    verify_agent_action_cbor,
    verify_sign_attestation,
)
from .virtual import VirtualAuthenticator

RP_ID = "empirelabs.com.au"
ORIGIN = "https://empirelabs.com.au"

SEP = "─" * 72

AGENT_IDENTITY = {
    "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
    "agent_name": "Sovereign",
    "agent_role": "security-division",
}


def _pretty_ext_inputs(ext_inputs: dict) -> str:
    """Compact human-readable view of the extension client inputs."""
    sign = ext_inputs[SIGN_EXTENSION_ID]
    taa = ext_inputs[EXTENSION_ID]
    lines = [f"  {SIGN_EXTENSION_ID}:"]
    if "generateKey" in sign:
        gen = sign["generateKey"]
        lines.append(f"    generateKey.algorithms = {gen['algorithms']}")
        if "tbs" in gen:
            lines.append(f"    generateKey.tbs       = {gen['tbs'].hex()[:40]}...")
    if "sign" in sign:
        lines.append(f"    sign.tbs              = {sign['sign']['tbs'].hex()[:40]}...")
        lines.append(f"    sign.keyHandleByCredential = {{")
        for cid, handle in sign["sign"]["keyHandleByCredential"].items():
            lines.append(f"      {cid[:16]}… -> COSE_Key_Ref ({len(handle)} bytes)")
        lines.append("    }")
    lines.append(f"  {EXTENSION_ID}: profile={taa.get('profile')}")
    if "action" in taa:
        action = taa["action"]
        descriptor = action.get("action_descriptor", {})
        lines.append(f"    action = {action['action_type']} / {descriptor.get('memo', '')[:48]}")
    return "\n".join(lines)


def _registration_client_data_hash() -> bytes:
    """Replicate the exact clientDataHash the authenticator attested to."""
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": b64url_encode(b"txAuthAgent-registration"),
            "origin": ORIGIN,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(client_data_json).digest()


def main() -> None:
    print(f"{SEP}")
    print("txAuthAgent v0.4 — hardware-attested agent authorizations")
    print("Application profile on the WebAuthn 'sign' extension (PR #2078)")
    print(f"{SEP}")

    # ------------------------------------------------------------------ #
    # 1. Registration
    # ------------------------------------------------------------------ #
    print("\n[1] REGISTRATION — agent creates a credential + signing key pair")
    print(f"    RP ID: {RP_ID}  |  Origin: {ORIGIN}")

    # The hardware key. Default policy: require-user-presence (physical tap).
    authenticator = VirtualAuthenticator(algorithm=ALG_ES256, rp_id=RP_ID, flags=FLAG_REQUIRE_UP)

    reg_input = build_registration_input(AGENT_IDENTITY, algorithms=[ALG_ES256])
    print("\n    client input (AuthenticationExtensionsClientInputsJSON):")
    print(_pretty_ext_inputs(reg_input))

    reg_output = authenticator.register(algorithms=[ALG_ES256], origin=ORIGIN)
    generated = parse_sign_generated_key(reg_output)
    print("\n    sign extension output: generatedKey")
    print(f"      algorithm          = {generated['algorithm']} (ES256)")
    print(f"      publicKey (COSE)   = {generated['publicKey'].hex()[:48]}... ({len(generated['publicKey'])} bytes)")
    print(f"      attestationObject  = {len(generated['attestationObject'])} bytes (packed, self-signed)")

    # The RP records the SIGNING public key (publishable!) and the attestation.
    signing_cose = generated["publicKey"]
    signing_pem = cose_key_to_pem(signing_cose)
    print("\n    PUBLISHED SIGNING PUBLIC KEY (any party can verify against this):")
    print("    " + signing_pem.decode().strip().replace("\n", "\n    "))

    # Attestation checks: structure + packed signature with the credential key.
    att = parse_sign_attestation(generated["attestationObject"])
    print(f"    attestation: fmt={att['fmt']}, sign_flags policy={att['sign_flags']}, "
          f"credential_id_len={len(att['credential_id'])}")
    print(f"    attested signing key == generatedKey.publicKey: "
          f"{att['signing_cose_key'] == signing_cose}")
    verify_sign_attestation(
        generated["attestationObject"],
        authenticator.credential_public_key_pem,
        expected_rp_id=RP_ID,
        client_data_hash=_registration_client_data_hash(),
    )
    print("    packed attestation signature verified against credential key: OK")

    print(f"\n{SEP}")
    print("[2] ACTION SIGNING — agent approves a PCI-DSS SSF security event")
    print(f"{SEP}")

    # ------------------------------------------------------------------ #
    # 2. Action signing ceremony
    # ------------------------------------------------------------------ #
    payload = build_action_payload(
        action_id="01JSDXQZ3MV8YR9K5WPHKE7N12K",
        action_type="security_events",
        agent_identity=AGENT_IDENTITY,
        action_descriptor={
            "contract_hash": "sha256:" + "0" * 64,
            "timestamp": "2026-08-04T09:30:00+10:00",
            "nonce": "8f2c1a6e9d4b7c3a5f0e8d2b6a4c1e9f",
            "counterparty": "pci-ssf",
            "memo": "Issue emergency session revocation for cardholder data environment",
        },
    )
    digest = compute_action_digest(payload)
    print("\n    ACTION PAYLOAD (validated): " + payload["action_type"])
    print(f"      memo     = {payload['action_descriptor']['memo']}")
    print(f"      digest   = SHA-256('txAuthAgent' || 0x00 || canonical-CBOR(payload))")
    print(f"      digest   = {digest.hex()}")
    print("      this digest becomes sign.tbs — signed UNALTERED by the key")

    # Wire the ceremony: client builds the extension inputs, passing the key
    # handle for the credential the RP is asking to sign with.
    key_handle_by_credential = {
        b64url_encode(authenticator.credential_id): authenticator.key_handle.cose_key_ref
    }
    ceremony_input = build_ceremony_input(payload, key_handle_by_credential)
    print("\n    client input (AuthenticationExtensionsClientInputsJSON):")
    print(_pretty_ext_inputs(ceremony_input))

    # User taps the key. For require-up policy that is the whole ceremony.
    outputs_cbor = authenticator.sign_action_cbor(payload, tap=True)
    outputs = cbor.loads(outputs_cbor)
    sign_entry = parse_sign_output(outputs)
    record = parse_profile_output(outputs)
    print(f"\n    authenticator output (CBOR, {len(outputs_cbor)} bytes) decoded:")
    print(f"      sign.signature            = {sign_entry['signature'].hex()[:40]}... ({len(sign_entry['signature'])} bytes)")
    print(f"      txAuthAgent.action_digest = {record['action_digest'].hex()[:40]}...")
    print(f"      txAuthAgent.agent_cid     = {record['agent_cid'].hex()[:16]}…")
    print(f"      txAuthAgent.algorithm     = {record['algorithm']}")
    print(f"      txAuthAgent.flags         = up={record['flags']['up']} uv={record['flags']['uv']}")

    print(f"\n{SEP}")
    print("[3] THIRD-PARTY VERIFICATION — no secrets, no pairwise credential")
    print(f"{SEP}")

    # ------------------------------------------------------------------ #
    # 3. Verification by any party holding the published signing key
    # ------------------------------------------------------------------ #
    result = verify_agent_action_cbor(
        payload,
        outputs_cbor,
        signing_pem,
        expected_rp_id=RP_ID,
    )
    print("\n    ✓ raw signature verified against PUBLISHED signing key")
    print("    ✓ canonical digest recomputed from payload matches record")
    print(f"    ✓ rp_id_hash matches {RP_ID}")
    print("    ✓ user presence flag set (physical gesture confirmed)")
    print(f"    → algorithm={result.algorithm_name}, credential={result.credential_id.hex()[:16]}…, "
          f"up={result.up}, uv={result.uv}")

    # Tamper: any modification to the payload breaks verification.
    tampered = dict(payload)
    tampered["action_descriptor"] = dict(payload["action_descriptor"])
    tampered["action_descriptor"]["memo"] = "Issue emergency session revocation (MODIFIED)"
    try:
        verify_agent_action_cbor(tampered, outputs_cbor, signing_pem, expected_rp_id=RP_ID)
        print("    ✗ tampered payload VERIFIED?! (bug)")
    except ValueError as exc:
        print(f"    ✓ tampered payload rejected: {exc}")

    print(f"\n{SEP}")
    print("[4] HIGH-VALUE ACTIONS — require user verification (PIN/biometric)")
    print(f"{SEP}")

    # ------------------------------------------------------------------ #
    # 4. require-uv policy
    # ------------------------------------------------------------------ #
    bank = VirtualAuthenticator(algorithm=ALG_ES256, rp_id=RP_ID, flags=FLAG_REQUIRE_UV)
    bank.register(algorithms=[ALG_ES256])
    bank_pem = bank.public_key_pem

    payment = build_action_payload(
        action_id="01JSE0K8QZ3MV8YR9K5WPHKE7N12",
        action_type="financial.wire_transfer",
        agent_identity=AGENT_IDENTITY,
        action_descriptor={
            "contract_hash": "sha256:" + "1" * 64,
            "timestamp": "2026-08-04T10:00:00+10:00",
            "nonce": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6",
            "counterparty": "supplier-verification",
            "amount": "25000",
            "currency": "AUD",
            "memo": "Approve $25,000 transfer to verified supplier",
        },
    )
    try:
        bank.sign_action_cbor(payment, tap=True, user_verified=False)
        print("    ✗ require-uv key signed without PIN?! (bug)")
    except ValueError as exc:
        print(f"    ✓ require-uv key refused without user verification: {exc}")

    bank_outputs_cbor = bank.sign_action_cbor(payment, tap=True, user_verified=True)
    bank_result = verify_agent_action_cbor(
        payment, bank_outputs_cbor, bank_pem, expected_rp_id=RP_ID, require_uv=True
    )
    print(f"    ✓ PIN/biometric verified — high-value action accepted: up={bank_result.up}, uv={bank_result.uv}")

    print(f"\n{SEP}")
    print("Profile summary")
    print(f"{SEP}")
    print("  sign extension (PR #2078)     : attested signing key pair, separate")
    print("                                  from the credential; raw signatures")
    print("                                  over an unaltered tbs.")
    print("  txAuthAgent (this profile)    : action schema + canonical digest +")
    print("                                  ceremony wiring + verification rules.")
    print("  Privacy                        : the pairwise WebAuthn credential is")
    print("                                  NEVER used for third-party verification —")
    print("                                  only the published signing public key.")
    print("\nDone.")


if __name__ == "__main__":
    main()
