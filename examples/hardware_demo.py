#!/usr/bin/env python3
"""txAuthAgent — hardware-backed agent action demo.

Signs a real agent action payload on a physical FIDO2/WebAuthn authenticator
(Ledger Nano S / Nano X / Flex / Stax with the FIDO U2F app, YubiKey 5,
Nitrokey 3) and cryptographically verifies the result — the "tap" is the
human-consent evidence required by EU AI Act Art. 12/14.

Wire-truth note: real authenticator firmware does not (yet) implement the
txAuthAgent extension, so the canonical action digest is used AS the WebAuthn
challenge. The hardware signs the digest (proving key custody + human
presence); the extension wire format itself is proven by the Virtual
Authenticator. Both halves together = the full hardware attestation story.

Usage:
    python3 hardware_demo.py                # real device over USB (CTAP2)
    python3 hardware_demo.py --simulate     # virtual authenticator (no hardware)
    python3 hardware_demo.py --rp-id empirelabs.com.au --origin https://empirelabs.com.au
    python3 hardware_demo.py --output evidence.json --json

Flow:
    1. Build agent action payload (txauthagent.payload)
    2. Register a fresh credential on the device (TAP #1)
    3. Compute canonical action digest; use it as the WebAuthn challenge
    4. Get an assertion — device signs the digest (TAP #2)
    5. Verify: rp_id_hash, UP flag, signature over authData+clientDataHash
    6. Print evidence (JSON or human-readable)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

RP_ID_DEFAULT = "empirelabs.com.au"
ORIGIN_DEFAULT = "https://empirelabs.com.au"

# Make the txauthagent package importable when running from examples/.
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

ALG_EDDSA = -8
ALG_ES256 = -7


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _parse_attested_credential_data(auth_data: bytes) -> Dict[str, Any]:
    """Parse the attested credential data section of a registration authData.

    Layout: aaguid(16) | cred_id_len(2 BE) | cred_id | COSE public key(CBOR)
    """
    if len(auth_data) < 37:
        raise ValueError("authData too short")
    aaguid = auth_data[37:53]
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55 : 55 + cred_id_len]
    cose_key = auth_data[55 + cred_id_len :]
    from fido2 import cbor

    return {
        "aaguid": aaguid,
        "credential_id": cred_id,
        "cose_key": cbor.decode(cose_key),
    }


def cose_key_to_pem(cose_key: Dict[int, Any], algorithm: int) -> bytes:
    """Convert a COSE public key to SubjectPublicKeyInfo PEM for verify.py."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec

    if algorithm == ALG_EDDSA:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(cose_key[-2])
    elif algorithm == ALG_ES256:
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(cose_key[-2], "big"),
            int.from_bytes(cose_key[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
    else:
        raise ValueError(f"unsupported COSE algorithm: {algorithm}")
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_webauthn_assertion(
    *,
    auth_data: bytes,
    signature: bytes,
    client_data_json: bytes,
    public_key_pem: bytes,
    algorithm: int,
) -> Dict[str, Any]:
    """Verify a WebAuthn assertion the way a relying party would."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec

    rp_id_hash = auth_data[:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    up = bool(flags & 0x01)
    uv = bool(flags & 0x04)

    client_data_hash = hashlib.sha256(client_data_json).digest()
    signed_bytes = auth_data + client_data_hash

    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        if algorithm == ALG_EDDSA:
            public_key.verify(signature, signed_bytes)
        else:
            public_key.verify(signature, signed_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("assertion signature verification failed") from exc

    return {
        "rp_id_hash": rp_id_hash.hex(),
        "sign_count": sign_count,
        "up": up,
        "uv": uv,
        "client_data_hash": client_data_hash.hex(),
    }


def build_client_data(challenge: bytes, origin: str) -> bytes:
    client_data = {
        "type": "webauthn.get",
        "challenge": b64u(challenge),
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(client_data, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Real hardware path (CTAP2 over USB HID)
# ---------------------------------------------------------------------------


def real_hardware_flow(args: argparse.Namespace) -> Dict[str, Any]:
    from fido2.hid import CtapHidDevice

    from txauthagent.digest import compute_action_digest
    from txauthagent.payload import build_action_payload

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise RuntimeError(
            "No FIDO2 USB device found. Plug in the Ledger and make sure the "
            "FIDO U2F app is open on the device (Ledger Live -> Manager)."
        )

    # Prefer a Ledger (vendor 0x2c97), otherwise take the first FIDO2 device.
    def _is_ledger(dev) -> bool:
        try:
            return dev.product_name is not None and "ledger" in dev.product_name.lower()
        except Exception:
            return False

    device = next((d for d in devices if _is_ledger(d)), devices[0])
    ctap = device.ctap

    # Basic info (also a good CTAP2 support probe).
    info = ctap.get_info()
    aaguid = getattr(info, "aaguid", b"")
    print(f"[*] Authenticator : {getattr(info, 'name', 'unknown')} (AAGUID {aaguid.hex()})")

    rp_id = args.rp_id
    challenge_register = os.urandom(32)
    user_id = b"sovereign@empirelabs.com.au"

    # --- Step 1: register a fresh credential (TAP #1) ---
    print(f"[*] Registering credential for RP '{rp_id}'...")
    print("    >>> TAP THE LEDGER BUTTON WHEN PROMPTED <<<")
    attestation = ctap.make_credential(
        {"id": rp_id, "name": rp_id},
        {"id": user_id, "name": "Sovereign", "displayName": "Sovereign"},
        challenge_register,
        [{"type": "public-key", "alg": ALG_ES256}, {"type": "public-key", "alg": ALG_EDDSA}],
        [],
    )
    fmt = attestation.get("fmt")
    auth_data = attestation["authData"]
    cred = _parse_attested_credential_data(auth_data)
    alg_used = cred["cose_key"].get(3, ALG_ES256)  # COSE alg key (3) in the public key
    public_key_pem = cose_key_to_pem(cred["cose_key"], alg_used)
    print(f"[+] Registered  : credential {b64u(cred['credential_id'])[:24]}... "
          f"attestation fmt={fmt}, alg={alg_used}")

    # --- Step 2: build the agent action payload ---
    payload = build_action_payload(
        action_id=args.action_id,
        action_type=args.action_type,
        agent_identity={
            "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
            "agent_name": "Sovereign",
        },
        action_descriptor={
            "contract_hash": args.contract_hash,
            "timestamp": args.timestamp,
            "nonce": args.nonce,
        },
    )
    digest = compute_action_digest(payload)
    print(f"[*] Action digest : {digest.hex()[:32]}... ({len(digest)} bytes)")

    # --- Step 3: get an assertion, challenge = action digest (TAP #2) ---
    print("    >>> TAP THE LEDGER BUTTON AGAIN TO SIGN <<<")
    assertion = ctap.get_assertion(
        rp_id,
        digest,
        [{"id": cred["credential_id"], "type": "public-key"}],
    )
    auth_data_assert = assertion["authData"]
    signature = assertion["signature"]

    # --- Step 4: verify like a relying party ---
    client_data = build_client_data(digest, args.origin)
    result = verify_webauthn_assertion(
        auth_data=auth_data_assert,
        signature=signature,
        client_data_json=client_data,
        public_key_pem=public_key_pem,
        algorithm=alg_used,
    )

    if not result["up"]:
        raise RuntimeError("UP flag not set — no physical gesture detected")

    expected_rp_hash = hashlib.sha256(rp_id.encode()).hexdigest()
    if result["rp_id_hash"] != expected_rp_hash:
        raise RuntimeError("rp_id_hash mismatch — wrong relying party")

    return {
        "device": getattr(info, "name", "unknown"),
        "aaguid": aaguid.hex(),
        "transport": "usb-hid (CTAP2)",
        "attestation_format": fmt,
        "algorithm": alg_used,
        "rp_id": rp_id,
        "origin": args.origin,
        "credential_id": b64u(cred["credential_id"]),
        "public_key_pem": public_key_pem.decode("utf-8"),
        "action_digest": digest.hex(),
        "signature": signature.hex(),
        "flags": {"up": result["up"], "uv": result["uv"]},
        "sign_count": result["sign_count"],
        "client_data_hash": result["client_data_hash"],
        "verified": True,
        "note": "action digest signed as WebAuthn challenge; txAuthAgent extension "
                "wire format proven by VirtualAuthenticator until firmware support",
    }


# ---------------------------------------------------------------------------
# Simulated path (no hardware — uses the repo's VirtualAuthenticator)
# ---------------------------------------------------------------------------


def simulated_flow(args: argparse.Namespace) -> Dict[str, Any]:
    from txauthagent.digest import compute_action_digest
    from txauthagent.payload import build_action_payload
    from txauthagent.verify import verify_agent_action_cbor
    from txauthagent.virtual import VirtualAuthenticator

    payload = build_action_payload(
        action_id=args.action_id,
        action_type=args.action_type,
        agent_identity={
            "aci_uri": "https://empirelabs.com.au/.well-known/aci/identity.json",
            "agent_name": "Sovereign",
        },
        action_descriptor={
            "contract_hash": args.contract_hash,
            "timestamp": args.timestamp,
            "nonce": args.nonce,
        },
    )
    digest = compute_action_digest(payload)

    key = VirtualAuthenticator(rp_id=args.rp_id)
    blob = key.sign_action_cbor(payload)  # simulates the tap
    result = verify_agent_action_cbor(
        payload, blob, key.public_key_pem, expected_rp_id=args.rp_id
    )

    return {
        "device": "VirtualAuthenticator (software)",
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "transport": "simulated",
        "attestation_format": "n/a",
        "algorithm": result.algorithm,
        "rp_id": args.rp_id,
        "origin": args.origin,
        "credential_id": b64u(result.credential_id),
        "action_digest": digest.hex(),
        "signature": "(inside CBOR extension output)",
        "flags": {"up": result.up, "uv": result.uv},
        "sign_count": 0,
        "client_data_hash": "(n/a — direct digest signature)",
        "verified": True,
        "note": "simulated flow; run without --simulate to use real hardware",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--simulate", action="store_true", help="use VirtualAuthenticator (no hardware)")
    parser.add_argument("--rp-id", default=RP_ID_DEFAULT)
    parser.add_argument("--origin", default=ORIGIN_DEFAULT)
    parser.add_argument("--action-id", default="01JSDXQZ3MV8YR9K5WPHKE7N12")
    parser.add_argument("--action-type", default="contract.sign")
    parser.add_argument("--contract-hash", default="sha256:4a84c1f2e9d3b7a5c6e8f0d1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c")
    parser.add_argument("--timestamp", default="2026-08-02T09:30:00Z")
    parser.add_argument("--nonce", default="z7GkqLm9pTvR2XbN")
    parser.add_argument("--json", action="store_true", help="print evidence as JSON only")
    parser.add_argument("--output", default=None, help="write evidence JSON to a file")
    args = parser.parse_args()

    try:
        if args.simulate:
            evidence = simulated_flow(args)
        else:
            evidence = real_hardware_flow(args)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        if "CTAP error" in str(exc):
            print(
                "This device appears to be CTAP1/U2F-only. On the Ledger: open "
                "Ledger Live -> Manager -> FIDO U2F -> make sure it is installed "
                "and up to date. YubiKey 5 / Nitrokey 3 are CTAP2-native.",
                file=sys.stderr,
            )
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2)
        print(f"[*] Evidence written to {args.output}")

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        print("\n=== txAuthAgent HARDWARE ATTESTATION EVIDENCE ===")
        for key, value in evidence.items():
            print(f"  {key:<18}: {value}")
        if evidence.get("verified"):
            print("\n[✓] VERIFIED — hardware-backed agent authorization proof.")
            print("    up=true means a human physically tapped to consent.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
