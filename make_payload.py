#!/usr/bin/env python3
"""
make_payload.py — Neurolix Protocol (BUILD-TIME, runs OUTSIDE the enclave)

Produces the AES-256-GCM envelope that inference.py consumes, plus the run
parameters for the Confidential Space VM.

This is the DATA OWNER's side of the PoC. In production it runs on the data
owner's infrastructure and the DEK is wrapped by a KMS key whose release policy
is gated on the enclave's attestation (image digest in the Workload Identity
Pool provider). Here the DEK is emitted in the clear so the operator can pass
it as a VM metadata variable — acceptable ONLY because the records are
synthetic. This limitation must be stated in any public write-up.

Usage:
    python make_payload.py                 # 20 records, deterministic
    python make_payload.py --records 50

Outputs:
    payload.json   the encrypted envelope (baked into the container image)
    stdout         DEK, session id, and the exact metadata block for the VM
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match inference.py exactly.
FEATURES = ["age", "glucose", "bp", "bmi", "insulin"]
SCHEMA = "neurolix.medical.v1"
KEY_REF = "demo"

# Physiological ranges — kept inside inference.py's fail-closed bounds.
_GEN_RANGES = {
    "age": (25, 78),
    "glucose": (72, 195),
    "bp": (55, 105),
    "bmi": (18.5, 44.0),
    "insulin": (10, 280),
}


def synthetic_records(n: int, seed: int) -> list[dict[str, Any]]:
    """Deterministic synthetic patients. NOT real clinical data — the whole
    point is that this PoC never touches a real medical record."""
    import random

    rng = random.Random(seed)
    records = []
    for i in range(n):
        r: dict[str, Any] = {"id": f"SYNTH-{i:04d}"}
        for f in FEATURES:
            lo, hi = _GEN_RANGES[f]
            value = rng.uniform(lo, hi)
            r[f] = round(value, 1) if f == "bmi" else int(value)
        records.append(r)
    return records


def build_envelope(records: list[dict[str, Any]], dek: bytes) -> dict[str, str]:
    """AES-256-GCM encrypt the records. The schema string is bound as AAD, so a
    ciphertext cannot be replayed under a different schema without failing the
    authentication tag."""
    plaintext = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    aad = SCHEMA.encode("utf-8")
    nonce = os.urandom(12)  # GCM standard nonce length; never reuse with a key
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return {
        "alg": "AES-256-GCM",
        "key_ref": KEY_REF,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate the encrypted PoC payload.")
    ap.add_argument("--records", type=int, default=20, help="number of synthetic patients")
    ap.add_argument("--seed", type=int, default=1337, help="seed for the synthetic generator")
    ap.add_argument("--out", default="payload.json", help="output envelope path")
    args = ap.parse_args()

    if not 1 <= args.records <= 10_000:
        raise SystemExit("records must be between 1 and 10000 (inference.py hard cap)")

    records = synthetic_records(args.records, args.seed)

    # 256-bit DEK and 256-bit session id, both from the OS CSPRNG.
    dek = secrets.token_bytes(32)
    session_id = secrets.token_bytes(32)

    envelope = build_envelope(records, dek)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
        fh.write("\n")

    dek_b64 = base64.b64encode(dek).decode("ascii")
    payload_sha = hashlib.sha256(json.dumps(envelope, sort_keys=True).encode()).hexdigest()

    print(json.dumps({
        "envelope_path": args.out,
        "records": args.records,
        "schema": SCHEMA,
        "key_ref": KEY_REF,
        "envelope_sha256": payload_sha,
        "NEUROLIX_DEK_" + KEY_REF: dek_b64,
        "NEUROLIX_SESSION_ID": session_id.hex(),
    }, indent=2))

    print(
        "\n--- Keep the two values above. The DEK is NOT stored anywhere else. ---\n"
        "\nVM metadata block (substitute into the deploy command):\n"
        f"  tee-env-NEUROLIX_DEK_{KEY_REF}={dek_b64}\n"
        f"  tee-env-NEUROLIX_SESSION_ID={session_id.hex()}\n"
        "  tee-env-NEUROLIX_PAYLOAD_FILE=/app/payload.json\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
