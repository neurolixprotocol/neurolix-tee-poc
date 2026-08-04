#!/usr/bin/env python3
"""
inference.py — Neurolix Protocol (RUNTIME, runs INSIDE the enclave)

Deterministic confidential medical inference that closes the PoC's audit gaps:

  C1 (fake base64 "encryption")  -> real AES-256-GCM authenticated decryption;
                                    the DEK comes from a KeyProvider that, in
                                    production, releases it ONLY to an attested
                                    enclave (KMS + Workload Identity Pool policy
                                    on the image digest). No plaintext in source.
  C3 (plaintext to stdout/logs)  -> NOTHING sensitive is ever logged or printed.
                                    Only counts and hashes leave this module.
  C4 (runtime model download)    -> the model is BAKED IN; its sha256 is verified
                                    against the build-time digest before any use.
                                    No network I/O for the model.
  H1 (non-reproducible output)   -> NO training at runtime; pure deterministic
                                    inference; outputs serialized at fixed
                                    precision so the commitment is stable.
  H3 (no input validation -> DoS)-> strict schema/type/range validation; malformed
                                    input fails closed, never crashes the enclave.
  M4 (train == inference data)   -> the model is pre-trained on held-out data
                                    (see build_model.py); we only score here.

Flow:  encrypted payload --AES-GCM--> records --validate--> deterministic infer
       --canonicalize--> (input_commitment, output_commitment) --build bundle
       (attestation.py: binding nonce = session_id-bound, real TEE token).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import time
from dataclasses import dataclass
from typing import Any, Final, Protocol

import joblib
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import attestation as att

FEATURES: Final[list[str]] = ["age", "glucose", "bp", "bmi", "insulin"]
SCHEMA: Final[str] = "neurolix.medical.v1"
SCORE_DECIMALS: Final[int] = 4  # fixed-precision output -> deterministic commitment

# Plausible physiological bounds for fail-closed validation (reject, don't clip).
_RANGES: Final[dict[str, tuple[float, float]]] = {
    "age": (0, 120),
    "glucose": (0, 600),
    "bp": (0, 250),
    "bmi": (5, 100),
    "insulin": (0, 2000),
}

_MODEL_PATH: Final[str] = "model.joblib"
_DIGEST_PATH: Final[str] = "model.sha256"

# v1.18 metering. Captured at MODULE IMPORT, which is the earliest point the workload
# controls — so the billed window covers model load, payload download and decryption,
# not just the scoring call. Those are real GPU-blocking seconds for the node.
#
# time.monotonic(), never time.time(): a duration must not move when the host steps
# the wall clock (NTP, a manual set, or a hostile operator). Monotonic is still
# host-supplied — the enclave has no trusted clock — but it removes the trivial
# manipulations and leaves only the ones the chain's own elapsed-time bound catches.
_PROCESS_START_MONOTONIC: Final[float] = time.monotonic()

# The node is never billed for less than this, even on an instant failure. It is the
# floor that makes a corrupt-payload DoS cost the attacker something: without it, an
# attacker uploads garbage, the node boots an enclave, fails in three seconds and earns
# nothing. Mirrors ComputeSession.MIN_BILLABLE_SEC — the two MUST stay equal.
_MIN_BILLABLE_SEC: Final[int] = 60


def elapsed_consumed_sec() -> int:
    """Billable enclave duration in whole seconds, rounded UP.

    Rounded up so a sub-second run bills 1s rather than 0 — a zero would make the
    on-chain settlement mint nothing for the node while still consuming the session.
    """
    elapsed = math.ceil(time.monotonic() - _PROCESS_START_MONOTONIC)
    return max(int(elapsed), 1)

_log = logging.getLogger("neurolix.inference")


class InferenceError(Exception):
    """Fail-closed error. Messages never contain patient data."""


# --------------------------------------------------------------------------- #
# Key provider (DEK source). Production = attestation-gated KMS (Option 1).
# --------------------------------------------------------------------------- #

class KeyProvider(Protocol):
    def get_dek(self, key_ref: str) -> bytes: ...


class EnvKeyProvider:
    """DEV ONLY. Reads a base64 DEK from env var NEUROLIX_DEK_<key_ref>.
    In production this is replaced by a KMS client that releases the DEK only
    when the caller presents a valid Confidential Space attestation whose image
    digest matches the Workload Identity Pool policy."""

    def get_dek(self, key_ref: str) -> bytes:
        import os

        raw = os.environ.get(f"NEUROLIX_DEK_{key_ref}")
        if not raw:
            raise InferenceError("DEK unavailable for key_ref")
        try:
            dek = base64.b64decode(raw)
        except Exception as exc:
            raise InferenceError("malformed DEK") from exc
        if len(dek) not in (16, 24, 32):
            raise InferenceError("DEK must be a 128/192/256-bit AES key")
        return dek


# --------------------------------------------------------------------------- #
# Authenticated decryption
# --------------------------------------------------------------------------- #

def decrypt_payload(envelope: dict[str, Any], key_provider: KeyProvider) -> list[dict[str, Any]]:
    """AES-256-GCM authenticated decryption of the patient payload.
    Envelope: {alg, key_ref, nonce(b64), ciphertext(b64), aad(b64?)}.
    Raises InferenceError on auth failure (tamper) or malformed input.
    The decrypted plaintext is never logged."""
    if envelope.get("alg") != "AES-256-GCM":
        raise InferenceError("unsupported envelope alg")
    try:
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        aad = base64.b64decode(envelope["aad"]) if envelope.get("aad") else None
        key_ref = envelope["key_ref"]
    except (KeyError, ValueError, TypeError) as exc:
        raise InferenceError("malformed envelope") from exc
    if len(nonce) != 12:
        raise InferenceError("GCM nonce must be 12 bytes")

    dek = key_provider.get_dek(key_ref)
    try:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # InvalidTag etc. — do NOT leak details
        raise InferenceError("payload authentication failed") from exc

    try:
        records = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise InferenceError("payload is not valid JSON") from exc
    finally:
        del plaintext  # drop the cleartext reference promptly

    if not isinstance(records, list) or not records:
        raise InferenceError("payload must be a non-empty list of records")
    return records


# --------------------------------------------------------------------------- #
# Validation (fail-closed; anti-DoS, anti-manipulation)
# --------------------------------------------------------------------------- #

def validate_records(records: list[dict[str, Any]]) -> None:
    if len(records) > 10_000:
        raise InferenceError("too many records")
    seen_ids = set()
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            raise InferenceError(f"record {i} is not an object")
        pid = r.get("id")
        if not isinstance(pid, str) or not pid or len(pid) > 128:
            raise InferenceError(f"record {i} has an invalid id")
        if pid in seen_ids:
            raise InferenceError("duplicate patient id")
        seen_ids.add(pid)
        for f in FEATURES:
            v = r.get(f)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise InferenceError(f"record {i} field {f} must be numeric")
            if not math.isfinite(float(v)):
                raise InferenceError(f"record {i} field {f} is not finite")
            lo, hi = _RANGES[f]
            if not (lo <= float(v) <= hi):
                raise InferenceError(f"record {i} field {f} out of range")


# --------------------------------------------------------------------------- #
# Baked-model loading (digest-verified) + deterministic inference
# --------------------------------------------------------------------------- #

def load_model(model_path: str = _MODEL_PATH, digest_path: str = _DIGEST_PATH) -> dict[str, Any]:
    """Load the baked model and verify its sha256 against the build-time digest.
    Fails closed on mismatch (tampered/wrong model)."""
    try:
        with open(model_path, "rb") as fh:
            blob = fh.read()
        with open(digest_path, "r", encoding="utf-8") as fh:
            expected = fh.read().strip().lower()
    except OSError as exc:
        raise InferenceError("baked model or digest file missing") from exc

    actual = hashlib.sha256(blob).hexdigest()
    if actual != expected:
        raise InferenceError("model digest mismatch — refusing to load")

    bundle = joblib.load(model_path)
    if bundle.get("schema") != SCHEMA or bundle.get("features") != FEATURES:
        raise InferenceError("unexpected model schema")
    return bundle


def model_digest_bytes(digest_path: str = _DIGEST_PATH) -> bytes:
    with open(digest_path, "r", encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


def run_inference(model_bundle: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Deterministic, pure inference. No training, no randomness, no time.
    Scores are emitted as fixed-precision STRINGS so the canonical output (and
    thus the commitment) is bit-stable."""
    scaler = model_bundle["scaler"]
    model = model_bundle["model"]
    X = np.array([[float(r[f]) for f in FEATURES] for r in records], dtype=float)
    proba = model.predict_proba(scaler.transform(X))[:, 1]
    out: list[dict[str, str]] = []
    for r, p in zip(records, proba):
        score = f"{round(float(p), SCORE_DECIMALS):.{SCORE_DECIMALS}f}"
        out.append(
            {
                "patient_id": r["id"],
                "risk_score": score,
                "classification": "HIGH_RISK" if float(score) > 0.5 else "LOW_RISK",
            }
        )
    out.sort(key=lambda d: d["patient_id"])  # order-independent commitment
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ConfidentialResult:
    canonical_input: bytes
    canonical_output: bytes
    n_records: int


def run_confidential_inference(
    envelope: dict[str, Any],
    key_provider: KeyProvider,
    model_bundle: dict[str, Any],
) -> ConfidentialResult:
    """Decrypt -> validate -> deterministic infer -> canonicalize. Returns only
    canonical BYTES (for commitments); the cleartext and results are not logged."""
    records = decrypt_payload(envelope, key_provider)
    validate_records(records)

    # Canonical input commits to the decrypted features WITHOUT revealing them
    # (it is hashed downstream). Sorted, fixed shape.
    canon_in_obj = {
        "schema": SCHEMA,
        "records": sorted(
            ({"id": r["id"], **{f: float(r[f]) for f in FEATURES}} for r in records),
            key=lambda d: d["id"],
        ),
    }
    canonical_input = att.canonical_json(canon_in_obj)

    results = run_inference(model_bundle, records)
    canonical_output = att.canonical_json({"schema": SCHEMA, "results": results})

    _log.info("inference complete: %d records (no plaintext logged)", len(records))
    return ConfidentialResult(canonical_input, canonical_output, len(records))


def emit_attestation_bundle(
    result: ConfidentialResult,
    *,
    session_id: bytes,
    model_digest: bytes,
    chain_id: int,
    verifier_address: str,
) -> att.AttestationBundle:
    """Wrap the deterministic result with the session-bound TEE attestation
    (binding nonce includes session_id + model_digest + I/O commitments +
    consumed_sec).

    consumed_sec is read HERE, at the last possible moment before the token is
    requested, so the billed window is as close as possible to the true lifetime
    of the workload. Everything after this point is token retrieval and printing.
    """
    return att.build_attestation_bundle(
        session_id=session_id,
        model_digest=model_digest,
        canonical_input=result.canonical_input,
        canonical_output=result.canonical_output,
        consumed_sec=elapsed_consumed_sec(),
        chain_id=chain_id,
        verifier_address=verifier_address,
        # PKI produces a self-contained token carrying its own x5c chain, so an
        # archived bundle stays verifiable offline against the long-lived
        # Confidential Space root. OIDC tokens depend on a JWKS key that Google
        # rotates, which eventually makes a published artifact unverifiable.
        token_type=os.environ.get("NEUROLIX_TOKEN_TYPE", att.TOKEN_TYPE_OIDC),
    )


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

# Confidential Space runs with swap DISABLED: an oversized payload does not
# slow the workload down, it crashes it. Hard cap before touching the file
# (audit H3).
_MAX_PAYLOAD_BYTES: Final[int] = 8 * 1024 * 1024


def _load_envelope(path: str) -> dict[str, Any]:
    """Read the encrypted envelope with a hard size cap. Fails closed."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise InferenceError("payload file unavailable") from exc
    if size > _MAX_PAYLOAD_BYTES:
        raise InferenceError("payload file exceeds the maximum allowed size")
    with open(path, "r", encoding="utf-8") as fh:
        envelope = json.load(fh)
    if not isinstance(envelope, dict):
        raise InferenceError("envelope must be a JSON object")
    return envelope


def _main() -> int:
    bundle_model = load_model()
    session_id = att.session_id_from_hex(os.environ["NEUROLIX_SESSION_ID"])
    md = model_digest_bytes()

    # The encrypted payload arrives via the job (here from a file path env).
    envelope = _load_envelope(os.environ["NEUROLIX_PAYLOAD_FILE"])

    result = run_confidential_inference(envelope, EnvKeyProvider(), bundle_model)
    att_bundle = emit_attestation_bundle(
        result,
        session_id=session_id,
        model_digest=md,
        chain_id=int(os.environ.get("NEUROLIX_CHAIN_ID", "8453")),
        verifier_address=os.environ["NEUROLIX_VERIFIER_ADDRESS"],
    )
    # Hashes and token only — never plaintext. stdout is the only practical
    # egress channel from a production Confidential Space image (no SSH).
    # Audit §C3 explicitly permits token/commitment output on stdout.
    print(att_bundle.to_json())
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        sys.exit(_main())
    except (InferenceError, att.AttestationError) as exc:
        # Both exception types are scrubbed by construction: their messages
        # describe protocol state, never payload contents. attestation.py raises
        # AttestationError, which is NOT an InferenceError — catching only the
        # latter previously discarded every attestation diagnostic.
        _log.error("fail-closed: %s: %s", type(exc).__name__, exc)
        sys.exit(2)
    except Exception as exc:
        # Truly unexpected: log the class only. The message could echo input,
        # and the traceback never reaches Cloud Logging (audit H4).
        _log.error("fail-closed: unexpected %s (message withheld)", type(exc).__name__)
        sys.exit(3)
