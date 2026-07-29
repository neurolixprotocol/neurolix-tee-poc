#!/usr/bin/env python3
"""
build_model.py — Neurolix Protocol (BUILD-TIME, runs OUTSIDE the enclave)

Produces the baked-in AI artifact for the confidential medical inference and its
SHA-256 digest. This is what closes audit findings C4 (no runtime model fetch)
and M4 (train != inference data):

  - The model is trained HERE, at image-build time, on a dedicated training set
    (never on the data it will later score).
  - The serialized artifact is hashed; `model.sha256` is the `model_digest`
    that (a) the runtime verifies before use, (b) you bind into the commitment,
    (c) identifies the model independently of the full image digest.
  - The artifact is COPIED INTO the container image (baked in). The enclave does
    no network I/O to obtain it.

Determinism: training uses a fixed seed and single-threaded fitting so a rebuild
on the same stack is reproducible. The artifact bytes + digest are build outputs;
the runtime ships and verifies exactly those bytes, so cross-version byte-
stability of the serializer is not required for the trust model (the attested
image pins the bytes).

Replace `_synthetic_training_set()` with your real, governed training data.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

FEATURES = ["age", "glucose", "bp", "bmi", "insulin"]
SCHEMA = "neurolix.medical.v1"
SEED = 42


def _synthetic_training_set(n: int = 800, seed: int = SEED) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic, clearly-synthetic training data. NOT the inference input.
    Risk is a monotone function of glucose/bmi/age plus noise — placeholder for a
    real, governed clinical dataset."""
    rng = np.random.default_rng(seed)
    age = rng.integers(21, 80, n)
    glucose = rng.integers(70, 200, n)
    bp = rng.integers(50, 110, n)
    bmi = rng.normal(30, 6, n).clip(16, 55)
    insulin = rng.integers(0, 300, n)
    logit = (
        0.03 * (glucose - 120)
        + 0.08 * (bmi - 30)
        + 0.02 * (age - 45)
        + rng.normal(0, 1.0, n)
    )
    risk = (logit > 0).astype(int)
    X = np.column_stack([age, glucose, bp, bmi, insulin]).astype(float)
    return X, risk


def train() -> dict:
    X, y = _synthetic_training_set()
    scaler = StandardScaler().fit(X)
    model = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=1)
    model.fit(scaler.transform(X), y)
    return {
        "schema": SCHEMA,
        "features": FEATURES,
        "scaler": scaler,
        "model": model,
        "sklearn_version": __import__("sklearn").__version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }


def main(model_path: str = "model.joblib", digest_path: str = "model.sha256") -> None:
    bundle = train()
    joblib.dump(bundle, model_path, compress=3, protocol=4)

    with open(model_path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    with open(digest_path, "w", encoding="utf-8") as fh:
        fh.write(digest + "\n")

    meta = {
        "model_path": model_path,
        "schema": SCHEMA,
        "features": FEATURES,
        "sklearn_version": bundle["sklearn_version"],
        "model_digest": digest,  # bytes32 (sha256) — bake in & use for verification
    }
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    args = sys.argv[1:]
    main(*(args or []))
