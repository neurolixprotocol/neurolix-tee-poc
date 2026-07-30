#!/usr/bin/env python3
"""
test_attestor_invariants.py — regression guards for bridge/attestor.py.

These are not unit tests of happy paths. Each case locks a property whose
silent loss would not break anything visible, which is exactly why they need a
test. The published bundle is used as the fixture: if verification of the real
artifact ever stops working, that is itself a failure worth catching.

    python3 tests/test_attestor_invariants.py

Requires the attestor dependencies (requirements-attestor.txt). Exit code 0 if
every invariant holds.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bridge"))

import jwt  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

from attestor import (  # noqa: E402
    MODE_ARCHIVAL,
    MODE_LIVE,
    TOKEN_TYPE_OIDC,
    TOKEN_TYPE_PKI,
    AttestorError,
    attest,
    verify_bundle,
)

BUNDLE_PATH = ROOT / "attestations" / "bundle-pki-v4.json"
DUMMY_KEY = "0x" + "11" * 32  # never used: attest() must refuse before signing

_failures: list[str] = []


def _load() -> dict:
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))


def expect_ok(label: str, fn) -> None:
    try:
        fn()
        print(f"  [PASS] {label}")
    except Exception as exc:
        _failures.append(label)
        print(f"  [FAIL] {label} — unexpectedly raised {type(exc).__name__}: {exc}")


def expect_refused(label: str, fn, *, because: str) -> None:
    """The invariant is that this FAILS, and fails for the stated reason.
    A test that only checks 'it raised' would pass for the wrong reason."""
    try:
        fn()
    except AttestorError as exc:
        if because.lower() in str(exc).lower():
            print(f"  [PASS] {label}")
        else:
            _failures.append(label)
            print(f"  [FAIL] {label} — refused, but for the wrong reason: {exc}")
    except Exception as exc:
        _failures.append(label)
        print(f"  [FAIL] {label} — raised {type(exc).__name__} instead of AttestorError: {exc}")
    else:
        _failures.append(label)
        print(f"  [FAIL] {label} — was ACCEPTED. The guard is gone.")


def _verify(bundle: dict, **kw):
    return verify_bundle(
        bundle,
        expected_audience=bundle["audience"],
        image_digest_allowlist=None,
        **kw,
    )


def main() -> int:
    bundle = _load()
    print(f"\nFixture: {BUNDLE_PATH.relative_to(ROOT)}\n")

    # --- 1. The published artifact still verifies ------------------------------
    print("1. Archival verification of the published PKI bundle")
    expect_ok(
        "verifies offline in archival mode with PKI pinned",
        lambda: _verify(bundle, mode=MODE_ARCHIVAL, require_token_type=TOKEN_TYPE_PKI),
    )

    # --- 2. Live mode still enforces exp --------------------------------------
    # If this ever passes, `exp` has stopped being enforced and every archived
    # bundle becomes a replayable authorisation.
    print("\n2. Live mode enforces token expiry")
    expect_refused(
        "an archived (expired) token is refused in live mode",
        lambda: _verify(bundle, mode=MODE_LIVE),
        because="has expired",
    )

    # --- 3. No silent downgrade ------------------------------------------------
    print("\n3. Token type cannot be downgraded silently")
    expect_refused(
        "a PKI token is refused when OIDC is required",
        lambda: _verify(bundle, mode=MODE_ARCHIVAL, require_token_type=TOKEN_TYPE_OIDC),
        because="expected a OIDC token",
    )

    # --- 4. THE hard constraint ------------------------------------------------
    # attest() signs an EIP-712 claim for on-chain submission. Signing an
    # archived proof would make every published bundle a free replay.
    print("\n4. attest() refuses archival verification")
    expect_refused(
        "attest() will not sign a claim from an archived proof",
        lambda: attest(
            json.dumps(bundle),
            private_key=DUMMY_KEY,
            chain_id=8453,
            verifier_address="0xDcCCda8662996b479bE5C5d44115a03a43a92F1B",
            mode=MODE_ARCHIVAL,
        ),
        because="refuses non-live verification",
    )

    # --- 5. The root pin actually pins ----------------------------------------
    # Substitute a different, perfectly valid Google certificate as the root.
    # Only the digest pin can catch this; chain-walking alone would not.
    print("\n5. Root certificate is pinned by digest")
    header = jwt.get_unverified_header(bundle["attestation_token"])
    intermediate = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][1]))
    with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as fh:
        fh.write(intermediate.public_bytes(serialization.Encoding.PEM))
        wrong_root = fh.name
    expect_refused(
        "a substituted root is refused even though it is a genuine Google cert",
        lambda: _verify(
            bundle,
            mode=MODE_ARCHIVAL,
            require_token_type=TOKEN_TYPE_PKI,
            root_pem_path=wrong_root,
        ),
        because="does not match cs_root_sha256",
    )

    # --- 6. Commitments cannot be detached from the nonce ---------------------
    # The whole point of the V2 design (audit finding C2). Swapping a
    # commitment must break the binding before any signature is even checked.
    print("\n6. Commitments are bound to the nonce")
    tampered = copy.deepcopy(bundle)
    tampered["output_commitment"] = "0x" + "00" * 32
    expect_refused(
        "a swapped output_commitment breaks the binding",
        lambda: _verify(tampered, mode=MODE_ARCHIVAL, require_token_type=TOKEN_TYPE_PKI),
        because="does not match its own fields",
    )

    # --- 7. Audience override is rejected --------------------------------------
    print("\n7. Audience override is rejected")
    expect_refused(
        "expected_audience cannot diverge from the derived audience",
        lambda: attest(
            json.dumps(bundle),
            private_key=DUMMY_KEY,
            chain_id=8453,
            verifier_address="0xDcCCda8662996b479bE5C5d44115a03a43a92F1B",
            expected_audience="neurolix://base/8453/0xbadbadbadbadbadbadbadbadbadbadbadbadbad",
            mode=MODE_LIVE,
        ),
        because="expected_audience does not match",
    )

    # --- 7b. ...but only when it actually diverges -----------------------------
    # Case 7 proves the guard fires. This proves it does NOT over-fire: a
    # matching expected_audience must pass through and let verification proceed,
    # so the refusal we see here is the expired token, not the audience check.
    # Without this, `raise` unconditionally would still pass case 7.
    print("\n7b. A matching audience is not rejected by the audience guard")
    expect_refused(
        "an explicit but matching expected_audience reaches verification",
        lambda: attest(
            json.dumps(bundle),
            private_key=DUMMY_KEY,
            chain_id=8453,
            verifier_address="0xDcCCda8662996b479bE5C5d44115a03a43a92F1B",
            expected_audience="neurolix://base/8453/0xdcccda8662996b479be5c5d44115a03a43a92f1b",
            mode=MODE_LIVE,
        ),
        because="has expired",
    )

    print()
    if _failures:
        print(f"RESULT: {len(_failures)} invariant(s) BROKEN\n")
        for f in _failures:
            print(f"  - {f}")
        print()
        return 1
    print("RESULT: all invariants hold\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
