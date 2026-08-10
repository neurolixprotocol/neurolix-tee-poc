#!/usr/bin/env python3
"""
verify.py — independent, offline verification of a Neurolix attestation bundle.

Requires only `cryptography`. Performs no network access: the certificate chain
travels inside the token itself. The only external reference is the root
fingerprint below, which anyone can confirm once against Google's published
root and then cache indefinitely.

    pip install cryptography
    python3 verify.py attestations/bundle-pki-v5.json

Bundle schema v2 only. bundle-pki-v4.json predates consumed_sec in the nonce
preimage and will be refused at check 1 — that is intended, not a regression.

Exit code 0 if every check passes, 1 otherwise.

On token expiry: attestation tokens carry a ~1 hour TTL, so an archived bundle
is always past `exp`. That is expected and is NOT a verification failure. The
question for an archived proof is whether the token was validly issued and
whether its signature still verifies — both remain answerable indefinitely.
This script reports `iat` and does not enforce `exp`. A live authorisation
path MUST enforce it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# sha256(b"NEUROLIX/attestation/nonce/v2") — mirrored in the Solidity verifier.
# v1.18: bumped from /v1 alongside the 168-byte preimage. The two changes are
# independent (different lengths already produce different hashes), but leaving
# the tag at v1 would have had the domain separator assert a scheme that no
# longer exists. Done now because every fixture is being regenerated anyway.
# v1 was e501d736b800d00539784c76a1f5334cb8f26b0bd7319fc02d2a6c149e9ba6d2
DST_NONCE = "117254d7707ce55039977d24974a1cb56dca1e6037c31143d063e4b877051232"

# SHA-256 of the DER encoding of the Confidential Space Root CA, published at
# https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
# (that endpoint returns a discovery document; follow its `root_ca_uri`).
GOOGLE_ROOT_SHA256 = "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39"

EXPECTED_ISSUER = "https://confidentialcomputing.googleapis.com"

# DELIBERATE DUPLICATION. bridge/attestor.py implements the same chain
# validation. This file is kept standalone on purpose: an auditor should be
# able to read one script with a single dependency rather than trace an import
# graph. The cost is that a change to the verification logic must be applied in
# BOTH files. If they ever disagree, bridge/attestor.py is authoritative.
#
# THAT COST CAME DUE ON 2026-08-04 AND WENT UNPAID FOR TWO DAYS. The v1.18
# metering change added consumed_sec to the nonce preimage in attestation.py
# and attestor.py, but not here. This script kept passing CI because it builds
# the preimage inline and never imports compute_binding_nonce: on a v1 bundle
# the 160-byte hash still matched, so it went green while the rest of the suite
# failed loudly. A duplicate that fails SILENTLY is worse than one that breaks.
#
# Before touching the nonce scheme again, change all THREE:
#   attestation.py (enclave) · bridge/attestor.py (signer) · verify.py (this file)


def b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def strip0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


class Report:
    def __init__(self) -> None:
        self.failed = 0

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        mark = "PASS" if ok else "FAIL"
        if not ok:
            self.failed += 1
        print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))
        return ok

    def note(self, label: str, value: str) -> None:
        print(f"         {label}: {value}")


def verify(path: str) -> int:
    bundle = json.load(open(path, encoding="utf-8"))
    r = Report()

    header_seg, payload_seg, signature_seg = bundle["attestation_token"].split(".")
    header = json.loads(b64url(header_seg))
    claims = json.loads(b64url(payload_seg))
    signature = b64url(signature_seg)

    print(f"\nBundle: {path}")
    print(f"Version: {bundle.get('version')}\n")

    # ---- 1. The binding nonce is consistent with the bundle's own fields ----
    print("1. Commitment binding")
    # v1.18 (bundle schema v2): consumed_sec closes the preimage as 8 big-endian
    # bytes, taking it from 160 to 168. It is IN the preimage, not beside it, so
    # the billed duration is covered by the Google signature over eat_nonce
    # exactly like the commitments — an attestor cannot restate it freely.
    # Fails closed on a bundle without the field: the protocol is v2-only by
    # decision (2026-08-06) and a v1 bundle is a dev artifact to regenerate,
    # never something to coerce into verifying.
    consumed_sec = bundle.get("consumed_sec")
    if not isinstance(consumed_sec, int) or isinstance(consumed_sec, bool):
        r.check("bundle carries consumed_sec (schema v2)", False,
                f"got {type(consumed_sec).__name__} — regenerate this bundle against the current enclave")
        print("\nRESULT: bundle predates the v2 nonce scheme; remaining checks are meaningless\n")
        return 1
    if not (0 <= consumed_sec < 2**64):
        r.check("consumed_sec fits in uint64", False, str(consumed_sec))
        return 1

    preimage = bytes.fromhex(
        DST_NONCE
        + strip0x(bundle["session_id"])
        + strip0x(bundle["model_digest"])
        + strip0x(bundle["input_commitment"])
        + strip0x(bundle["output_commitment"])
        + f"{consumed_sec:016x}"  # uint64 big-endian == abi.encodePacked(uint64) in Solidity
    )
    r.check("preimage is 168 bytes", len(preimage) == 168, f"{len(preimage)} bytes")
    r.note("consumed_sec (billable seconds)", str(consumed_sec))
    recomputed = hashlib.sha256(preimage).hexdigest()
    r.check("recomputed nonce matches bundle", recomputed == strip0x(bundle["binding_nonce"]))

    # ---- 2. That nonce is inside the signed token ----
    print("\n2. Binding is attested")
    r.check("eat_nonce in signed token matches recomputed nonce",
            claims.get("eat_nonce") == recomputed)
    r.check("token audience matches bundle audience",
            claims.get("aud") == bundle.get("audience"))
    r.note("audience", str(claims.get("aud")))

    # ---- 3. JWT signature against the leaf certificate ----
    print("\n3. Token signature")
    if "x5c" not in header:
        r.check("token carries an x5c chain (PKI token)", False,
                "OIDC token — signature needs Google's rotating JWKS, not verifiable offline")
        chain = []
    else:
        chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header["x5c"]]
        r.check("token carries an x5c chain", True, f"{len(chain)} certificates")
        leaf = chain[0]
        signing_input = f"{header_seg}.{payload_seg}".encode()
        try:
            pub = leaf.public_key()
            assert isinstance(pub, rsa.RSAPublicKey)
            pub.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            r.check("signature valid under the leaf certificate", True)
        except Exception as exc:
            r.check("signature valid under the leaf certificate", False, type(exc).__name__)

    # ---- 4. Certificate chain ----
    print("\n4. Certificate chain")
    if len(chain) >= 3:
        for cert in chain:
            r.note("subject", cert.subject.rfc4514_string().split(",")[0])

        def signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
            try:
                parent.public_key().verify(  # type: ignore[union-attr]
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,  # type: ignore[arg-type]
                )
                return True
            except Exception:
                return False

        # Leaf certificates live about two months. An archived bundle must be
        # checked against the instant the token was issued, not against now.
        from datetime import datetime, timezone

        issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
        in_window = all(
            c.not_valid_before_utc <= issued_at <= c.not_valid_after_utc for c in chain
        )
        r.check("every certificate was valid when the token was issued", in_window,
                issued_at.isoformat())

        r.check("leaf signed by intermediate", signed_by(chain[0], chain[1]))
        r.check("intermediate signed by root", signed_by(chain[1], chain[2]))
        r.check("root is self-signed", signed_by(chain[2], chain[2]))

        # ---- 5. Root anchored to Google's published certificate ----
        print("\n5. Root anchor")
        fingerprint = chain[2].fingerprint(hashes.SHA256()).hex()
        r.check("root matches Google's published Confidential Space root",
                fingerprint == GOOGLE_ROOT_SHA256)
        r.note("root fingerprint", fingerprint)
        r.note("root valid until", str(chain[2].not_valid_after_utc.date()))
    else:
        print("   skipped — no certificate chain in this token")

    # ---- Environment claims ----
    print("\n6. Attested environment")
    container = claims.get("submods", {}).get("container", {})
    r.check("issuer is Google Confidential Computing", claims.get("iss") == EXPECTED_ISSUER)
    r.check("debugging disabled since boot", claims.get("dbgstat") == "disabled-since-boot",
            str(claims.get("dbgstat")))
    r.check("secure boot enabled", claims.get("secboot") is True)
    r.note("hardware", str(claims.get("hwmodel")))
    r.note("software", str(claims.get("swname")))
    r.note("image digest", str(container.get("image_digest")))
    r.note("issued at (iat)", str(claims.get("iat")))
    r.note("expired at (exp, not enforced for archived proofs)", str(claims.get("exp")))

    print()
    if r.failed:
        print(f"RESULT: {r.failed} check(s) FAILED\n")
        return 1
    print("RESULT: all checks passed\n")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(verify(sys.argv[1]))
