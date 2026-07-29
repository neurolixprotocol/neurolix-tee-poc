#!/usr/bin/env python3
"""
verify.py — independent, offline verification of a Neurolix attestation bundle.

Requires only `cryptography`. Performs no network access: the certificate chain
travels inside the token itself. The only external reference is the root
fingerprint below, which anyone can confirm once against Google's published
root and then cache indefinitely.

    pip install cryptography
    python3 verify.py attestations/bundle-pki-v4.json

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

# sha256(b"NEUROLIX/attestation/nonce/v1") — mirrored in the Solidity verifier.
DST_NONCE = "e501d736b800d00539784c76a1f5334cb8f26b0bd7319fc02d2a6c149e9ba6d2"

# SHA-256 of the DER encoding of the Confidential Space Root CA, published at
# https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
# (that endpoint returns a discovery document; follow its `root_ca_uri`).
GOOGLE_ROOT_SHA256 = "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39"

EXPECTED_ISSUER = "https://confidentialcomputing.googleapis.com"


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
    preimage = bytes.fromhex(
        DST_NONCE
        + strip0x(bundle["session_id"])
        + strip0x(bundle["model_digest"])
        + strip0x(bundle["input_commitment"])
        + strip0x(bundle["output_commitment"])
    )
    r.check("preimage is 160 bytes", len(preimage) == 160, f"{len(preimage)} bytes")
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
