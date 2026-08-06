#!/usr/bin/env python3
"""
attestor.py — Neurolix Protocol

Off-chain ATTESTOR service: the single trust anchor of the v1 verification
pipeline. It runs OUTSIDE the enclave, on relay infrastructure, and bridges a
Google-signed Confidential Space attestation token to an on-chain EIP-712
`AttestationClaim` that NeurolixAttestationVerifier.submitAttestation accepts.

Pipeline position:
    enclave (attestation.py)  --bundle(JSON: fields + JWT)-->  attestor.py
    attestor.py  --verify JWT, sign EIP-712-->  relay  --submitAttestation-->  chain

What it verifies on the JWT (fail-closed on any miss):
  1. Signature        — RS256 against Google's JWKS (key resolved by `kid`),
                        with the JWKS URI discovered from the issuer's OIDC doc.
  2. Issuer           — exactly https://confidentialcomputing.googleapis.com.
  3. Audience         — exactly the protocol audience the enclave requested
                        (neurolix://base/<chainId>/<verifier>), preventing a
                        token minted for another relying party from being reused.
  4. Expiry / iat     — required; small leeway for clock skew.
  5. dbgstat          — "disabled-since-boot" (reject debug/insecure enclaves).
  6. swname           — "CONFIDENTIAL_SPACE".
  7. hwmodel          — in the configured allowlist (e.g. GCP_AMD_SEV).
  8. image_digest     — submods.container.image_digest in the approved set.
  9. eat_nonce        — equals the binding_nonce, which is ALSO recomputed from
                        the bundle's commitments (sha256, same DST as the enclave
                        and the contract). This is the linchpin tying the signed
                        claim to the exact computation the token attested.

Security posture:
  - The attestor's signing key authorizes on-chain attestations. In production
    it MUST live in an HSM/Cloud KMS (sign via the KMS API), NOT an env var.
    The env-key path here is for development only.
  - Decentralize over time: run M-of-N attestors (multiple ATTESTOR_ROLE keys),
    stake/slash via the SlashingManager, and publish every JWT so anyone can
    independently re-verify and challenge.
  - Upgrade path to trustless: replace this signer with on-chain RS256 against a
    JWKS registry, or a zk-JWT proof verified on-chain.

Dependencies (see requirements at the bottom of this file):
    PyJWT[crypto]>=2.8, eth-account>=0.11   (eth-abi/eth-utils come transitively)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Iterable

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

# Single source of truth for the nonce scheme (identical bytes to the contract).
from attestation import DST_NONCE, compute_binding_nonce, protocol_audience

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CS_ISSUER: Final[str] = "https://confidentialcomputing.googleapis.com"
CS_DISCOVERY_URL: Final[str] = CS_ISSUER + "/.well-known/openid-configuration"

ALLOWED_ALGS: Final[list[str]] = ["RS256"]
REQUIRED_SWNAME: Final[str] = "CONFIDENTIAL_SPACE"
REQUIRED_DBGSTAT: Final[str] = "disabled-since-boot"

# Token types. OIDC signatures are checked against a JWKS key that Google
# rotates; PKI tokens carry their own certificate chain and verify offline
# against a long-lived root, which is what an archived artifact needs.
TOKEN_TYPE_OIDC: Final[str] = "OIDC"
TOKEN_TYPE_PKI: Final[str] = "PKI"

# Verification modes — see verify_cs_token for the full semantics.
MODE_LIVE: Final[str] = "live"
MODE_ARCHIVAL: Final[str] = "archival"

# Vendored Confidential Space root, pinned by digest. Replacing the file
# without updating this constant makes verification fail closed.
_DEFAULT_ROOT_PATH: Final[Path] = Path(__file__).with_name("confidential_space_root.pem")
CS_ROOT_SHA256: Final[str] = "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39"
# Confirm exact hwmodel strings against the current GCP "Attestation token
# claims" documentation before locking these down in production.
DEFAULT_HWMODEL_ALLOWLIST: Final[frozenset[str]] = frozenset({"GCP_AMD_SEV", "GCP_INTEL_TDX"})

DEFAULT_CLAIM_TTL_S: Final[int] = 600  # on-chain submission must land within 10 min
DEFAULT_LEEWAY_S: Final[int] = 60

# EIP-712 — MUST match NeurolixAttestationVerifier exactly.
EIP712_DOMAIN_NAME: Final[str] = "NeurolixAttestationVerifier"
EIP712_DOMAIN_VERSION: Final[str] = "1"
ATTESTATION_CLAIM_TYPE: Final[str] = (
    "AttestationClaim(bytes32 sessionId,bytes32 imageDigest,bytes32 modelDigest,"
    "bytes32 inputCommitment,bytes32 outputCommitment,bytes32 bindingNonce,uint256 deadline)"
)

_log = logging.getLogger("neurolix.attestor")


class AttestorError(Exception):
    """Raised on any verification or signing failure. Fail-closed."""


# --------------------------------------------------------------------------- #
# JWKS / token verification
# --------------------------------------------------------------------------- #

def _fetch_jwks_uri(discovery_url: str = CS_DISCOVERY_URL, timeout: float = 10.0) -> str:
    try:
        with urllib.request.urlopen(discovery_url, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        uri = doc["jwks_uri"]
        if not isinstance(uri, str) or not uri.startswith("https://"):
            raise AttestorError("invalid jwks_uri in OIDC discovery document")
        return uri
    except AttestorError:
        raise
    except Exception as exc:
        raise AttestorError("failed to fetch OIDC discovery document") from exc


def _load_pinned_root(root_pem_path: str | Path | None) -> x509.Certificate:
    """Load the vendored Confidential Space root and check it against the pin."""
    path = Path(root_pem_path) if root_pem_path else _DEFAULT_ROOT_PATH
    try:
        root = x509.load_pem_x509_certificate(path.read_bytes())
    except Exception as exc:
        raise AttestorError(f"cannot load the pinned root certificate at {path}") from exc
    digest = hashlib.sha256(root.public_bytes(serialization.Encoding.DER)).hexdigest()
    if digest != CS_ROOT_SHA256:
        raise AttestorError("pinned root certificate does not match CS_ROOT_SHA256")
    return root


def _token_chain(token: str) -> list[x509.Certificate] | None:
    """Return the x5c chain from the JWT header, or None for an OIDC token."""
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise AttestorError("malformed attestation token header") from exc
    x5c = header.get("x5c")
    if not x5c:
        return None
    if not isinstance(x5c, list) or len(x5c) < 2:
        raise AttestorError("x5c chain is malformed or too short")
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(c)) for c in x5c]
    except Exception as exc:
        raise AttestorError("x5c chain contains an unparseable certificate") from exc


def _signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
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


def _verify_pki_chain(
    chain: list[x509.Certificate],
    *,
    at_time: datetime,
    root_pem_path: str | Path | None,
) -> x509.Certificate:
    """Validate leaf <- ... <- root against the pinned root and return the leaf.

    Every certificate's validity window is checked at `at_time`, not at `now`.
    Confidential Space leaf certificates live about two months, so an archived
    bundle checked against the current clock would fail for the wrong reason —
    an expired leaf, not an invalid proof.
    """
    pinned = _load_pinned_root(root_pem_path)
    root = chain[-1]
    if root.fingerprint(hashes.SHA256()) != pinned.fingerprint(hashes.SHA256()):
        raise AttestorError("x5c chain does not terminate at the pinned root")

    for cert in chain:
        if not (cert.not_valid_before_utc <= at_time <= cert.not_valid_after_utc):
            subject = cert.subject.rfc4514_string().split(",")[0]
            raise AttestorError(f"certificate outside its validity window at the checked instant: {subject}")

    for child, parent in zip(chain, chain[1:]):
        if not _signed_by(child, parent):
            raise AttestorError("x5c chain is not correctly signed")
    if not _signed_by(root, root):
        raise AttestorError("root certificate is not self-signed")

    return chain[0]


def verify_cs_token(
    token: str,
    *,
    expected_audience: str,
    hwmodel_allowlist: Iterable[str] = DEFAULT_HWMODEL_ALLOWLIST,
    leeway_s: int = DEFAULT_LEEWAY_S,
    jwks_uri: str | None = None,
    require_token_type: str | None = None,
    mode: str = MODE_LIVE,
    root_pem_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify a Confidential Space attestation token and return its claims.

    The token type is detected from the header: a token carrying an `x5c` chain
    is PKI, otherwise it is OIDC. Pass `require_token_type` to pin the
    expectation and fail closed on a downgrade — auto-detection alone would let
    a caller expecting an offline-verifiable PKI token silently accept an OIDC
    one whose verifiability depends on a key Google rotates.

    `mode` selects the temporal policy:
      MODE_LIVE     enforce `exp`; validate the chain at `now`. The only mode
                    acceptable for an authorisation decision.
      MODE_ARCHIVAL do not enforce `exp`; validate the chain at the token's
                    `iat`. For a published artifact, where the question is
                    whether the token was validly issued, not whether it is
                    still current.

    MODE_ARCHIVAL must never gate an on-chain submission — see `attest`.
    """
    if mode not in (MODE_LIVE, MODE_ARCHIVAL):
        raise AttestorError(f"unknown verification mode: {mode!r}")
    if require_token_type is not None and require_token_type not in (TOKEN_TYPE_OIDC, TOKEN_TYPE_PKI):
        raise AttestorError(f"unknown token type requirement: {require_token_type!r}")

    chain = _token_chain(token)
    detected = TOKEN_TYPE_PKI if chain else TOKEN_TYPE_OIDC
    if require_token_type is not None and detected != require_token_type:
        raise AttestorError(f"expected a {require_token_type} token, got {detected}")

    if chain is not None:
        at_time = datetime.now(timezone.utc)
        if mode == MODE_ARCHIVAL:
            # `iat` is read unverified ONLY to choose the instant at which the
            # chain is checked. It grants no trust: the signature is verified
            # immediately below against a chain that must terminate at the
            # pinned root, so a forged `iat` cannot widen the trusted set.
            try:
                unverified = jwt.decode(token, options={"verify_signature": False})
                at_time = datetime.fromtimestamp(int(unverified["iat"]), tz=timezone.utc)
            except Exception as exc:
                raise AttestorError("token has no usable iat for archival verification") from exc
        leaf = _verify_pki_chain(chain, at_time=at_time, root_pem_path=root_pem_path)
        key = leaf.public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            raise AttestorError("leaf certificate does not carry an RSA public key")
        signing_key: Any = key
    else:
        if mode == MODE_ARCHIVAL:
            _log.warning(
                "archival verification of an OIDC token: it will stop verifying "
                "once Google rotates the signing key. Prefer a PKI token."
            )
        try:
            uri = jwks_uri or _fetch_jwks_uri()
            signing_key = jwt.PyJWKClient(uri).get_signing_key_from_jwt(token).key
        except AttestorError:
            raise
        except Exception as exc:
            raise AttestorError("could not resolve the OIDC signing key") from exc

    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=ALLOWED_ALGS,
            audience=expected_audience,
            issuer=CS_ISSUER,
            leeway=leeway_s,
            options={
                "require": ["exp", "iat", "aud", "iss"],
                "verify_exp": mode == MODE_LIVE,
            },
        )
    except AttestorError:
        raise
    except jwt.ExpiredSignatureError as exc:
        # Expiry and forgery previously produced the same message. An operator
        # debugging a live rejection must be able to tell "this proof is old"
        # from "this proof is fake" — they call for opposite responses.
        raise AttestorError("attestation token has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AttestorError("attestation token is not yet valid (nbf is in the future)") from exc
    except jwt.InvalidSignatureError as exc:
        raise AttestorError("attestation token signature is invalid") from exc
    except jwt.InvalidAudienceError as exc:
        raise AttestorError("attestation token audience does not match the expected relying party") from exc
    except jwt.InvalidIssuerError as exc:
        raise AttestorError("attestation token issuer is not Confidential Space") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise AttestorError(f"attestation token is missing a required claim: {exc.claim}") from exc
    except Exception as exc:  # anything else stays deliberately opaque
        raise AttestorError("attestation token verification failed") from exc

    _check_cs_claims(claims, hwmodel_allowlist=hwmodel_allowlist)
    _log.info("token verified (type=%s, mode=%s)", detected, mode)
    return claims


def _check_cs_claims(claims: dict[str, Any], *, hwmodel_allowlist: Iterable[str]) -> None:
    dbgstat = claims.get("dbgstat")
    if dbgstat != REQUIRED_DBGSTAT:
        raise AttestorError(f"debug status not production-safe: {dbgstat!r}")

    swname = claims.get("swname")
    if swname != REQUIRED_SWNAME:
        raise AttestorError(f"unexpected swname: {swname!r}")

    hwmodel = claims.get("hwmodel")
    if hwmodel not in set(hwmodel_allowlist):
        raise AttestorError(f"hwmodel not allowlisted: {hwmodel!r}")

    # Presence check; value validated by the caller against the image allowlist.
    _ = extract_image_digest(claims)


def extract_image_digest(claims: dict[str, Any]) -> bytes:
    """Return submods.container.image_digest as 32 raw bytes.
    The claim is of the form 'sha256:<64-hex>'; the on-chain `imageDigest`
    (bytes32) is those 32 bytes."""
    try:
        raw = claims["submods"]["container"]["image_digest"]
    except (KeyError, TypeError) as exc:
        raise AttestorError("token missing submods.container.image_digest") from exc
    if not isinstance(raw, str) or not raw.startswith("sha256:"):
        raise AttestorError("image_digest is not a sha256: reference")
    hexpart = raw.split(":", 1)[1]
    if len(hexpart) != 64:
        raise AttestorError("image_digest sha256 hex must be 64 chars")
    return bytes.fromhex(hexpart)


def _eat_nonce_value(claims: dict[str, Any]) -> str:
    """eat_nonce may be a single string or a one-element list. Return it
    lowercased; reject ambiguous multi-nonce tokens."""
    val = claims.get("eat_nonce")
    if isinstance(val, list):
        if len(val) != 1:
            raise AttestorError("expected exactly one eat_nonce")
        val = val[0]
    if not isinstance(val, str):
        raise AttestorError("eat_nonce missing or malformed")
    return val.lower().removeprefix("0x")


# --------------------------------------------------------------------------- #
# Bundle parsing + nonce binding
# --------------------------------------------------------------------------- #

def _b32(hexstr: str, name: str) -> bytes:
    s = hexstr[2:] if hexstr.startswith(("0x", "0X")) else hexstr
    raw = bytes.fromhex(s)
    if len(raw) != 32:
        raise AttestorError(f"{name} must be a 32-byte hex value")
    return raw


def _u64(value: Any, name: str) -> int:
    """v1.18. Reads a uint64 field, failing closed on anything that is not one.

    Deliberately strict: a bundle missing consumed_sec is a v1-scheme artifact,
    and the protocol is v2-only. There is no legacy path — a KeyError here means
    the bundle predates metered settlement and must be regenerated, not coerced.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise AttestorError(f"{name} must be an integer")
    if not (0 <= value < 2**64):
        raise AttestorError(f"{name} must fit in uint64")
    return value


@dataclass(frozen=True)
class VerifiedClaim:
    session_id: bytes
    image_digest: bytes
    model_digest: bytes
    input_commitment: bytes
    output_commitment: bytes
    binding_nonce: bytes
    deadline: int
    consumed_sec: int  # v1.18: billable enclave duration, bound into the nonce


def verify_bundle(
    bundle: dict[str, Any],
    *,
    expected_audience: str,
    image_digest_allowlist: Iterable[bytes] | None,
    hwmodel_allowlist: Iterable[str] = DEFAULT_HWMODEL_ALLOWLIST,
    claim_ttl_s: int = DEFAULT_CLAIM_TTL_S,
    leeway_s: int = DEFAULT_LEEWAY_S,
    jwks_uri: str | None = None,
    require_token_type: str | None = None,
    mode: str = MODE_LIVE,
    root_pem_path: str | Path | None = None,
    now: int | None = None,
) -> VerifiedClaim:
    """Verify the enclave bundle and the embedded token, then return the fields
    to be signed. Raises AttestorError on any inconsistency."""
    session_id = _b32(bundle["session_id"], "session_id")
    model_digest = _b32(bundle["model_digest"], "model_digest")
    input_commitment = _b32(bundle["input_commitment"], "input_commitment")
    output_commitment = _b32(bundle["output_commitment"], "output_commitment")
    bundle_nonce = _b32(bundle["binding_nonce"], "binding_nonce")
    consumed_sec = _u64(bundle.get("consumed_sec"), "consumed_sec")
    token = bundle["attestation_token"]

    # (1) Recompute the binding nonce from the bundle's own fields (same scheme
    #     as the enclave and the contract). The bundle cannot lie about its nonce.
    #     v1.18: consumed_sec is part of the preimage, so the billed duration is
    #     covered by the Google signature over eat_nonce just like the commitments.
    #     A bundle without it fails at _u64 above — intentionally, since the
    #     protocol is v2-only and pre-v2 bundles are dev artifacts to regenerate.
    recomputed = compute_binding_nonce(
        session_id, model_digest, input_commitment, output_commitment, consumed_sec
    )
    if recomputed != bundle_nonce:
        raise AttestorError("bundle binding_nonce does not match its own fields")

    # (2) Verify the Google-signed token (sig/iss/aud/exp + CS claims).
    claims = verify_cs_token(
        token,
        expected_audience=expected_audience,
        hwmodel_allowlist=hwmodel_allowlist,
        leeway_s=leeway_s,
        jwks_uri=jwks_uri,
        require_token_type=require_token_type,
        mode=mode,
        root_pem_path=root_pem_path,
    )

    # (3) The token's eat_nonce MUST equal the recomputed binding nonce. This is
    #     what cryptographically ties the TEE attestation to THIS computation.
    if _eat_nonce_value(claims) != recomputed.hex():
        raise AttestorError("eat_nonce does not match the recomputed binding nonce")

    # (4) image_digest comes from the signed token, not the bundle.
    image_digest = extract_image_digest(claims)
    if image_digest_allowlist is not None and image_digest not in {bytes(d) for d in image_digest_allowlist}:
        raise AttestorError(f"image_digest not allowlisted: sha256:{image_digest.hex()}")

    _now = int(time.time()) if now is None else now
    deadline = _now + int(claim_ttl_s)

    _log.info(
        "bundle verified: session=0x%s image=sha256:%s nonce=0x%s",
        session_id.hex(), image_digest.hex(), recomputed.hex(),
    )
    return VerifiedClaim(
        session_id=session_id,
        image_digest=image_digest,
        model_digest=model_digest,
        input_commitment=input_commitment,
        output_commitment=output_commitment,
        binding_nonce=recomputed,
        deadline=deadline,
        consumed_sec=consumed_sec,
    )


# --------------------------------------------------------------------------- #
# EIP-712 signing
# --------------------------------------------------------------------------- #

def _typed_data(chain_id: int, verifier_address: str, c: VerifiedClaim) -> dict[str, Any]:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "AttestationClaim": [
                {"name": "sessionId", "type": "bytes32"},
                {"name": "imageDigest", "type": "bytes32"},
                {"name": "modelDigest", "type": "bytes32"},
                {"name": "inputCommitment", "type": "bytes32"},
                {"name": "outputCommitment", "type": "bytes32"},
                {"name": "bindingNonce", "type": "bytes32"},
                {"name": "deadline", "type": "uint256"},
                {"name": "consumedSec", "type": "uint64"},
            ],
        },
        "primaryType": "AttestationClaim",
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": verifier_address,
        },
        "message": {
            "sessionId": c.session_id,
            "imageDigest": c.image_digest,
            "modelDigest": c.model_digest,
            "inputCommitment": c.input_commitment,
            "outputCommitment": c.output_commitment,
            "bindingNonce": c.binding_nonce,
            "deadline": c.deadline,
            "consumedSec": c.consumed_sec,
        },
    }


def sign_claim(
    private_key: str,
    *,
    chain_id: int,
    verifier_address: str,
    claim: VerifiedClaim,
) -> dict[str, Any]:
    """Sign the AttestationClaim with the attestor key. In production, replace
    Account.sign_message with an HSM/KMS signing call over the same digest."""
    typed = _typed_data(chain_id, verifier_address, claim)
    signable = encode_typed_data(full_message=typed)
    signed = Account.sign_message(signable, private_key=private_key)
    return {
        "claim": {
            "sessionId": "0x" + claim.session_id.hex(),
            "imageDigest": "0x" + claim.image_digest.hex(),
            "modelDigest": "0x" + claim.model_digest.hex(),
            "inputCommitment": "0x" + claim.input_commitment.hex(),
            "outputCommitment": "0x" + claim.output_commitment.hex(),
            "bindingNonce": "0x" + claim.binding_nonce.hex(),
            "deadline": claim.deadline,
            "consumedSec": claim.consumed_sec,
        },
        "signature": "0x" + signed.signature.hex(),
        "attestor": Account.from_key(private_key).address,
        "digest": "0x" + signable_digest(signable).hex(),
    }


def signable_digest(signable) -> bytes:
    """The EIP-712 digest = keccak(0x19 0x01 || domainSeparator || structHash).
    Mirrors NeurolixAttestationVerifier._hashTypedDataV4 + ECDSA.recover input."""
    return keccak(b"\x19" + signable.version + signable.header + signable.body)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def attest(
    bundle_json: str,
    *,
    private_key: str,
    chain_id: int,
    verifier_address: str,
    expected_audience: str | None = None,
    image_digest_allowlist: Iterable[bytes] | None = None,
    hwmodel_allowlist: Iterable[str] = DEFAULT_HWMODEL_ALLOWLIST,
    claim_ttl_s: int = DEFAULT_CLAIM_TTL_S,
    leeway_s: int = DEFAULT_LEEWAY_S,
    jwks_uri: str | None = None,
    require_token_type: str | None = None,
    root_pem_path: str | Path | None = None,
    mode: str = MODE_LIVE,
) -> dict[str, Any]:
    """Verify an enclave bundle and return a signed, submit-ready claim.
    `expected_audience` defaults to the protocol audience the enclave derives
    from (chain_id, verifier_address).

    HARD CONSTRAINT: archival verification can never produce a signed claim.
    An archived proof has an expired token by construction; treating it as an
    authorisation would turn every published bundle into a free replay against
    the on-chain verifier.
    """
    if mode != MODE_LIVE:
        raise AttestorError(
            "attest() refuses non-live verification: an archived proof must never "
            "be signed for on-chain submission"
        )
    bundle = json.loads(bundle_json)
    derived = protocol_audience(chain_id, verifier_address)
    if expected_audience is not None and expected_audience != derived:
        # The audience names the relying party the enclave minted the token for.
        # verifyingContract names the contract that will check the signature.
        # Letting them diverge defeats check (3): a token addressed to relying
        # party A would authorise a claim submitted to verifier B.
        raise AttestorError(
            "expected_audience does not match the audience derived from "
            "(chain_id, verifier_address); refusing to decouple the relying party "
            "from the signing domain"
        )
    audience = derived
    claim = verify_bundle(
        bundle,
        expected_audience=audience,
        image_digest_allowlist=image_digest_allowlist,
        hwmodel_allowlist=hwmodel_allowlist,
        claim_ttl_s=claim_ttl_s,
        leeway_s=leeway_s,
        jwks_uri=jwks_uri,
        require_token_type=require_token_type,
        mode=MODE_LIVE,
        root_pem_path=root_pem_path,
    )
    return sign_claim(private_key, chain_id=chain_id, verifier_address=verifier_address, claim=claim)


if __name__ == "__main__":  # pragma: no cover
    import os
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # DEV ONLY. In production the key is in an HSM/KMS and never touches the host.
    pk = os.environ["NEUROLIX_ATTESTOR_PRIVATE_KEY"]
    chain_id = int(os.environ.get("NEUROLIX_CHAIN_ID", "8453"))
    verifier = os.environ["NEUROLIX_VERIFIER_ADDRESS"]

    bundle_json = sys.stdin.read()
    signed = attest(bundle_json, private_key=pk, chain_id=chain_id, verifier_address=verifier)
    print(json.dumps(signed, indent=2))

# Dependencies are declared in requirements-attestor.txt — single source.
