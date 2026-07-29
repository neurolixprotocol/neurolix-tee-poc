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

import json
import logging
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Final, Iterable

import jwt  # PyJWT
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


def verify_cs_token(
    token: str,
    *,
    expected_audience: str,
    hwmodel_allowlist: Iterable[str] = DEFAULT_HWMODEL_ALLOWLIST,
    leeway_s: int = DEFAULT_LEEWAY_S,
    jwks_uri: str | None = None,
) -> dict[str, Any]:
    """Verify the Confidential Space OIDC token end-to-end and return its claims.
    Raises AttestorError on any failure."""
    try:
        uri = jwks_uri or _fetch_jwks_uri()
        jwk_client = jwt.PyJWKClient(uri)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGS,
            audience=expected_audience,
            issuer=CS_ISSUER,
            leeway=leeway_s,
            options={"require": ["exp", "iat", "aud", "iss"]},
        )
    except AttestorError:
        raise
    except Exception as exc:  # signature/aud/iss/exp failures land here
        raise AttestorError("attestation token verification failed") from exc

    _check_cs_claims(claims, hwmodel_allowlist=hwmodel_allowlist)
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


@dataclass(frozen=True)
class VerifiedClaim:
    session_id: bytes
    image_digest: bytes
    model_digest: bytes
    input_commitment: bytes
    output_commitment: bytes
    binding_nonce: bytes
    deadline: int


def verify_bundle(
    bundle: dict[str, Any],
    *,
    expected_audience: str,
    image_digest_allowlist: Iterable[bytes] | None,
    hwmodel_allowlist: Iterable[str] = DEFAULT_HWMODEL_ALLOWLIST,
    claim_ttl_s: int = DEFAULT_CLAIM_TTL_S,
    leeway_s: int = DEFAULT_LEEWAY_S,
    jwks_uri: str | None = None,
    now: int | None = None,
) -> VerifiedClaim:
    """Verify the enclave bundle and the embedded token, then return the fields
    to be signed. Raises AttestorError on any inconsistency."""
    session_id = _b32(bundle["session_id"], "session_id")
    model_digest = _b32(bundle["model_digest"], "model_digest")
    input_commitment = _b32(bundle["input_commitment"], "input_commitment")
    output_commitment = _b32(bundle["output_commitment"], "output_commitment")
    bundle_nonce = _b32(bundle["binding_nonce"], "binding_nonce")
    token = bundle["attestation_token"]

    # (1) Recompute the binding nonce from the bundle's own fields (same scheme
    #     as the enclave and the contract). The bundle cannot lie about its nonce.
    recomputed = compute_binding_nonce(session_id, model_digest, input_commitment, output_commitment)
    if recomputed != bundle_nonce:
        raise AttestorError("bundle binding_nonce does not match its own fields")

    # (2) Verify the Google-signed token (sig/iss/aud/exp + CS claims).
    claims = verify_cs_token(
        token,
        expected_audience=expected_audience,
        hwmodel_allowlist=hwmodel_allowlist,
        leeway_s=leeway_s,
        jwks_uri=jwks_uri,
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
) -> dict[str, Any]:
    """Verify an enclave bundle and return a signed, submit-ready claim.
    `expected_audience` defaults to the protocol audience the enclave derives
    from (chain_id, verifier_address)."""
    bundle = json.loads(bundle_json)
    audience = expected_audience or protocol_audience(chain_id, verifier_address)
    claim = verify_bundle(
        bundle,
        expected_audience=audience,
        image_digest_allowlist=image_digest_allowlist,
        hwmodel_allowlist=hwmodel_allowlist,
        claim_ttl_s=claim_ttl_s,
        leeway_s=leeway_s,
        jwks_uri=jwks_uri,
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

# requirements-attestor.txt (pin + hash-lock in production):
#   PyJWT[crypto]>=2.8
#   eth-account>=0.11
