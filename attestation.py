#!/usr/bin/env python3
"""
attestation.py — Neurolix Protocol

In-enclave attestation and commitment construction for Confidential Space
(AMD SEV-SNP / Intel TDX) workloads.

What this module DOES:
  - Builds domain-separated, length-safe SHA-256 commitments over the
    (already-canonicalized) input and output of a confidential computation.
  - Derives a `binding_nonce` that ties the computation to its on-chain
    session_id, the model weights digest, and the I/O commitments. This nonce
    is fixed-width and reproducible BOTH off-chain and on-chain (Solidity
    `sha256` precompile), so the on-chain verifier can recompute it.
  - Requests the REAL Confidential Space attestation token from the launcher,
    placing `binding_nonce` (hex) into the token's `eat_nonce` claim and a
    protocol-scoped `audience`. The token is Google-signed and natively
    carries the workload's container `image_digest` in its claims — so the
    image identity does NOT need to be re-asserted by us.
  - Emits an attestation BUNDLE (structured fields + the JWT) to be handed to
    the off-chain attestor / relay over a secure channel.

What this module DOES NOT do (by design — see audit C1/C3/C4):
  - It NEVER receives, logs, or prints plaintext patient data. Callers pass
    *canonical bytes* only so this module can hash them; raw bytes are hashed
    and discarded, never retained or logged.
  - It does NOT decrypt payloads, fetch models, or touch the network beyond the
    local launcher Unix socket. Key release / decryption must be gated by the
    attestation token via a Workload Identity Pool policy on `image_digest`.
  - It does NOT submit anything on-chain. The enclave holds no chain keys and
    performs no chain egress; on-chain submission is the relay/attestor's job.

Trust model note:
  The JWT is verified OFF-CHAIN by the attestor (signature against Google's
  JWKS or the Confidential Space PKI root, `iss`, `aud`, `dbgstat`,
  `image_digest` allowlist, and `eat_nonce == binding_nonce`). The attestor
  then signs an EIP-712 claim the on-chain verifier checks. The on-chain
  verifier additionally RECOMPUTES `binding_nonce` from the submitted fields
  (same SHA-256 preimage as here) — so even under the attestor trust
  assumption, the fields cannot be detached from the nonce. See
  NeurolixAttestationVerifier.sol and the audit (§6) for the full chain and the
  trust-minimization upgrade path (on-chain RS256 / zk-JWT).
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
from dataclasses import dataclass
from typing import Any, Final

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Confidential Space launcher IPC (token endpoint over a Unix domain socket).
# Confirm against the current GCP "Confidential Space" docs before deploying.
TEESERVER_SOCKET: Final[str] = "/run/container_launcher/teeserver.sock"
TOKEN_ENDPOINT_PATH: Final[str] = "/v1/token"
# Bootstrap token (no custom nonce) auto-written by the launcher; ~60 min TTL.
BOOTSTRAP_TOKEN_PATH: Final[str] = "/run/container_launcher/attestation_verifier_claims_token"

# OIDC: signature verified against a rotating JWKS public key.
# PKI : self-contained token verifiable against the Confidential Space root
#       certificate (supports offline verification). Pick per your attestor.
TOKEN_TYPE_OIDC: Final[str] = "OIDC"
TOKEN_TYPE_PKI: Final[str] = "PKI"

# eat_nonce JSON-encoded size constraint enforced by the attestation service:
# min 10 bytes, max 74 bytes. A 32-byte hash in lowercase hex = 64 chars, safe.
EAT_NONCE_MIN_LEN: Final[int] = 10
EAT_NONCE_MAX_LEN: Final[int] = 74

# Network timeout for the local socket call (fail-closed, do not hang the enclave).
TOKEN_TIMEOUT_S: Final[float] = 10.0

# v2 (2026-08-03): adds `consumed_sec` to the binding nonce preimage and to the bundle.
# A v1 bundle can no longer produce a nonce a v1.18 verifier will accept, and vice versa —
# the version string is the tripwire that makes the mismatch loud instead of silent.
BUNDLE_VERSION: Final[str] = "neurolix-attestation/v2"

# Domain-separation tags. The *byte values* below are the SHA-256 of the tag
# strings and are MIRRORED verbatim in NeurolixAttestationVerifier.sol as
# `DST_NONCE`. If you ever change the tag string, regenerate and update BOTH.
#   sha256(b"NEUROLIX/attestation/nonce/v1")
DST_NONCE: Final[bytes] = bytes.fromhex(
    "e501d736b800d00539784c76a1f5334cb8f26b0bd7319fc02d2a6c149e9ba6d2"
)
# These two are used only off-chain (input/output are never recomputed on-chain),
# so they are kept as tag strings and hashed inside `_tagged_hash`.
DST_INPUT: Final[str] = "NEUROLIX/attestation/input/v1"
DST_OUTPUT: Final[str] = "NEUROLIX/attestation/output/v1"

_HASH_LEN: Final[int] = 32

_log = logging.getLogger("neurolix.attestation")


class AttestationError(Exception):
    """Raised on any attestation/commitment failure. Messages are sanitized:
    they never include payloads, prompts, model outputs, or token contents."""


# --------------------------------------------------------------------------- #
# Hashing primitives (SHA-256 end-to-end, to match the Solidity precompile)
# --------------------------------------------------------------------------- #

def _sha256(data: bytes) -> bytes:
    import hashlib  # local import keeps the module import graph minimal

    return hashlib.sha256(data).digest()


def _require_len(value: bytes, expected: int, name: str) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) != expected:
        # No value content in the message — only the field name and the lengths.
        raise AttestationError(f"{name} must be exactly {expected} bytes")


def _tagged_hash(dst: str, *parts: bytes) -> bytes:
    """Domain-separated, length-prefixed SHA-256 over variable-length parts.

    Layout:  sha256( sha256(dst) || ( len(p) as 8-byte BE || p )* )
    The 8-byte length prefix removes concatenation ambiguity (audit M5).
    Used for input/output commitments, which are opaque 32-byte values on-chain.
    """
    h = _Sha256Streaming()
    h.update(_sha256(dst.encode("utf-8")))
    for p in parts:
        h.update(len(p).to_bytes(8, "big"))
        h.update(p)
    return h.digest()


class _Sha256Streaming:
    """Thin streaming wrapper so we never materialize a large concatenation
    of sensitive bytes in a single buffer."""

    def __init__(self) -> None:
        import hashlib

        self._h = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()


def compute_input_commitment(canonical_input: bytes) -> bytes:
    """Commit to the canonical input bytes. The bytes are hashed and dropped;
    they are never logged or retained by this module."""
    return _tagged_hash(DST_INPUT, canonical_input)


def compute_output_commitment(canonical_output: bytes) -> bytes:
    """Commit to the canonical output bytes (the inference result). The bytes
    are hashed and dropped; they are never logged or retained."""
    return _tagged_hash(DST_OUTPUT, canonical_output)


def compute_binding_nonce(
    session_id: bytes,
    model_digest: bytes,
    input_commitment: bytes,
    output_commitment: bytes,
    consumed_sec: int,
) -> bytes:
    """Fixed-width SHA-256 binding nonce, reproducible on-chain.

    Preimage (168 bytes: five fixed 32-byte fields + one 8-byte BE integer;
    order is load-bearing):
        DST_NONCE || session_id || model_digest || input_commitment
                  || output_commitment || consumed_sec(uint64 BE)

    Mirrored in Solidity as:
        sha256(abi.encodePacked(DST_NONCE, sessionId, modelDigest,
                                inputCommitment, outputCommitment, consumedSec))
    where consumedSec is uint64 — abi.encodePacked emits exactly 8 big-endian
    bytes for it, matching to_bytes(8, "big") here.

    WHY consumed_sec IS IN HERE (v2, load-bearing):
    the billed duration is what the client pays for. If it travelled beside the
    nonce instead of inside it, the off-chain attestor could sign any number it
    liked without the enclave ever having committed to it. Folding it into the
    preimage means the value is bound to the same Google-signed eat_nonce as the
    I/O commitments: altering it invalidates the token.

    HONEST LIMITATION: this proves the ENCLAVE asserted the duration, not that the
    duration is true. SEV-SNP and TDX expose no trusted clock — the host, i.e. the
    node operator, owns the time the enclave reads. The on-chain settlement
    therefore clamps this value to the elapsed time the chain itself measured
    (see ComputeSession `_billable`: min(attested, physical, plafond)). Neither
    bound is sufficient alone; each closes the attack the other opens.
    """
    _require_len(session_id, _HASH_LEN, "session_id")
    _require_len(model_digest, _HASH_LEN, "model_digest")
    _require_len(input_commitment, _HASH_LEN, "input_commitment")
    _require_len(output_commitment, _HASH_LEN, "output_commitment")
    if not isinstance(consumed_sec, int) or isinstance(consumed_sec, bool):
        raise AttestationError("consumed_sec must be an int")
    if not (0 <= consumed_sec < 2**64):
        raise AttestationError("consumed_sec must fit in uint64")
    preimage = (
        DST_NONCE
        + session_id
        + model_digest
        + input_commitment
        + output_commitment
        + consumed_sec.to_bytes(8, "big")
    )
    assert len(preimage) == 5 * _HASH_LEN + 8  # internal invariant
    return _sha256(preimage)


def protocol_audience(chain_id: int, verifier_address: str) -> str:
    """Audience binds the token to a single relying party (this verifier on this
    chain), preventing cross-RP replay. Required when custom nonces are used."""
    addr = verifier_address.lower()
    if not (addr.startswith("0x") and len(addr) == 42):
        raise AttestationError("verifier_address must be a 0x-prefixed 20-byte address")
    return f"neurolix://base/{int(chain_id)}/{addr}"


# --------------------------------------------------------------------------- #
# Confidential Space token retrieval (stdlib only — no extra enclave deps)
# --------------------------------------------------------------------------- #

class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a Unix domain socket instead of TCP."""

    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:  # noqa: D401
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
        except OSError as exc:
            sock.close()
            raise AttestationError(
                f"cannot reach launcher token socket at {self._socket_path}"
            ) from exc
        self.sock = sock


def request_attestation_token(
    *,
    audience: str,
    nonce_hex: str,
    token_type: str = TOKEN_TYPE_OIDC,
) -> str:
    """POST to http://localhost/v1/token over the launcher Unix socket and
    return the raw signed attestation token (JWT for OIDC; self-contained for
    PKI). Fails closed; never logs the token."""
    _validate_nonce(nonce_hex)
    if token_type not in (TOKEN_TYPE_OIDC, TOKEN_TYPE_PKI):
        raise AttestationError("unsupported token_type")

    body = json.dumps(
        {"audience": audience, "token_type": token_type, "nonces": [nonce_hex]},
        separators=(",", ":"),
    )
    conn = _UnixHTTPConnection(TEESERVER_SOCKET, timeout=TOKEN_TIMEOUT_S)
    try:
        conn.request(
            "POST",
            TOKEN_ENDPOINT_PATH,
            body=body,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        resp = conn.getresponse()
        raw = resp.read()
        if resp.status != 200:
            # Do not echo the response body — it may carry diagnostic context.
            raise AttestationError(f"token endpoint returned HTTP {resp.status}")
        token = raw.decode("utf-8").strip()
        if not token:
            raise AttestationError("token endpoint returned an empty token")
        _log.info(
            "attestation token obtained (type=%s, aud=%s, nonce_len=%d)",
            token_type, audience, len(nonce_hex),
        )
        return token
    except AttestationError:
        raise
    except Exception as exc:  # fail-closed, sanitized
        raise AttestationError("attestation token request failed") from exc
    finally:
        conn.close()


def read_bootstrap_token() -> str:
    """Read the launcher-provisioned bootstrap token (no custom nonce). Useful
    at startup to discover the workload's own image_digest / claims, or as a
    liveness check that the workload is genuinely in Confidential Space."""
    try:
        with open(BOOTSTRAP_TOKEN_PATH, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        if not token:
            raise AttestationError("bootstrap token file is empty")
        return token
    except AttestationError:
        raise
    except OSError as exc:
        raise AttestationError(
            "bootstrap attestation token unavailable — not running in Confidential Space?"
        ) from exc


# --------------------------------------------------------------------------- #
# Bundle assembly
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AttestationBundle:
    version: str
    session_id: bytes
    model_digest: bytes
    input_commitment: bytes
    output_commitment: bytes
    binding_nonce: bytes
    consumed_sec: int  # v2: billable enclave duration, folded into the nonce preimage
    audience: str
    attestation_token: str  # Google-signed; image_digest lives in its claims

    def to_json(self) -> str:
        """Serialize for transport to the off-chain attestor over a secure
        channel. Hex fields are 0x-prefixed; `eat_nonce` is the exact string
        placed in the token (lowercase hex, no 0x) for the attestor to compare."""
        return json.dumps(
            {
                "version": self.version,
                "session_id": "0x" + self.session_id.hex(),
                "model_digest": "0x" + self.model_digest.hex(),
                "input_commitment": "0x" + self.input_commitment.hex(),
                "output_commitment": "0x" + self.output_commitment.hex(),
                "binding_nonce": "0x" + self.binding_nonce.hex(),
                "consumed_sec": self.consumed_sec,
                "eat_nonce": self.binding_nonce.hex(),
                "audience": self.audience,
                "attestation_token": self.attestation_token,
            },
            separators=(",", ":"),
        )


def build_attestation_bundle(
    *,
    session_id: bytes,
    model_digest: bytes,
    canonical_input: bytes,
    canonical_output: bytes,
    consumed_sec: int,
    chain_id: int,
    verifier_address: str,
    token_type: str = TOKEN_TYPE_OIDC,
) -> AttestationBundle:
    """End-to-end: commit to I/O, derive the session-bound nonce, fetch the real
    attestation token, and assemble the transport bundle.

    IMPORTANT (audit H1): `canonical_output` MUST come from a DETERMINISTIC
    inference run (no sampling; pinned library versions; fixed seed/threads;
    declared hardware) or the commitment will not be reproducible/verifiable.

    `canonical_input` / `canonical_output` are hashed and discarded here; they
    are never logged. Pass them as canonical bytes (e.g. canonical_json(...)).
    """
    _require_len(session_id, _HASH_LEN, "session_id")
    _require_len(model_digest, _HASH_LEN, "model_digest")

    input_commitment = compute_input_commitment(canonical_input)
    output_commitment = compute_output_commitment(canonical_output)
    binding_nonce = compute_binding_nonce(
        session_id, model_digest, input_commitment, output_commitment, consumed_sec
    )
    audience = protocol_audience(chain_id, verifier_address)
    token = request_attestation_token(
        audience=audience, nonce_hex=binding_nonce.hex(), token_type=token_type
    )
    return AttestationBundle(
        version=BUNDLE_VERSION,
        session_id=session_id,
        model_digest=model_digest,
        input_commitment=input_commitment,
        output_commitment=output_commitment,
        binding_nonce=binding_nonce,
        consumed_sec=consumed_sec,
        audience=audience,
        attestation_token=token,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON for hashing: sorted keys, no whitespace, UTF-8.
    Use the SAME canonicalization on the verifier side that reproduces an
    output_commitment, if any party ever recomputes it."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def session_id_from_hex(value: str) -> bytes:
    """Parse a bytes32 session id (with or without 0x) into 32 raw bytes."""
    v = value[2:] if value.startswith(("0x", "0X")) else value
    raw = bytes.fromhex(v)
    _require_len(raw, _HASH_LEN, "session_id")
    return raw


def _validate_nonce(nonce_hex: str) -> None:
    _validate_nonce_len(nonce_hex)
    int(nonce_hex, 16)  # raises ValueError if not valid hex


def _validate_nonce_len(nonce_hex: str) -> None:
    # The constraint is on the JSON-encoded eat_nonce; a lowercase-hex string of
    # 64 chars is well within [10, 74]. Guard anyway to fail fast.
    if not (EAT_NONCE_MIN_LEN <= len(nonce_hex) <= EAT_NONCE_MAX_LEN):
        raise AttestationError(
            f"eat_nonce length {len(nonce_hex)} out of bounds [{EAT_NONCE_MIN_LEN},{EAT_NONCE_MAX_LEN}]"
        )


# --------------------------------------------------------------------------- #
# Usage sketch (NOT executed on import). Shows how the deterministic inference
# module would call into this one. No plaintext is ever printed.
# --------------------------------------------------------------------------- #
if __name__ == "__main__":  # pragma: no cover
    import os

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # session_id: the on-chain NeurolixGateway session this job is paid under.
    sid = session_id_from_hex(os.environ["NEUROLIX_SESSION_ID"])

    # model_digest: sha256 of the BAKED-IN safetensors weights (audit C4),
    # ideally read from a digest file produced at image-build time.
    with open(os.environ["NEUROLIX_MODEL_DIGEST_FILE"], "r", encoding="utf-8") as fh:
        model_digest = bytes.fromhex(fh.read().strip())

    # --- The deterministic confidential computation happens elsewhere. ---
    # decrypted_input = <decrypt with KMS key released only on valid attestation>
    # result          = <deterministic inference: do_sample=False, pinned deps>
    # Here we only hold their CANONICAL BYTES to commit to them:
    canonical_input = canonical_json({"_schema": "neurolix.input.v1"})    # placeholder
    canonical_output = canonical_json({"_schema": "neurolix.output.v1"})  # placeholder

    bundle = build_attestation_bundle(
        session_id=sid,
        model_digest=model_digest,
        canonical_input=canonical_input,
        canonical_output=canonical_output,
        chain_id=int(os.environ.get("NEUROLIX_CHAIN_ID", "8453")),  # Base mainnet
        verifier_address=os.environ["NEUROLIX_VERIFIER_ADDRESS"],
    )

    # Hand the bundle to the off-chain attestor over a SECURE channel.
    # Logged here is only the bundle metadata (hashes + JWT) — never plaintext.
    _log.info("attestation bundle ready for session %s", "0x" + sid.hex())
    # e.g. secure_channel.send(bundle.to_json())
