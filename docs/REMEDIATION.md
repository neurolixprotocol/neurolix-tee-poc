# Remediation Report — Neurolix TEE PoC

**Status:** all findings that block a public proof are closed. Two are
deliberately out of scope and declared as such below.
**Audited artifact:** the v1 PoC, preserved at tag [`v1-poc`](https://github.com/neurolixprotocol/neurolix-tee-poc/tree/v1-poc) (`neurolix_inference.py`, `neurolix_llm.py`).
**Remediated artifact:** the v2 PoC in this repository. The bundle published for
verification is `attestations/bundle-pki-v4.json`, image digest
`sha256:f59c6434b5ab1760f03a901d1579ceea649962b49e64f93d97a0305c7e6d2baf`. The
run anchored on Base Sepolia used
`sha256:a757c3312535db1a2cf76d36047fc7867bd0e1fcd9b81e6e5522b0764a1ac6f2` —
same source, rebuilt, hence a different digest.

This document exists because publishing an audit without its remediation is
half a story, and publishing a remediation without its audit is marketing.
Both are here. Read `docs/neurolix_tee_poc_security_audit.md` first.

---

## What the v1 audit actually found

The single most important finding was **C2**, and it is worth stating precisely
because it is easy to get wrong in both directions.

The v1 PoC **did** run inside a genuine Confidential Space enclave, and it
**did** obtain a real Google-signed attestation token. That part was never
fake. The defect was that the token and the computation were two unrelated
artifacts: the commitment was computed as
`sha256(prompt + response + "AMD-SEV-NEUROLIX")`, entirely independently of the
token. Nothing prevented that token from being presented alongside a different
output.

So the correct characterisation of the v1 → v2 change is not
*fake attestation → real attestation*. It is
**unbound attestation → bound attestation**.

---

## Findings and disposition

| ID | Finding | Status | Where to verify |
|----|---------|--------|-----------------|
| **C1** | Payload "encryption" was base64 encoding | **Closed** | `inference.py::decrypt_payload` — AES-256-GCM with authenticated decryption, 12-byte nonce, schema bound as AAD. Key material arrives through a `KeyProvider` interface |
| **C2** | Output commitment decoupled from the attestation token | **Closed** | `attestation.py::compute_binding_nonce` derives a nonce over `session_id ‖ model_digest ‖ input_commitment ‖ output_commitment`; that nonce is submitted as `eat_nonce` and appears inside the Google-signed token. Since 30 July 2026 the same binding is recomputed on chain — see "the relay" below |
| **C3** | Sensitive plaintext written to stdout and logs | **Closed** | `inference.py` logs record counts only. The bundle carries hashes and the token, never payload contents |
| **C4** | Model fetched from the network at runtime | **Closed** | `build_model.py` trains at image-build time; `Dockerfile` bakes `model.joblib` into the measured image; `inference.py::load_model` verifies its SHA-256 before loading and fails closed on mismatch |
| **C5** | Report asserted claims it could not support | **Closed** | Every claim in `README.md` maps to a field inside the signed token. Claims that cannot be supported are listed under "Out of scope" below rather than omitted |
| **H1** | Output not reproducible, so the commitment was meaningless | **Closed** | No training at runtime; `PYTHONHASHSEED=0` and all BLAS thread counts pinned to 1 in the `Dockerfile`; scores serialised at fixed precision; results sorted by patient id. Demonstrated empirically — see below |
| **H2** | No session binding, replay possible | **Closed** | `session_id` enters the nonce preimage; the token `audience` is scoped to a single chain and verifier address, preventing cross-relying-party replay |
| **H3** | No input validation — malformed input could crash the enclave | **Closed** | `inference.py::validate_records` enforces schema, type, finiteness, physiological range, duplicate ids and a record cap. `_load_envelope` applies a hard size cap **before** reading the file, because Confidential Space runs with swap disabled |
| **H4** | Raw tracebacks could reach the logs | **Closed** | The entrypoint catches `InferenceError` and `AttestationError` and logs their sanitised messages; any other exception logs its class name only. Tracebacks never reach Cloud Logging |
| **M1** | Dependencies not pinned | **Partial** | Exact `==` pins in `requirements-tee.txt`. Hash-locking (`pip --require-hashes`) is not yet applied |
| **M4** | Model trained on the data it later scored | **Closed** | `build_model.py` trains on a separate synthetic set at build time; the runtime only scores |
| **M5** | Concatenation ambiguity in commitment construction | **Closed** | `attestation.py::_tagged_hash` uses a domain separation tag plus an 8-byte big-endian length prefix per part. The binding nonce uses a fixed-width 160-byte preimage, reproducible by the Solidity `sha256` precompile |

---

## Determinism, demonstrated rather than asserted

H1 is the finding most often claimed and least often shown. Four independent
runs, on four separate VMs, at different times across three days, using three
different container images and both Confidential Space image families:

| Run | Image | `input_commitment` | `output_commitment` |
|-----|-------|--------------------|---------------------|
| debug v3 | `sha256:227eb380…` | `0x39ba7add…` | `0xae9aaaee…` |
| production v3 | `sha256:227eb380…` | `0x39ba7add…` | `0xae9aaaee…` |
| production v4 (PKI) | `sha256:f59c6434…` | `0x39ba7add…` | `0xae9aaaee…` |
| production v5 (relayed) | `sha256:a757c331…` | `0x39ba7add…` | `0xae9aaaee…` |

The `binding_nonce` differs between them because `model_digest` changes with
every build — see the reproducibility limitation below.

---

## Out of scope, and why

These are not oversights. They are decisions, and the proof is weaker for them.

### C1 remains architecturally incomplete: key release is not attestation-gated

The data encryption key is passed to the enclave as a VM metadata variable
(`tee-env-NEUROLIX_DEK_demo`). In a production system it must instead be
released by a KMS whose policy is conditioned on the enclave's attestation —
specifically on the image digest, through a Workload Identity Pool provider.

**This has a consequence that must be understood before reusing the pattern.**
Confidential Space attests the container's environment, so every `tee-env-`
variable appears *in cleartext inside the signed, publishable token*. The DEK
for this PoC is therefore visible to anyone holding the bundle. That is
acceptable here — and useful, since it lets any reader decrypt `payload.json`
and recompute the commitments independently — precisely because the records are
synthetic. With real data this pattern would be a disclosure, not a feature.

### The data is synthetic

No clinical record was involved at any stage. `make_payload.py` generates
patients from a seeded RNG; `build_model.py` trains on a separate synthetic
set. The model is a RandomForest fitted to a monotone function of glucose, BMI
and age plus noise. It is a stand-in for a governed clinical model, not one.

### The build is not byte-reproducible

`build_model.py` writes a `created_utc` timestamp into the serialised model, so
every build produces a different `model.joblib` and therefore a different
`model_digest`. A third party rebuilding from this source will not reproduce
our image digest.

This does not weaken the proof: the runtime verifies the model against the
digest baked into the *same measured image*, and the attestation covers that
image. But no claim of reproducible builds is made, and none should be read
into this repository.

### The model digest check is not an anti-tampering control

`load_model` compares `model.joblib` against `model.sha256` — two files sitting
side by side. An attacker able to replace one can replace the other. That check
guards against corruption. The actual guarantee comes from both files being
inside the image whose digest Google signed.

### The session id is operator-chosen

`session_id` is supplied by whoever launches the VM. In the full protocol it
would be the on-chain session under which the job is paid. Here it is an
arbitrary 32-byte value, so it provides domain separation between runs but no
independent freshness guarantee.

### Nothing is anchored on Base Mainnet

`NeurolixAttestation.sol` on Base Mainnet
(`0xDcCCda8662996b479bE5C5d44115a03a43a92F1B`) still holds zero transactions,
and this PoC does not write to it. That contract is a permissionless registry:
it accepts self-declared strings and verifies nothing, so anchoring into it
would reintroduce C5 one layer down.

### The relay: what was walked, and what was stubbed to walk it

The chain from enclave to contract is no longer merely built. On 30 July 2026 a
claim produced by `bridge/attestor.py` was submitted to
`NeurolixAttestationVerifier` on **Base Sepolia**
(`0xBD5f47876Dc7DD20ECE7f09A65Bf4E65dfe289CF`), in transaction
`0xa32529d0f442b68fa0074eec4d660f3d13de1aa11bbdf81c71e7ec43b0d92412`.

The contract recomputed the binding nonce from the claim's own fields with the
`sha256` precompile, recovered the signer from the EIP-712 signature, checked
that signer against `ATTESTOR_ROLE`, matched the image digest against its
allowlist, and consumed the nonce against replay. None of that was stubbed.

Two things were.

**The compute session is mocked.** The verifier requires an `IComputeSession`
that confirms the session is active. `ComputeSession.sol` declares itself
`SCAFFOLD — NOT PRODUCTION, NOT AUDITED`, and deploying it to satisfy a
constructor argument would mean standing behind code that does not yet stand
up. A minimal `MockComputeSession` answers the two view functions the verifier
calls and does nothing else: it verifies nothing, tracks no nonces, emits no
verification events. The verifier's `session` pointer is mutable, so the real
contract replaces the mock without redeployment.

**It is testnet.** A mocked session behind a contract that looks like it
verifies things has no business on a chain where its events could be read as
production claims.

### The chain trusts the attestor key, not Google

This is the limitation the relay introduces, and it is a reduction of trust
rather than its removal.

The Google-signed token is verified *off chain*, by `bridge/attestor.py`, which
then signs an EIP-712 claim with `NEUROLIX_ATTESTOR_PRIVATE_KEY`. The contract
never sees the JWT. It verifies that a key holding `ATTESTOR_ROLE` vouched for
a computation, and that the claim is internally consistent and unreplayed.

An on-chain attestation is therefore exactly as trustworthy as that key.
Whoever holds it can anchor an arbitrary claim and the contract will accept it.
Verifying the Google PKI chain on chain would remove the assumption; parsing
X.509 and checking RSA signatures inside the EVM is why it was not done. Today
the key sits in an environment variable — the same class of shortcut as C1, and
it carries the same warning.

---

## The one-hour token lifetime

Attestation tokens carry roughly a one-hour TTL. A standard JWT library checks
`exp` by default and will reject an archived bundle as expired.

That is the library asking the wrong question. For a live authorisation
decision — releasing a key, admitting a result on chain — `exp` matters and
must be enforced. For an archived proof, the question is whether the token was
validly issued and whether its signature still verifies. Both remain answerable
indefinitely.

The verifier therefore needs two modes: a live mode that enforces `exp`, and an
archival mode that verifies signature, chain and `iat` but not `exp`. Disabling
the check globally would be wrong.

---

## Why the published artifact uses a PKI token

The first production bundle (`bundle-prod-v3.json`) requested an OIDC token,
whose signature is verified against a JWKS key that Google rotates on a regular
schedule. Once that key rotates out, the archived artifact becomes unverifiable
— not because it is false, but because the verification key no longer exists.

`bundle-pki-v4.json` requests a PKI token instead. It is self-contained: the
JWT header carries the full `x5c` chain (leaf, intermediate, root), and the
root is validated against the certificate published at Google's well-known PKI
endpoint. That root is valid until **16 January 2034**.

All three bundles are included in `attestations/`. The PKI one is the artifact
intended for verification.
