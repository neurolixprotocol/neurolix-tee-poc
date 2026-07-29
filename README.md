# Neurolix TEE PoC — attested confidential inference

A machine learning inference executed inside an AMD SEV enclave on Google
Confidential Space, where the attestation signed by Google covers **the
computation itself** — not merely the environment it ran in.

The proof is a 12 KB JSON file. Verifying it requires no network access, no
Google Cloud account, and no trust in this repository's authors.

---

## The claim, stated precisely

A Google-signed attestation token asserts all of the following about one
specific execution:

- it ran on AMD SEV hardware — `hwmodel: GCP_AMD_SEV`
- under Confidential Space with secure boot — `swname: CONFIDENTIAL_SPACE`,
  `secboot: true`
- with debugging disabled from boot — `dbgstat: disabled-since-boot`
- running exactly the container image
  `sha256:f59c6434b5ab1760f03a901d1579ceea649962b49e64f93d97a0305c7e6d2baf`
- and, critically, the token's `eat_nonce` claim equals a hash derived from the
  session id, the model digest, and commitments to the computation's input and
  output

That last point is the whole exercise. An attestation token proves an enclave
existed. Binding the token's nonce to the I/O commitments proves *this output
came from that enclave*. Anyone can recompute the nonce from the bundle's own
fields and check it against the signed claim.

**What this does not claim:** that the data was real, that key management was
production-grade, or that the build is reproducible. Those limits are set out
in `docs/REMEDIATION.md` and are not buried there — read it.

---

## How to verify the artifact

No dependencies beyond `cryptography`. No network.

```bash
pip install cryptography
python3 verify.py attestations/bundle-pki-v4.json
```

The verification performs five independent checks:

1. **Recompute the binding nonce.** `sha256(DST_NONCE ‖ session_id ‖
   model_digest ‖ input_commitment ‖ output_commitment)` — a fixed 160-byte
   preimage — must equal the bundle's `binding_nonce`.
2. **Check it against the signed token.** The `eat_nonce` claim inside the JWT
   must equal that recomputed value. This is the binding.
3. **Verify the JWT signature** using the public key of the leaf certificate
   carried in the token's own `x5c` header.
4. **Walk the certificate chain:** leaf signed by intermediate, intermediate
   signed by root, root self-signed.
5. **Anchor the root.** Compare its SHA-256 fingerprint against the root
   certificate published by Google at
   `https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root`
   — the only step that touches the network, and it can be done once and cached
   for years.

Expected root fingerprint:

```
148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39
```

### A note on token expiry

Attestation tokens carry a one-hour TTL, so a standard JWT library will reject
this archived bundle as expired. That is the wrong question for an archived
proof: what matters is that the token was validly issued and that its signature
still verifies. Verify `iat` and the signature; do not enforce `exp` on an
archived artifact. See `docs/REMEDIATION.md`.

---

## What runs inside the enclave

```
encrypted payload
   │  AES-256-GCM, authenticated, schema bound as AAD
   ▼
records ──► strict validation (schema, type, range, duplicates, size caps)
   │
   ▼
deterministic inference against a model baked into the measured image
   │  no training, no sampling, no clock, BLAS pinned to one thread
   ▼
canonical JSON ──► input_commitment, output_commitment
   │
   ▼
binding_nonce ──► submitted as eat_nonce to the Confidential Space launcher
   │
   ▼
Google-signed attestation token ──► bundle (hashes + token, never plaintext)
```

No plaintext leaves the enclave. The bundle carries hashes and the token only.

---

## Reproducing a run

The encrypted payload and the key that opens it are both in this repository —
deliberately, since the records are synthetic. Any reader can decrypt the
payload, run the inference, and confirm the commitments match.

```bash
# 1. Generate a fresh encrypted payload (prints a new DEK and session id)
python3 make_payload.py --records 20

# 2. Build the workload image
gcloud builds submit --tag <REGION>-docker.pkg.dev/<PROJECT>/<REPO>/tee-poc:v1 .

# 3. Launch on Confidential Space, passing only the per-run secrets
gcloud compute instances create neurolix-tee \
  --zone=<ZONE> --machine-type=n2d-standard-4 \
  --confidential-compute-type=SEV --maintenance-policy=TERMINATE \
  --shielded-secure-boot \
  --image-project=confidential-space-images \
  --image-family=confidential-space \
  --service-account=<WORKLOAD_SA> \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --metadata="^~^tee-image-reference=<IMAGE>@sha256:<DIGEST>~tee-container-log-redirect=true~tee-env-NEUROLIX_SESSION_ID=<SESSION>~tee-env-NEUROLIX_DEK_demo=<DEK>"
```

The workload service account needs three roles:
`confidentialcomputing.workloadUser` to obtain a token at all,
`logging.logWriter` for the bundle to reach Cloud Logging, and
`artifactregistry.reader` to pull the image.

Your image digest will differ from ours — the build is not byte-reproducible.
See `docs/REMEDIATION.md`.

---

## Two Confidential Space details worth knowing

Both cost real debugging time and neither is obvious.

**Environment overrides must be authorised by the image author.** The workload
operator cannot inject any variable unless the image declares it:

```dockerfile
LABEL "tee.launch_policy.allow_env_override"="NEUROLIX_SESSION_ID,NEUROLIX_DEK_demo"
```

Everything else — the verifier address, the chain id, the payload path — is
baked into the measured image as `ENV`. This is not tidiness. Those values
determine the token's `audience`; an operator able to change them could make
the enclave mint a token for a different relying party.

**Log redirection defaults to `debugonly`.** On a production image, stdout is
silently discarded unless the image declares otherwise — and stdout is how the
bundle leaves the enclave:

```dockerfile
LABEL "tee.launch_policy.log_redirect"="always"
```

---

## Layout

```
Dockerfile               two-stage build; stage 2 is the measured image
attestation.py           in-enclave: commitments, binding nonce, token request
inference.py             in-enclave: decrypt, validate, infer, emit bundle
build_model.py           build-time: trains and hashes the baked model
make_payload.py          build-time: produces the encrypted payload
requirements-tee.txt     pinned enclave dependencies
payload.json             encrypted synthetic payload (baked into the image)
bridge/attestor.py       off-chain verifier — OIDC and PKI, live and archival
attestations/            the three bundles produced during this work
docs/                    the v1 security audit and this work's remediation
```

`attestations/bundle-pki-v4.json` is the artifact to verify. The other two are
kept for provenance: `bundle-debug-v3.json` carries `dbgstat: enabled` and is
not a valid proof, and `bundle-prod-v3.json` is a valid OIDC-signed proof whose
verifiability depends on a Google key that rotates.

The Solidity verifier contract lives in the `neurolix-contracts` repository and
is deliberately not duplicated here.

---

## Status

This is a proof of concept. It demonstrates that attested, deterministic,
committed inference works end to end on commodity confidential computing
infrastructure. It is not a production confidential AI system, and the gap
between the two is documented rather than glossed over.
