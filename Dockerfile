# syntax=docker/dockerfile:1.7
#
# Neurolix TEE PoC — workload image for Google Confidential Space (AMD SEV-SNP)
# Medical inference path. No torch, no transformers, no network egress.
#
# Build (from Cloud Shell, in the directory containing these files):
#   gcloud builds submit --tag europe-west4-docker.pkg.dev/$PROJECT/neurolix/tee-poc:v1 .
#
# TODO before public release: pin the base image by digest
#   (FROM python:3.12-slim@sha256:...) and add --require-hashes (audit M1).

# ─────────────────────────────────────────────────────────────────────────────
# STAGE 1 — build-time, OUTSIDE the enclave: train and serialize the model.
# Closes C4 (no runtime download) and M4 (training set != inference input).
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements-tee.txt .
RUN pip install --no-cache-dir -r requirements-tee.txt

COPY build_model.py .
# Produces model.joblib + model.sha256. The digest becomes the model_digest
# that feeds into the binding_nonce and is verified at runtime before loading.
RUN python build_model.py model.joblib model.sha256


# ─────────────────────────────────────────────────────────────────────────────
# STAGE 2 — runtime. THIS is the measured image: its digest ends up in the
# attestation token claims. Everything baked here is attested.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Determinism (audit H1): fixed hash seed and single-threaded BLAS.
# Multiple BLAS threads produce different floats across runs, breaking the
# commitment reproducibility guarantee.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1

# Protocol parameters baked into the MEASURED image. These are deliberately NOT
# operator-overridable: the verifier address and chain id determine the
# attestation token's audience, so an operator able to change them could make
# the enclave mint a token for a different relying party.
ENV NEUROLIX_VERIFIER_ADDRESS=0xBD5f47876Dc7DD20ECE7f09A65Bf4E65dfe289CF \
    NEUROLIX_CHAIN_ID=84532 \
    NEUROLIX_PAYLOAD_FILE=/app/payload.json

ENV NEUROLIX_TOKEN_TYPE=PKI

# Confidential Space launch policies — set by the workload AUTHOR at build time.
# Only the per-run secrets may be supplied by the operator; everything that
# defines the trust boundary is measured into the image.
LABEL "tee.launch_policy.allow_env_override"="NEUROLIX_SESSION_ID,NEUROLIX_DEK_demo"

# Default is 'debugonly', which would silently block the stdout redirect on the
# production image. stdout is how the attestation bundle leaves the enclave.
LABEL "tee.launch_policy.log_redirect"="always"

WORKDIR /app

COPY requirements-tee.txt .
RUN pip install --no-cache-dir -r requirements-tee.txt

COPY attestation.py inference.py payload.json ./
COPY --from=builder /build/model.joblib /build/model.sha256 ./

# Non-root, no shell — minimal attack surface inside the enclave.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin neurolix \
 && chown -R neurolix:neurolix /app
# USER neurolix  -- REVERTED
# The launcher's attestation token socket is root-owned, so a non-root workload
# cannot open it. Inside Confidential Space the enclave boundary is the security
# boundary, not the in-container uid: on the production image the operator has
# no access to the running container. The useradd above is left in place so the
# change is a one-line flip if a future image exposes the socket more widely.

# Do NOT add the -O flag. It strips the assert that guards the nonce preimage
# length invariant in attestation.py.
ENTRYPOINT ["python", "inference.py"]
