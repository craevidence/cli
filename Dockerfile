# =============================================================================
# CRA Evidence CLI - Hardened Production Dockerfile
# =============================================================================
# Multi-stage build using Docker Hardened Images (DHI) from dhi.io registry.
# Includes local check engines for SBOM generation and vulnerability matching.
#
# CRA Compliance Features:
#   - Immutable base images pinned by SHA256 digest (supply chain security)
#   - Zero shell policy in production runtime (distroless)
#   - Non-root execution (UID 1001 - DHI default)
#   - Minimal attack surface
#   - Python 3.14 runtime
#
# SBOM Generation:
#   docker scout sbom --image craevidence:latest
#   docker sbom craevidence:latest --output sbom.spdx.json
#   syft craevidence:latest -o cyclonedx-json > sbom.cdx.json
#
# Usage:
#   # Upload existing SBOM
#   docker run --rm -e CRA_EVIDENCE_API_KEY=xxx -v $(pwd):/workspace craevidence \
#     upload-sbom --product my-product --version 1.0.0 --file /workspace/sbom.json
#
#   # Generate SBOM from Docker image and upload
#   docker run --rm -e CRA_EVIDENCE_API_KEY=xxx \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     craevidence upload-sbom --product my-product --version 1.0.0 --image nginx:latest
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Build Environment
# -----------------------------------------------------------------------------
# The -dev variant includes pip, build-essential, git, and package manager.
# Pin by SHA256 digest for supply chain integrity.
#
# To update digest:
#   docker pull dhi.io/python:3.14-dev
#   docker inspect dhi.io/python:3.14-dev --format='{{index .RepoDigests 0}}'
# -----------------------------------------------------------------------------
# Allow org builds to supply alternative base images (e.g. a newer DHI digest)
# and allow anyone without DHI access to build using public images. Fallback
# builds must also override the identity labels so the image records the base
# actually used instead of claiming hardened properties it does not have:
#   docker build \
#     --build-arg BASE_IMAGE_BUILDER=python:3.14 \
#     --build-arg BASE_IMAGE=python:3.14-slim \
#     --build-arg BASE_IMAGE_NAME=python:3.14-slim \
#     --build-arg IMAGE_DESCRIPTION="CLI tool for CI/CD integration with CRA Evidence - public Python base fallback build" \
#     --build-arg SECURITY_HARDENED=false \
#     --build-arg SECURITY_NO_SHELL=false \
#     --build-arg SECURITY_NO_PACKAGE_MANAGER=false .
# Scan engine: grype fork with improvements. The default is the digest-pinned
# engine artifact; anyone without registry access can build with the upstream
# engine instead:
#   --build-arg GRYPE_ENGINE_IMAGE=docker.io/anchore/grype:v0.116.1
ARG GRYPE_ENGINE_IMAGE=636143320258.dkr.ecr.eu-west-1.amazonaws.com/craevidence/grype-engine@sha256:59204fe467cf425107f2e469735c59c65de2652afb9d1c769ef62996c413d067

ARG BASE_IMAGE_BUILDER=dhi.io/python:3.14-dev@sha256:5acf54c5ce21277f52115d45e217915779f8ce43a3667ea0b37a642bc7b7c8a7
# Declared here (before the first FROM) because Docker only resolves ARGs in
# FROM lines when they are global; a stage-scoped ARG cannot feed a FROM.
ARG BASE_IMAGE=dhi.io/python:3.14@sha256:f3c4e102e557c0eee652cfd14b7da473c89d9126a07f5b0ebd9f8e79183f4038
FROM ${GRYPE_ENGINE_IMAGE} AS grype-engine

FROM ${BASE_IMAGE_BUILDER} AS builder

# Build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install curl for downloading check engine binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Install local check engines via direct downloads with SHA256 verification.
ARG SYFT_VERSION=1.50.0
ARG GRYPE_LICENSE_REF=v0.116.1
ARG TARGETARCH
COPY --from=grype-engine /grype /usr/local/bin/grype
RUN set -eux; \
    ARCH="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"; \
    SYFT_TARBALL="syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz"; \
    case "${ARCH}" in \
        amd64) \
            SYFT_EXPECTED="bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788" ;; \
        arm64) \
            SYFT_EXPECTED="887c57cbcc2d0e8c5c110a4571a3fc7150058b24d74f993ee4663516e5c8ce86" ;; \
        *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
    esac; \
    GRYPE_LICENSE_EXPECTED="c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"; \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${SYFT_TARBALL}" \
        -o "/tmp/${SYFT_TARBALL}"; \
    curl -fsSL "https://raw.githubusercontent.com/anchore/grype/${GRYPE_LICENSE_REF}/LICENSE" \
        -o /tmp/grype-LICENSE; \
    echo "${SYFT_EXPECTED}  /tmp/${SYFT_TARBALL}" | sha256sum -c -; \
    echo "${GRYPE_LICENSE_EXPECTED}  /tmp/grype-LICENSE" | sha256sum -c -; \
    mkdir -p /usr/local/bin /licenses/syft /licenses/grype; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /usr/local/bin syft; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /licenses/syft LICENSE; \
    install -m 0644 /tmp/grype-LICENSE /licenses/grype/LICENSE; \
    test -s /licenses/syft/LICENSE; \
    test -s /licenses/grype/LICENSE; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /licenses/syft NOTICE 2>/dev/null || true; \
    rm -f "/tmp/${SYFT_TARBALL}" /tmp/grype-LICENSE; \
    chmod 755 /usr/local/bin/syft /usr/local/bin/grype; \
    syft version; \
    grype version

# Create virtual environment for clean dependency isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy package files and install
COPY pyproject.toml README.md ./
COPY cra_evidence_cli/ ./cra_evidence_cli/

# Install the CLI into virtual environment
RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir .

# Verify CLI installation
RUN craevidence --version || craevidence --help

# Copy CA certificates for runtime HTTPS connections
RUN mkdir -p /build/ssl && cp -r /etc/ssl/certs /build/ssl/

# Set ownership for non-root user (UID 1001 - DHI default)
RUN chown -R 1001:1001 /opt/venv /build/ssl

# -----------------------------------------------------------------------------
# STAGE 2: Production Runtime (minimalist distroless variant)
# -----------------------------------------------------------------------------
# The hardened runtime variant has no shell and no package manager. It ships
# the Python interpreter plus the Debian runtime packages the interpreter
# depends on; generate an SBOM from the image for the exact package inventory.
#
# To update digest:
#   docker pull dhi.io/python:3.14
#   docker inspect dhi.io/python:3.14 --format='{{index .RepoDigests 0}}'
# -----------------------------------------------------------------------------
FROM ${BASE_IMAGE}

# Image identity build-args. The defaults describe the pinned DHI base; the
# public-base fallback build must override them so the labels always record
# the base image actually used (see .github/workflows/ci.yml).
ARG BASE_IMAGE_NAME="dhi.io/python:3.14"
ARG IMAGE_DESCRIPTION="CLI tool for CI/CD integration with CRA Evidence - DHI hardened production image"
ARG SECURITY_HARDENED="true"
ARG SECURITY_NO_SHELL="true"
ARG SECURITY_NO_PACKAGE_MANAGER="true"

# OCI Image Labels for CRA compliance and traceability.
# org.opencontainers.image.licenses is "MIT AND Apache-2.0": MIT is the CLI's own
# licence; Apache-2.0 covers the redistributed Syft and Grype binaries. Their
# LICENSE (and NOTICE where present) files are available at /licenses/{syft,grype}/.
LABEL org.opencontainers.image.title="CRA Evidence CLI" \
      org.opencontainers.image.description="${IMAGE_DESCRIPTION}" \
      org.opencontainers.image.vendor="CRA Evidence" \
      org.opencontainers.image.url="https://craevidence.com" \
      org.opencontainers.image.documentation="https://github.com/craevidence/cli/tree/main/docs" \
      org.opencontainers.image.source="https://github.com/craevidence/cli" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      org.opencontainers.image.base.name="${BASE_IMAGE_NAME}" \
      org.opencontainers.image.python.version="3.14" \
      eu.cra.security.hardened="${SECURITY_HARDENED}" \
      eu.cra.security.non-root="true" \
      eu.cra.security.no-shell="${SECURITY_NO_SHELL}" \
      eu.cra.security.no-package-manager="${SECURITY_NO_PACKAGE_MANAGER}" \
      eu.cra.security.sbom-command="docker scout sbom --image <image>"

# Runtime environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SSL_CERT_DIR="/app/ssl/certs" \
    HOME="/tmp" \
    GRYPE_DB_CACHE_DIR="/tmp/grype-db"

WORKDIR /app

# Copy virtual environment with installed CLI
COPY --from=builder --chown=1001:1001 /opt/venv /opt/venv

# Copy local check engine binaries
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype

# Third-party LICENSE and NOTICE files for redistributed Apache-2.0 binaries
COPY --from=builder /licenses /licenses

# Copy CA certificates for HTTPS connections
COPY --from=builder --chown=1001:1001 /build/ssl /app/ssl

# Explicit non-root user directive (UID 1001 - DHI default)
USER 1001:1001

# Set working directory to workspace (for file mounts)
WORKDIR /workspace

# Default entrypoint is the CLI
# Using exec form (JSON array) - no shell required
ENTRYPOINT ["python", "-m", "cra_evidence_cli.cli"]

# Default command shows help
CMD ["--help"]
