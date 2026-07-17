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
# and allow anyone without DHI access to build using public images:
#   docker build --build-arg BASE_IMAGE_BUILDER=python:3.14 \
#                --build-arg BASE_IMAGE=python:3.14-slim .
ARG BASE_IMAGE_BUILDER=dhi.io/python:3.14-dev@sha256:9b72c38a520f44fafa1c4a3026e9b390eb3b4967c62d38be01400ecbb0232b65
# Declared here (before the first FROM) because Docker only resolves ARGs in
# FROM lines when they are global; a stage-scoped ARG cannot feed a FROM.
ARG BASE_IMAGE=dhi.io/python:3.14@sha256:c82da5a1a30a6214f45c42def5b6f5b85981c7dc7a1802015a6ebf264675436d
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
ARG SYFT_VERSION=1.48.0
ARG GRYPE_VERSION=0.116.0
ARG TARGETARCH
RUN set -eux; \
    ARCH="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"; \
    SYFT_TARBALL="syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz"; \
    GRYPE_TARBALL="grype_${GRYPE_VERSION}_linux_${ARCH}.tar.gz"; \
    case "${ARCH}" in \
        amd64) \
            SYFT_EXPECTED="6cef9a7f37220d9067eaf9cfaaa2fce986e9f320a8d42cbc36658c99af78ea04"; \
            GRYPE_EXPECTED="40aff724297312f91ea390d003bed8d8651c74cc7f5b26732db80b3a408d2fc5" ;; \
        arm64) \
            SYFT_EXPECTED="6865a3d97c4e28b4b38571c17a2bf512da4494ef1d37613c3122fce0d67e63b0"; \
            GRYPE_EXPECTED="7af3eed24f469b0cf3ab5ec4508d9c12f4bb9c2c6be714f32973c7b5d63cb6a5" ;; \
        *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${SYFT_TARBALL}" \
        -o "/tmp/${SYFT_TARBALL}"; \
    curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${GRYPE_TARBALL}" \
        -o "/tmp/${GRYPE_TARBALL}"; \
    echo "${SYFT_EXPECTED}  /tmp/${SYFT_TARBALL}" | sha256sum -c -; \
    echo "${GRYPE_EXPECTED}  /tmp/${GRYPE_TARBALL}" | sha256sum -c -; \
    mkdir -p /usr/local/bin /licenses/syft /licenses/grype; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /usr/local/bin syft; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /licenses/syft LICENSE; \
    tar -xzf "/tmp/${GRYPE_TARBALL}" -C /usr/local/bin grype; \
    tar -xzf "/tmp/${GRYPE_TARBALL}" -C /licenses/grype LICENSE; \
    test -s /licenses/syft/LICENSE; \
    test -s /licenses/grype/LICENSE; \
    tar -xzf "/tmp/${SYFT_TARBALL}" -C /licenses/syft NOTICE 2>/dev/null || true; \
    tar -xzf "/tmp/${GRYPE_TARBALL}" -C /licenses/grype NOTICE 2>/dev/null || true; \
    rm -f "/tmp/${SYFT_TARBALL}" "/tmp/${GRYPE_TARBALL}"; \
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
# The runtime variant has no shell, no package manager, minimal attack surface.
# Only Python interpreter and essential runtime libraries are included.
#
# To update digest:
#   docker pull dhi.io/python:3.14
#   docker inspect dhi.io/python:3.14 --format='{{index .RepoDigests 0}}'
# -----------------------------------------------------------------------------
FROM ${BASE_IMAGE}

# OCI Image Labels for CRA compliance and traceability.
# org.opencontainers.image.licenses is "MIT AND Apache-2.0": MIT is the CLI's own
# licence; Apache-2.0 covers the redistributed Syft and Grype binaries. Their
# LICENSE (and NOTICE where present) files are available at /licenses/{syft,grype}/.
LABEL org.opencontainers.image.title="CRA Evidence CLI" \
      org.opencontainers.image.description="CLI tool for CI/CD integration with CRA Evidence - DHI hardened production image" \
      org.opencontainers.image.vendor="CRA Evidence" \
      org.opencontainers.image.url="https://craevidence.com" \
      org.opencontainers.image.documentation="https://github.com/craevidence/cli/tree/main/docs" \
      org.opencontainers.image.source="https://github.com/craevidence/cli" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0" \
      org.opencontainers.image.base.name="dhi.io/python:3.14" \
      org.opencontainers.image.python.version="3.14" \
      eu.cra.security.hardened="true" \
      eu.cra.security.non-root="true" \
      eu.cra.security.no-shell="true" \
      eu.cra.security.no-package-manager="true" \
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
