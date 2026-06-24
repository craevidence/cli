# =============================================================================
# CRA Evidence CLI - Hardened Production Dockerfile
# =============================================================================
# Multi-stage build using Docker Hardened Images (DHI) from dhi.io registry.
# Includes Syft for SBOM generation from Docker images.
#
# CRA Compliance Features:
#   - Immutable base images pinned by SHA256 digest (supply chain security)
#   - Zero shell policy in production runtime (distroless)
#   - Non-root execution (UID 1001 - DHI default)
#   - Minimal attack surface
#   - Python 3.14 for latest security patches
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
FROM dhi.io/python:3.14-dev@sha256:278a2051e1ccb1f349d1d9f86da9a5a3cb8e52c122ee6a9da278993ecbc1090b AS builder

# Build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install curl for downloading Syft (DHI dev image includes build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gzip \
    && rm -rf /var/lib/apt/lists/*

# Install Syft CLI for SBOM generation via direct binary download with SHA256 verification
# Uses a checksum-verified direct download instead of curl|sh to reduce supply chain risk
ARG SYFT_VERSION=1.45.1
ARG TARGETARCH
# Known SHA256 checksums for syft v1.45.1 linux tarballs (from official release page)
# amd64: 20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716
# arm64: 7df9f45cba1f6358ecfc7fac349d43b4605137001f9646b41267abe15a7c6cd7
RUN set -eux; \
    ARCH="${TARGETARCH:-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')}"; \
    TARBALL="syft_${SYFT_VERSION}_linux_${ARCH}.tar.gz"; \
    curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${TARBALL}" \
        -o "/tmp/${TARBALL}"; \
    case "${ARCH}" in \
        amd64) EXPECTED="20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716" ;; \
        arm64) EXPECTED="7df9f45cba1f6358ecfc7fac349d43b4605137001f9646b41267abe15a7c6cd7" ;; \
        *) echo "Unsupported architecture: ${ARCH}" && exit 1 ;; \
    esac; \
    echo "${EXPECTED}  /tmp/${TARBALL}" | sha256sum -c -; \
    mkdir -p /usr/local/bin /usr/local/share/licenses/syft; \
    tar -xzf "/tmp/${TARBALL}" -C /usr/local/bin syft; \
    tar -xzf "/tmp/${TARBALL}" -C /usr/local/share/licenses/syft LICENSE; \
    if tar -tzf "/tmp/${TARBALL}" | grep -qx NOTICE; then \
        tar -xzf "/tmp/${TARBALL}" -C /usr/local/share/licenses/syft NOTICE; \
    fi; \
    test -s /usr/local/share/licenses/syft/LICENSE; \
    rm -f "/tmp/${TARBALL}"; \
    chmod 755 /usr/local/bin/syft; \
    syft version

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
FROM dhi.io/python:3.14@sha256:f0e074dca2de2f27be6e3536b13fb8cd9e44764b22daac237b9cbf2c9982be59

# OCI Image Labels for CRA compliance and traceability
LABEL org.opencontainers.image.title="CRA Evidence CLI" \
      org.opencontainers.image.description="CLI tool for CI/CD integration with CRA Evidence - DHI hardened production image" \
      org.opencontainers.image.vendor="CRA Evidence" \
      org.opencontainers.image.url="https://craevidence.com" \
      org.opencontainers.image.documentation="https://docs.craevidence.com/cli" \
      org.opencontainers.image.source="https://github.com/craevidence/cli" \
      org.opencontainers.image.licenses="MIT" \
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
    SSL_CERT_DIR="/app/ssl/certs"

WORKDIR /app

# Copy virtual environment with installed CLI
COPY --from=builder --chown=1001:1001 /opt/venv /opt/venv

# Copy Syft binary (static, no runtime dependencies)
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft

# Syft is Apache-2.0 - ship its license alongside the bundled binary
COPY --from=builder /usr/local/share/licenses/syft /usr/local/share/licenses/syft

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
