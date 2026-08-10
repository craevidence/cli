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
#   docker run --rm craevidence check --image craevidence:latest
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
# engine artifact. An override must provide the same supported CRA Evidence
# engine contract, including /grype, /LICENSE and /NOTICE.
ARG GRYPE_ENGINE_IMAGE=636143320258.dkr.ecr.eu-west-1.amazonaws.com/craevidence/grype-engine@sha256:700d2d2016ab95d5e06807629a55fdcac4571b93a79b1f064c8c9ee5660ef340

ARG BASE_IMAGE_BUILDER=dhi.io/python:3.14-dev@sha256:4e6d70f6819594aa6210ba629695eaec7e56f72cd1ec0dca22e9cf0699ff01d7
# Declared here (before the first FROM) because Docker only resolves ARGs in
# FROM lines when they are global; a stage-scoped ARG cannot feed a FROM.
ARG BASE_IMAGE=dhi.io/python:3.14@sha256:7fa71fa6509c110456742c8505dfea44f0b4656018123b3eaf4f33f71ae902b7
FROM ${GRYPE_ENGINE_IMAGE} AS grype-engine

FROM ${BASE_IMAGE_BUILDER} AS builder
ARG TARGETARCH
ARG OPENGREP_VERSION=1.26.0
ARG OPENGREP_COMMIT=1bef4ea4ff3264754132eec823b5b1d8cde3e4ee

# Build-time environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install the exact promoted local check engine. SBOM generation uses the Syft
# library embedded in this binary; there is no second standalone Syft binary.
COPY --from=grype-engine /grype /usr/local/bin/grype
COPY --from=grype-engine /LICENSE /licenses/grype/LICENSE
COPY --from=grype-engine /NOTICE /licenses/grype/NOTICE
RUN set -eux; \
    chmod 755 /usr/local/bin/grype; \
    test -s /licenses/grype/LICENSE; \
    test -s /licenses/grype/NOTICE; \
    grype version --output json; \
    grype sbom --help | grep -F 'grype sbom SOURCE' >/dev/null; \
    grype sbom --help | grep -F -- '--offline' >/dev/null

# Fetch the official Opengrep binary by immutable release checksum. Release CI
# additionally verifies the upstream Sigstore signature before publishing.
RUN python -c 'import hashlib, json, os, pathlib, re, urllib.request; arch=os.environ["TARGETARCH"]; version=os.environ["OPENGREP_VERSION"]; commit=os.environ["OPENGREP_COMMIT"]; assets={"amd64":("opengrep_manylinux_x86","40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26"),"arm64":("opengrep_manylinux_aarch64","3042a3b1aa98fa93407b9d66a45ab1f179b5b367e76965f56afdbd2c038fb1fa")}; asset,expected=assets[arch]; target=pathlib.Path("/usr/local/bin/opengrep"); urllib.request.urlretrieve(f"https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}", target); content=target.read_bytes(); actual=hashlib.sha256(content).hexdigest(); assert actual == expected, f"Opengrep SHA-256 mismatch: {actual}"; target.chmod(0o755); license_dir=pathlib.Path("/licenses/opengrep"); license_dir.mkdir(parents=True); urllib.request.urlretrieve(f"https://raw.githubusercontent.com/opengrep/opengrep/{commit}/LICENSE", license_dir / "LICENSE"); urllib.request.urlretrieve(f"https://raw.githubusercontent.com/opengrep/opengrep/{commit}/COPYRIGHT", license_dir / "COPYRIGHT"); libraries=sorted({match.group(0)[:-1].decode("ascii") for match in re.finditer(rb"(?:lib[A-Za-z0-9_+.-]+\.(?:so(?:\.[0-9.]+)?|dylib))\x00", content)}); assert libraries, f"no native dependencies found in {asset}"; (license_dir / "NATIVE-DEPENDENCIES.json").write_text(json.dumps({asset:libraries}, indent=2, sort_keys=True)+"\n", encoding="utf-8"); (license_dir / "NOTICE").write_text(f"This product includes Opengrep {version}, licensed under the GNU Lesser General Public License version 2.1. Source commit: {commit}. The upstream repository is https://github.com/opengrep/opengrep. The matching CRA Evidence CLI GitHub release includes opengrep-{version}-source.tar.gz with the pinned build-source modules. Upstream copyright notices and the native dependency inventory accompany this notice.\n", encoding="utf-8")'
RUN opengrep --version | grep -F "${OPENGREP_VERSION}" >/dev/null

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
# MIT is the CLI license, Apache-2.0 covers Grype and its embedded Syft library,
# and LGPL-2.1-only covers the redistributed Opengrep executable.
LABEL org.opencontainers.image.title="CRA Evidence CLI" \
      org.opencontainers.image.description="${IMAGE_DESCRIPTION}" \
      org.opencontainers.image.vendor="CRA Evidence" \
      org.opencontainers.image.url="https://craevidence.com" \
      org.opencontainers.image.documentation="https://github.com/craevidence/cli/tree/main/docs" \
      org.opencontainers.image.source="https://github.com/craevidence/cli" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0 AND LGPL-2.1-only" \
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

# Copy the local check engine binary
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/opengrep /usr/local/bin/opengrep

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
