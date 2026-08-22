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
ARG GRYPE_ENGINE_IMAGE=636143320258.dkr.ecr.eu-west-1.amazonaws.com/craevidence/grype-engine@sha256:02f1fbc3f1bdcc2c3354600f40d11aa4f5de3203f1933a30167d73c3f4ee211f

ARG BASE_IMAGE_BUILDER=dhi.io/python:3.14-dev@sha256:02173cae8b920c98ff9fab81eb1aefcadd229f158110553c6ed758dc935589dd
# Declared here (before the first FROM) because Docker only resolves ARGs in
# FROM lines when they are global; a stage-scoped ARG cannot feed a FROM.
ARG BASE_IMAGE=dhi.io/python:3.14@sha256:0536ccad57c9be08128bd2a6f0982570086ec943a88033f4f53f7adffe407903
FROM ${GRYPE_ENGINE_IMAGE} AS grype-engine

FROM ${BASE_IMAGE_BUILDER} AS builder
ARG TARGETARCH
ARG OPENGREP_VERSION=1.26.0
ARG OPENGREP_COMMIT=1bef4ea4ff3264754132eec823b5b1d8cde3e4ee
ARG LIBCLANG_VERSION=1:18.1.8-18+b1
ARG LIBEDIT_VERSION=3.1-20250104-1
ARG LIBXML2_VERSION=2.12.7+dfsg+really2.9.14-2.1+deb13u3
ARG LIBZ3_VERSION=4.13.3-1

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

# Install the exact Debian 13 libclang frontend and build a runtime subset.
# The final image receives only the frontend libraries, required headers,
# package identity records, and copyright files. It does not receive apt,
# dpkg, a compiler driver, a linker, or a shell.
RUN set -eux; \
    gcc_version="$(dpkg-query -W -f='${Version}' gcc-14-base)"; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      "libclang1-18=${LIBCLANG_VERSION}" \
      "libllvm18=${LIBCLANG_VERSION}" \
      "libclang-common-18-dev=${LIBCLANG_VERSION}" \
      "libstdc++-14-dev=${gcc_version}" \
      "libedit2=${LIBEDIT_VERSION}" \
      "libxml2=${LIBXML2_VERSION}" \
      "libz3-4=${LIBZ3_VERSION}"; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    architecture="$(dpkg-query -W -f='${Architecture}' libc6)"; \
    case "${architecture}" in \
      amd64) triple=x86_64-linux-gnu ;; \
      arm64) triple=aarch64-linux-gnu ;; \
      *) printf 'Unsupported Debian architecture: %s\n' "${architecture}" >&2; exit 1 ;; \
    esac; \
    runtime_root=/semantic-runtime; \
    mkdir -p "${runtime_root}" "${runtime_root}/licenses/semantic"; \
    header_packages="libclang-common-18-dev libstdc++-14-dev libc6-dev linux-libc-dev"; \
    runtime_packages="libclang1-18 libllvm18 libedit2 libxml2 libz3-4 libbsd0 libmd0"; \
    for package in ${header_packages}; do \
      dpkg-query -L "${package}" | while IFS= read -r path; do \
        case "${path}" in \
          /usr/include/*|/usr/lib/llvm-18/lib/clang/18/include/*) \
            if [ -f "${path}" ] || [ -L "${path}" ]; then \
              relative="${path#/}"; \
              (cd / && cp -a --parents "${relative}" "${runtime_root}"); \
            fi \
            ;; \
        esac; \
      done; \
    done; \
    for package in ${runtime_packages}; do \
      dpkg-query -L "${package}" | while IFS= read -r path; do \
        case "${path}" in \
          /lib/${triple}/*.so*|/usr/lib/${triple}/*.so*) \
            if [ -f "${path}" ] || [ -L "${path}" ]; then \
              relative="${path#/}"; \
              (cd / && cp -a --parents "${relative}" "${runtime_root}"); \
            fi \
            ;; \
        esac; \
      done; \
    done; \
    : > "${runtime_root}/licenses/semantic/DPKG-STATUS"; \
    for package in ${header_packages} ${runtime_packages}; do \
      dpkg-query -s "${package}" >> "${runtime_root}/licenses/semantic/DPKG-STATUS"; \
      printf '\n' >> "${runtime_root}/licenses/semantic/DPKG-STATUS"; \
      copyright="/usr/share/doc/${package}/copyright"; \
      test -e "${copyright}"; \
      cp -L "${copyright}" "${runtime_root}/licenses/semantic/${package}-copyright"; \
    done; \
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' \
      ${header_packages} ${runtime_packages} \
      > "${runtime_root}/licenses/semantic/PACKAGES"; \
    printf '%s\n' \
      'This image includes a build-free C and C++ semantic evidence frontend.' \
      'Package identities and Debian copyright notices are stored in this directory.' \
      > "${runtime_root}/licenses/semantic/NOTICE"; \
    test -e "${runtime_root}/usr/lib/${triple}/libclang-18.so.18"; \
    test -e "${runtime_root}/usr/lib/${triple}/libLLVM-18.so.18.1"; \
    test -d "${runtime_root}/usr/lib/llvm-18/lib/clang/18/include"; \
    test -d "${runtime_root}/usr/include/c++/14"

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
# LGPL-2.1-only covers Opengrep, and the semantic frontend notices record
# LLVM, GCC runtime exception, libc, Linux headers, and support-library terms.
LABEL org.opencontainers.image.title="CRA Evidence CLI" \
      org.opencontainers.image.description="${IMAGE_DESCRIPTION}" \
      org.opencontainers.image.vendor="CRA Evidence" \
      org.opencontainers.image.url="https://craevidence.com" \
      org.opencontainers.image.documentation="https://github.com/craevidence/cli/tree/main/docs" \
      org.opencontainers.image.source="https://github.com/craevidence/cli" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0 AND LGPL-2.1-only AND (Apache-2.0 WITH LLVM-exception) AND (GPL-3.0-or-later WITH GCC-exception-3.1) AND LGPL-2.1-or-later AND (GPL-2.0-only WITH Linux-syscall-note) AND BSD-3-Clause" \
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

# Copy the compiler frontend subset without adding a package manager, shell,
# compiler driver, linker, or project build tool to the runtime image.
COPY --from=builder /semantic-runtime/ /

# Merge the copied packages into the runtime inventory so SBOM and
# vulnerability scanners see every redistributed frontend component. Existing
# packages must have the same exact version or the build fails.
USER 0:0
RUN ["python", "-c", "from pathlib import Path; base=Path('/var/lib/dpkg/status'); extra=Path('/licenses/semantic/DPKG-STATUS'); stanzas=lambda text:[item for item in text.strip().split('\\n\\n') if item]; field=lambda item,name:next(line[len(name)+2:] for line in item.splitlines() if line.startswith(name+': ')); current=stanzas(base.read_text(encoding='utf-8')); incoming=stanzas(extra.read_text(encoding='utf-8')); key=lambda item:(field(item,'Package'),field(item,'Architecture')); versions={key(item):field(item,'Version') for item in current}; conflicts=[(key(item),versions[key(item)],field(item,'Version')) for item in incoming if key(item) in versions and versions[key(item)]!=field(item,'Version')]; assert not conflicts, f'package inventory version conflict: {conflicts}'; additions=[item for item in incoming if key(item) not in versions]; base.write_text('\\n\\n'.join(current+additions)+'\\n', encoding='utf-8')"]
USER 1001:1001

# Copy CA certificates for HTTPS connections
COPY --from=builder --chown=1001:1001 /build/ssl /app/ssl

# Verify the final distroless runtime can load both exact semantic profiles.
RUN ["python", "-c", "from cra_evidence_cli.local.c_semantic_analyzer import inspect_c_frontend; c=inspect_c_frontend('c'); cpp=inspect_c_frontend('cpp'); assert c['profile']=='libclang-18.1.8-debian13-c17-security-evidence-v2'; assert cpp['profile']=='libclang-18.1.8-debian13-cpp17-security-evidence-v2'"]

# Explicit non-root user directive (UID 1001 - DHI default)
USER 1001:1001

# Set working directory to workspace (for file mounts)
WORKDIR /workspace

# Default entrypoint is the CLI
# Using exec form (JSON array) - no shell required
ENTRYPOINT ["python", "-m", "cra_evidence_cli.cli"]

# Default command shows help
CMD ["--help"]
