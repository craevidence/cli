#!/usr/bin/env bash
# One-time Codespaces setup: install the editable CLI and sbomqs.
set -euo pipefail

python -m pip install --upgrade pip
pip install -e ".[dev]"

# Install sbomqs at a pinned version with checksum verification.
SBOMQS_VERSION="2.0.11"

MACHINE="$(uname -m)"
case "${MACHINE}" in
    x86_64)
        SBOMQS_ARCH="x86_64"
        SBOMQS_SHA256="14fd58b89d4948265cce0fdb95d9b635ff667f352b5a9a05b3d13dbefa5d0195"
        ;;
    aarch64|arm64)
        SBOMQS_ARCH="arm64"
        SBOMQS_SHA256="baf0519fe2fc54f1e23273c98f8efd9048e11a8f589d0cf92c3fd6d5765a4bdb"
        ;;
    *)
        echo "Unsupported architecture: ${MACHINE}" >&2
        exit 1
        ;;
esac

install_sbomqs() {
    local tarball="sbomqs_${SBOMQS_VERSION}_Linux_${SBOMQS_ARCH}.tar.gz"
    local url="https://github.com/interlynk-io/sbomqs/releases/download/v${SBOMQS_VERSION}/${tarball}"
    local tmpfile
    tmpfile="$(mktemp)"
    curl -fsSL "${url}" -o "${tmpfile}"
    echo "${SBOMQS_SHA256}  ${tmpfile}" | sha256sum -c - >/dev/null
    sudo tar -xzf "${tmpfile}" -C /usr/local/bin sbomqs
    rm -f "${tmpfile}"
}

install_sbomqs

cat <<'EOF'

CRA Evidence CLI is ready. Try a no-account local check:

  craevidence check --sbom docs/demo-assets/sbom.demo.json
  craevidence check .

Editable source installs do not bundle the release engine. Set
CRA_EVIDENCE_ENGINE to a supported engine binary to exercise local matching.

EOF
