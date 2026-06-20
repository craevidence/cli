#!/usr/bin/env bash
# One-time Codespaces setup: install the CLI and the scanners it shells out to,
# then prime the local vulnerability database so check works in the codespace.
set -euo pipefail

python -m pip install --upgrade pip
pip install -e ".[dev]"

# Syft generates SBOMs from a directory or image; Grype matches vulnerabilities.
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin
grype db update || true

cat <<'EOF'

CRA Evidence CLI is ready. Try a no-account local check:

  craevidence check --sbom docs/demo-assets/sbom.cdx.json
  craevidence check .

EOF
