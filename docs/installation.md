# Installation

How to install the CRA Evidence CLI via PyPI, Homebrew, Docker, container registries, or from source, plus how to install Syft for SBOM generation.

Back to the [README](../README.md).

## Install

```bash
# Install
pip install craevidence                     # PyPI
pipx install craevidence                    # PyPI, isolated (recommended for a CLI)
brew install craevidence/tap/craevidence    # Homebrew (via tap)

# Run (no signup, ~30 seconds)
craevidence check .                              # scan a project directory
craevidence check --image ghcr.io/acme/app:1.4.2 # scan a container image
craevidence check --sbom sbom.cdx.json           # score an SBOM you already have

# Use it as a CI gate (exit non-zero on actively-exploited vulns)
craevidence check . --fail-on known-exploited
```

## Installation

### PyPI

```bash
pip install craevidence
```

### Docker

```bash
docker pull craevidence/cli:latest
```

### Container Registries

The CLI Docker image is published to multiple registries:

| Registry | Image | Usage |
|----------|-------|-------|
| **Docker Hub** (primary) | `craevidence/cli:latest` | Default - no registry prefix needed |
| **GHCR** | `ghcr.io/craevidence/craevidence:latest` | Alternative if Docker Hub rate-limited |
| **Quay.io** | `quay.io/craevidence/cli:latest` | Alternative mirror |

### From Source

```bash
git clone https://github.com/craevidence/cli.git
cd cli
pip install -e .
```

### SBOM Generation from Docker Images

The CLI Docker image includes Syft for generating SBOMs directly from Docker images. When using the Docker image, no additional installation is required. Mount the Docker socket:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CRA_EVIDENCE_API_KEY=xxx \
  craevidence/cli:latest \
  upload-sbom --product my-app --version 1.0 --image nginx:latest
```

> **Security note:** Mounting the Docker socket grants the container full control over the Docker daemon. Only do this in trusted CI/CD environments.

If running the CLI natively (`pip install`), install Syft separately:

```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```
