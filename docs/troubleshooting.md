# Troubleshooting

Back to the [README](../README.md).

### "A compatible CRA Evidence engine is required"

The CLI could not resolve a supported product engine from
`CRA_EVIDENCE_ENGINE`, a bundled wheel payload, or `PATH`; or the resolved
executable was stock Grype, an unstamped build, or an older CRA Evidence engine
without SBOM generation. The message names which one. Use the published CRA
Evidence CLI Docker image, which bundles a compatible engine. Standalone engine
archives are not a supported distribution channel. A standalone Syft executable
and stock Grype are not fallbacks.

`check` still attempts an OSV.dev fallback without an engine and says so on
stderr, naming the reason the local matcher was skipped. The fallback may use
the network and its findings can differ from the local engine because the
matching strategies are not equivalent.

### "Cannot connect to Docker daemon"

Mount the Docker socket when running inside a container:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  craevidence/cli:latest \
  upload-sbom --image my-app:latest ...
```

### "Image not found"

Pull the image before generating an SBOM from it:

```bash
docker pull nginx:latest
craevidence upload-sbom --product my-app --version 1.0 --image nginx:latest
```

### Timeout during SBOM generation

Large images take longer to analyse. For very large images, generate the SBOM in
your build system or another trusted SBOM tool, then upload the resulting file:

```bash
craevidence upload-sbom --product my-app --version 1.0 --file sbom.json
```

### `401 Unauthorized` while building the CLI Docker image

The published Dockerfile defaults to Docker Hardened Images (DHI) from `dhi.io`. Building it
requires either DHI registry credentials or the `--build-arg` public-base override:

```bash
docker build \
  --build-arg BASE_IMAGE_BUILDER=python:3.14 \
  --build-arg BASE_IMAGE=python:3.14-slim \
  -t craevidence-cli:local .
```

The `--build-arg` form substitutes standard public Python images for the DHI bases. The resulting
image behaves identically; only the base image source differs. See
[Installation](installation.md#building-the-docker-image-from-source) for the full command.
