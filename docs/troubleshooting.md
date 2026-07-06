# Troubleshooting

Back to the [README](../README.md).

### "Syft not installed" when using `--image`

Use the Docker image (Syft is bundled) or install Syft natively:

```bash
brew install syft           # macOS
# Linux: see https://github.com/anchore/syft#installation
```

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

Large images take longer to analyse. For very large images, run Syft directly and upload the resulting file instead of using `--image`:

```bash
syft my-app:latest -o cyclonedx-json > sbom.json
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
