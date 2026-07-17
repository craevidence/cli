# Releasing

Maintainer reference for publishing a CRA Evidence CLI release. Every step
that publishes something is deliberate: nothing here happens implicitly.

## Channels and support policy

A release publishes to PyPI, GHCR, Docker Hub, and Quay, and attaches signed
artifacts and per-platform SBOMs to the GitHub release. All channels are
required for a successful release run. Multi-channel publication is not
transactional: a failed run can leave already-published version artifacts in
place, and a rerun resumes from them instead of replacing them. The `latest`
tags move only after every required channel has succeeded.

Only the latest minor release line is supported. Older lines receive no
fixes; users should upgrade to the newest release.

## The release commit

One commit contains everything the release needs:

1. Roll the `[Unreleased]` section of `CHANGELOG.md` into `## [X.Y.Z] - date`.
2. Bump `version` in `pyproject.toml`.
3. Update the pinned CLI wheel version and checksum in
   `gitlab-ci-component.yml` (both templates install it). The checksum is
   predictable before PyPI has the file because wheel builds are
   byte-reproducible: build with the same pinned tools and fixed epoch the
   pipeline uses and take the wheel's SHA-256:

   ```sh
   docker run --rm -v "$PWD":/src:ro python:3.14-slim sh -ec '
     cp -r /src /build && cd /build && rm -rf dist
     python -m pip install -q pip==26.1.2 build==1.5.0
     export SOURCE_DATE_EPOCH=946684800
     python -m build -q
     sha256sum dist/*.whl'
   ```

4. Move the documented component include refs (the `v...` raw URL in
   `gitlab-ci-component.yml` and `docs/ci-cd.md`) to the new tag.

## Before pushing anything

Run the full local gate on the release commit; every check must pass, and the
scan checks must be re-run immediately before the push because the
vulnerability database and base image digests move daily:

```sh
./.venv/bin/python -m pytest -q
./.venv/bin/ruff check .
bash scripts/check-dhi-base.sh --strict
docker build -t craevidence:release-check .
bash scripts/check-image-gate.sh craevidence:release-check
./.venv/bin/python scripts/check_dist.py
```

## Tag and publish

1. Push the release commit to `main`.
2. Create the release tag at exactly that commit and push it:
   `git tag vX.Y.Z <commit> && git push origin vX.Y.Z`. The pipeline's
   signing identity and checkout both derive from this tag.
3. Create the GitHub release from the existing tag `vX.Y.Z` and publish it.
4. Approve the protected deployments when GitHub asks. Three release jobs are
   approval-gated: image publishing and the final `latest` move both use the
   `release-images` environment, and the immutable PyPI upload uses `pypi`.

The pipeline then: validates the release tag against the package version in
a read-only job before any publishing job starts; builds the canonical
multi-arch image once and pushes it to GHCR, or reuses the already-published
digest when the version tag exists; copies the index to registries that do
not have it and refuses to overwrite a published version tag that differs;
requires every version tag to resolve to the canonical digest; signs that
digest on each registry and verifies every signature against the release
identity `.../.github/workflows/ci.yml@refs/tags/vX.Y.Z`; generates
per-platform SBOMs from the released digests, attaches them to the GitHub
release, and uploads the linux/amd64 SBOM to CRA Evidence as a required
step; checks the built wheel against the component pin, builds, signs, and
publishes the PyPI artifacts with a pre-publish idempotence check and a
post-publish verification; and only after both the container channels and
PyPI have succeeded, moves the `latest` tags in a final approval-gated job.

## After the pipeline

Verify the release from a clean environment. Each check is an assertion, not
a glance:

1. All three registries resolve `X.Y.Z` and `latest` to the same digest as
   GHCR, and `cosign verify` passes for each `repo@digest` with the exact
   release identity above.
2. PyPI serves exactly the built wheel and sdist, with hashes equal to the
   GitHub release assets, and the wheel hash equals the checksum pinned in
   `gitlab-ci-component.yml`.
3. The GitHub release carries `sbom-X.Y.Z-linux-amd64.cdx.json` and
   `sbom-X.Y.Z-linux-arm64.cdx.json`.
4. The image labels report the hardened base
   (`org.opencontainers.image.base.name=dhi.io/python:3.14`).

## Reruns and partial failures

A rerun resumes a partially failed release: it reuses the digest already
published under the version tag instead of rebuilding, refuses to act when a
registry's state cannot be determined or a published tag differs from the
canonical digest, and uploads only release assets that are not attached yet,
so SBOMs and signature bundles published by an earlier run are never
replaced, and the CRA Evidence upload runs on every release run with the
published SBOM bytes after verifying the canonical digest is the SBOM's
subject. When PyPI already serves the complete file set, a rerun recovers
those bytes instead of rebuilding, so it can finish the remaining channels;
a partially published PyPI version stops the run for investigation. Retained
release assets are verified before being kept: distributions must match the
canonical bytes and signature bundles must verify with the release identity. A
release run holds one workflow concurrency group from its first job to its
last, so two release runs cannot interleave their checks and pushes, and
queued release runs are retained instead of canceled. Ordinary push and pull
request runs cancel their superseded predecessors per ref. `latest` cannot move
until both the container channels and PyPI have succeeded, so a partial
failure leaves the previous release as the default. The PyPI job refuses to
publish when freshly built artifacts differ from files PyPI already serves;
the wheel is byte-reproducible, the sdist is not. These are resume
guarantees, not transactions: artifacts published before a failure stay
published. Never amend or force-push a released commit or tag: correct
forward with a new commit and, when needed, a new patch release.

## The `v3` major tag

`uses: craevidence/cli@v3` resolves through the mutable `v3` tag. It always
points at the latest `v3.x` release commit, never at `main`.

- Creation and every later move: verify the target release tag and commit
  first, then update only `refs/tags/v3`
  (`git tag -f v3 <release-commit> && git push --force origin refs/tags/v3`),
  then re-read the remote tag and confirm it points at the intended commit.
- Moving `v3` is the one documented exception to the no-force-push rule, and
  it applies to `refs/tags/v3` only.

## Retro-signed images

The Docker Hub and Quay copies of releases published before per-registry
signing carry post-hoc signatures created by the manually dispatched,
approval-gated workflow in `.github/workflows/retro-sign.yml`. Verify those
with the identity
`https://github.com/craevidence/cli/.github/workflows/retro-sign.yml@refs/heads/main`
instead of a release tag identity.
