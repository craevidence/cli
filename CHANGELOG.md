# Changelog

All notable changes to the CRA Evidence CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Release pipeline: registry reads and cross-registry copies use a pinned
  crane binary through a fail-closed classifier, the cosign version is pinned
  explicitly, and the post-publish PyPI check verifies exactly the two
  released distributions by name and hash.

## [3.8.1] - 2026-07-18

Completes the 3.8.0 release across all distribution channels with a more
reliable publishing pipeline. Functionally identical to 3.8.0; see that entry
for the bundled tool and base image updates.

### Fixed

- Reliability of release publishing across the container registries.

## [3.8.0] - 2026-07-17

### Added

- `docs/releasing.md`: maintainer reference for the release process, channel
  verification, the mutable `v3` tag procedure, and the support policy
  (latest minor release line only).

### Changed

- Bundled Syft updated to 1.48.0 and Grype to 0.116.0 everywhere the tools are
  pinned: the Docker image, the GitHub Action, the GitLab CI component, the
  Codespaces setup, the demo workflow, and the Syft fallback container image.
  Scan output can change across this update: Grype 0.116.0 deduplicates
  advisory aliases, filters Go compiler-only CVEs, and applies reachability
  filtering to Go modules, so the same input may report findings under
  different advisory identifiers than 0.115.0 did.
- Docker Hardened Images base digests refreshed to the current
  `python:3.14-dev` and `python:3.14` builds.

### Security

- The CI image vulnerability gate now runs through
  `scripts/check-image-gate.sh`, which pins Grype 0.116.0 by checksum, updates
  the vulnerability database before scanning, and fails closed on any
  download, checksum, or database error. The same script serves as the local
  pre-push gate, so CI and local checks run the same pinned scanner, flags,
  and database refresh policy; results can still differ between runs when the
  vulnerability database changes in between.
- `.github/grype.yaml` now holds only reviewed waivers for fixed findings at
  High or Critical severity; fixed findings below that threshold stay visible
  in the gate output, and findings without a published fix moved to the new
  `.github/grype-watchlist.yaml` inventory, where a future fix release
  surfaces them through the gate instead of staying hidden behind a
  suppression.
- Release, main, and manually dispatched builds fail closed when the DHI
  registry login fails, instead of silently building from public fallback
  base images under hardened-image labels. Pull requests keep the fallback
  build, and their vulnerability scan becomes informational when DHI
  credentials are unavailable.
- Image labels record the base image actually used: fallback builds no longer
  claim `eu.cra.security.hardened`, `no-shell`, or `no-package-manager`, and
  CI asserts every security label plus the actual shell and package-manager
  surface for both variants. The documented fallback build commands pass the
  label overrides.
- `scripts/check-dhi-base.sh` gains a `--strict` mode that classifies every
  registry operation's failure (authentication, network, unresolvable tag,
  removed digest, moved tag) instead of skipping on registry errors. Publishing builds verify in CI
  that the pinned DHI digests are still the current tag digests before
  building; the lenient default for contributors is unchanged.

- Releases now publish one canonical multi-arch image: built once, pushed to
  GHCR, and copied to Docker Hub and Quay by digest, so all three registries
  serve the identical content-addressed artifact. The release verifies digest
  equality on every registry, signs each registry's copy of that digest, and
  verifies every signature against the exact release workflow identity before
  the `latest` tags move. All three registries are required channels; a
  failing registry fails the release run instead of continuing without it.
  Release reruns reuse the digest already published under the version tag
  instead of rebuilding, refuse to act when a registry's state cannot be
  determined or a published version tag differs, upload only release assets
  that are not attached yet, and resubmit the published SBOM bytes to CRA
  Evidence after verifying the canonical digest is the SBOM's subject. When
  PyPI already serves the complete file set, a rerun recovers those bytes
  instead of rebuilding, and retained release assets are verified before
  being kept: distributions against the canonical bytes, signature bundles
  against the release identity. A release run holds one workflow concurrency
  group from start to finish, so two release runs cannot interleave; a
  running release run is never canceled, and superseded push and pull
  request runs are canceled per ref. Previously the
  Docker Hub and Quay images were separate builds signed with the GHCR
  digest, so their published tags carried no valid signature.
- The release tag is validated against the package version in a read-only
  job before any publishing job starts, and the `latest` tags move in a
  final approval-gated job only after both the container registries and
  PyPI have published successfully.
- The GitLab CI templates install a version-pinned CLI wheel verified by
  checksum instead of a floating, caller-overridable pip package spec; the
  `cli-package` input is removed. The Sigstore OIDC token moved out of the
  base upload template into the new `.cra-evidence-upload-signed` variant, so
  jobs that never sign no longer receive a signing token. The component
  documentation now describes masking, protecting, and environment-scoping
  the `CRA_EVIDENCE_API_KEY` variable.
- Registry publishing, image signing, and evidence upload moved into a
  release-only job behind the approval-protected release-images environment,
  holding the only registry-push and OIDC permissions in the workflow; pull
  request and main builds now run with read-only repository permissions.
- Release SBOMs are digest-bound: two per-platform SBOMs are generated from
  the canonical released image digests, attached to the GitHub release, and
  the linux/amd64 one is uploaded to CRA Evidence as a required release step
  instead of a best-effort one. The single-architecture CI scan SBOM remains
  a workflow artifact only.
- Release reruns can no longer diverge the published channels: the PyPI
  publish job pins its build tools, refuses to proceed when freshly built
  artifacts differ from files PyPI already serves for the version, and
  verifies after publishing that PyPI serves exactly the built artifacts
  with matching hashes. Wheel builds pin the build frontend and backend and
  use a fixed source date epoch, so the wheel builds to identical bytes
  everywhere, and the release checks the built wheel against the version and
  checksum pinned in the GitLab component before publishing. The CI opengrep
  download is verified against pinned checksums before it runs.
- A manually dispatched workflow, gated by an approval-protected environment,
  retro-signs the Docker Hub and Quay copies of releases 3.6.0, 3.6.1, and
  3.7.0 at their audited digests. These post-hoc signatures carry the
  workflow's main-branch identity rather than a release tag identity, as
  documented in the workflow file.

### Fixed

- The PyPI project page's Documentation link points at the public command
  reference on GitHub instead of a page that requires signing in.
- The Docker installation guide no longer describes the public-base fallback
  image as functionally identical to the hardened image; the fallback keeps
  the CLI functionality but includes a shell and a package manager.

## [3.7.0] - 2026-07-11

### Added

- `code-check` command (alias `sast`) to scan first-party source code for
  potential security weaknesses using Opengrep. Advisory by default with a
  `--fail-on` gate (exit 27). Ships a bundled MIT rule pack for Python,
  JavaScript/TypeScript, and Go covering SQL injection (structural and intrafile
  taint), OS command injection (structural and intrafile taint), code injection
  via `eval`/`exec`, unsafe deserialization, weak hashes, disabled TLS
  verification, HMAC timing side-channels, HMAC shared-hash misuse, integer
  downcast after a 64-bit parse, and mismatched mutex lock/unlock (the Go rules
  are adapted from dgryski/semgrep-go, MIT). Detects the engine on `PATH` and
  never bundles or downloads it; results upload to CRA Evidence only with an
  explicit `--upload`.
- Framework rules for the bundled `code-check` pack (Python), authored from CWE,
  OWASP, and framework documentation, each with an engine-proven fixture. Flask:
  server-side template injection, `send_file` path traversal, open redirect,
  debug mode, hardcoded `SECRET_KEY`, insecure session cookies, permissive CORS
  with credentials, disabled CSRF, `Markup` XSS, plaintext password comparison,
  and whole-object request reflection. Django: raw SQL via
  `raw()`/`RawSQL`/`.extra()`, `mark_safe`/`format_html` XSS, `HttpResponse`
  body, open redirect, file path traversal, pickle signing, `csrf_exempt`, and
  settings hardening. SQLAlchemy: interpolated
  `text()`/`exec_driver_sql()`/`literal_column()`/`order_by()`. JWT: signature
  verification disabled, the `none` algorithm, a missing `algorithms` allowlist,
  and hardcoded keys.
- `config-check`: flag Dockerfile `ARG`/`ENV` whose name matches a credential-like
  pattern (`dockerfile-secret-arg`), and three GitHub Actions workflow checks:
  untrusted event data interpolated into shell steps (`workflow-script-injection`),
  the `pull_request_target` trigger (`workflow-pull-request-target`), and deprecated
  `::set-output`/`::save-state` commands (`workflow-set-output-deprecated`).
  Workflow files under `.github/workflows` are now scanned; other dotdirs remain
  skipped.
- The GitHub Action warns when an upload runs on a branch ref with the branch
  name as the version, since SBOM, HBOM, and document uploads create that
  version record. Branch names such as `main` get a second warning that the
  default environment rules classify them as production. The CI/CD guide now
  documents the split between branch check jobs and release upload jobs.

### Changed

- Updated the container base images to the current Docker Hardened Images
  digests.

## [3.6.1] - 2026-07-06

### Changed

- Build the published container image on the Docker Hardened Images base.

## [3.6.0] - 2026-07-06

### Added

- `assessment` command to build and check a local CRA Annex I applicability
  assessment. No API key required.
- `.cra/evidence.yaml` repository identity file.

### Changed

- Updated the container base image, bundled Syft 1.46.0 and Grype 0.115.0, and
  refreshed the Grype vulnerability suppressions.
- Narrowed the scope of the local secrets history scan.

### Fixed

- Return a clear error message when the API cannot be reached, instead of
  surfacing an unhandled network exception.

_The public release history starts at 3.6.0. Earlier versions were internal
development builds and are not itemized._

[Unreleased]: https://github.com/craevidence/cli/compare/v3.8.1...HEAD
[3.8.1]: https://github.com/craevidence/cli/compare/v3.8.0...v3.8.1
[3.8.0]: https://github.com/craevidence/cli/compare/v3.7.0...v3.8.0
[3.7.0]: https://github.com/craevidence/cli/compare/v3.6.1...v3.7.0
[3.6.1]: https://github.com/craevidence/cli/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/craevidence/cli/releases/tag/v3.6.0
