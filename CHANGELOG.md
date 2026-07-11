# Changelog

All notable changes to the CRA Evidence CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/craevidence/cli/compare/v3.7.0...HEAD
[3.7.0]: https://github.com/craevidence/cli/compare/v3.6.1...v3.7.0
[3.6.1]: https://github.com/craevidence/cli/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/craevidence/cli/releases/tag/v3.6.0
