# Changelog

All notable changes to the CRA Evidence CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

_Releases before 3.6.0 are not itemized in this file; see the Git tags for
earlier history._

[Unreleased]: https://github.com/craevidence/cli/compare/v3.6.0...HEAD
[3.6.0]: https://github.com/craevidence/cli/compare/v3.5.0...v3.6.0
