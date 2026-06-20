# Contributing

Thanks for your interest in improving the CRA Evidence CLI.

## Getting started

- Python 3.12 or newer.
- Install with the dev extras:

  ```bash
  pip install -e ".[dev]"
  ```

- Run the test suite:

  ```bash
  pytest
  ```

- Lint, format, and type-check:

  ```bash
  ruff check .
  black --check .
  mypy cra_evidence_cli
  ```

## Pull requests

- Keep each pull request focused on a single topic.
- Add or update tests for any change in behaviour.
- Make sure `pytest`, `ruff`, and `mypy` pass before opening the pull request.
- Write commit messages using [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Releases and changelog

Release notes are published on the [GitHub Releases](https://github.com/craevidence/cli/releases)
page. That page is the canonical changelog.

## Reporting bugs and requesting features

Open an issue using the provided templates. For security issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
