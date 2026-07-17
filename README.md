# CRA Evidence CLI

[![PyPI](https://img.shields.io/pypi/v/craevidence)](https://pypi.org/project/craevidence/)
[![CI](https://github.com/craevidence/cli/actions/workflows/ci.yml/badge.svg)](https://github.com/craevidence/cli/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/craevidence/cli)](https://github.com/craevidence/cli/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://github.com/craevidence/cli/blob/main/docs/installation.md)
[![Docker pulls](https://img.shields.io/docker/pulls/craevidence/cli)](https://hub.docker.com/r/craevidence/cli)

Command-line tools for [CRA Evidence](https://craevidence.com) workflows and local software supply-chain checks.

![craevidence check scans an SBOM and gates CI on known-exploited vulnerabilities](https://raw.githubusercontent.com/craevidence/cli/main/docs/demo.gif)

The CLI has two modes:

- Local commands that run without a CRA Evidence account or API key.
- Account commands that upload evidence or read release state from CRA Evidence.

This page covers the public command basics. The full reference lives in
[docs/](https://github.com/craevidence/cli/blob/main/docs/README.md).
Registered CRA Evidence users can also sign in to view the command
documentation at https://docs.craevidence.com/cli.

The local checks are review aids and CI gates. They are not an audit, and
exit 0 does not prove compliance.

## Install

```bash
pip install craevidence
pipx install craevidence
```

`pipx` is a good fit for command-line tools because it installs the package in
an isolated environment.

The installed command is:

```bash
craevidence --help
```

Python 3.12 or newer is required. Docker images and other install options are
covered in the [installation guide](https://github.com/craevidence/cli/blob/main/docs/installation.md).

## Documentation

| Page | Contents |
|---|---|
| [Local commands](https://github.com/craevidence/cli/blob/main/docs/local-commands.md) | `check`, `eol-check`, `egress-check`, `secrets-check`, `config-check`, `code-check`, `draft`, `assessment`, `db`, and the offline template scaffold. |
| [Account commands](https://github.com/craevidence/cli/blob/main/docs/account-commands.md) | Uploads, scan, status, release lifecycle, distributor, profiles, validation, and verification. |
| [CI/CD integration](https://github.com/craevidence/cli/blob/main/docs/ci-cd.md) | GitHub Action, GitLab Component, Docker, Jenkins, OpenSSF Scorecard, and complyctl. |
| [Installation](https://github.com/craevidence/cli/blob/main/docs/installation.md) | PyPI, Docker, container registries, and from source. |
| [Troubleshooting](https://github.com/craevidence/cli/blob/main/docs/troubleshooting.md) | Common errors and fixes. |
| [Releasing](https://github.com/craevidence/cli/blob/main/docs/releasing.md) | Maintainer reference: channels, verification, tags, support policy. |

## Local Check

`craevidence check` scans a directory, container image, or existing SBOM and
reports known vulnerability signals that can block CI when a threshold is met.
It does not require an account and does not upload your project to CRA Evidence.

```bash
craevidence check .
craevidence check --image ghcr.io/acme/app:1.4.2
craevidence check --sbom sbom.cdx.json
craevidence check . --fail-on known-exploited
```

By default, `check` uses network data sources. It uses Grype when installed
and working, falls back to OSV.dev when Grype is absent or fails, and consults
CISA KEV plus FIRST EPSS for enrichment. For a network-restricted run, provide
an SBOM with `--sbom` and run where Grype has a local database; CISA KEV and
FIRST EPSS enrichment are reported as unavailable if they cannot be reached.

Verbose output includes a section named **What this local snapshot cannot tell
you**. The JSON output keeps the same review context in machine-readable form.

## Free Commands

These commands do not need `CRA_EVIDENCE_API_KEY`:

| Command | Purpose |
|---|---|
| `check` | Scan a directory, image, or SBOM and gate CI with `--fail-on`. |
| `eol-check` | Flag end-of-life and support status from local SBOM components. |
| `egress-check` | Inventory external interfaces and data-egress indicators. |
| `secrets-check` | Scan the working tree for candidate hard-coded secrets. |
| `config-check` | Audit Dockerfile, Terraform, and Kubernetes files for insecure defaults. |
| `code-check` | Scan source code for potential security weaknesses using Opengrep (requires separate install). |
| `draft` | Scaffold VEX, security.txt, advisory, risk-assessment, and threat-model drafts for review. |
| `compliance-as-code template --offline` | Create starter YAML from local input without an API key. |
| `assessment` | Scaffold an Annex I applicability matrix and gate CI on structured gaps. |
| `db update` / `db status` | Manage and inspect the local Grype vulnerability database cache. |

## CI Examples

GitHub Actions:

```yaml
jobs:
  cra-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install craevidence
      - run: craevidence check . --fail-on known-exploited
```

GitLab CI:

```yaml
cra-check:
  image: python:3.12-slim
  script:
    - pip install craevidence
    - craevidence check . --fail-on known-exploited
```

## Account Commands

Commands that upload evidence or read CRA Evidence release state need an API key:

```bash
export CRA_EVIDENCE_API_KEY=...
craevidence upload-sbom --product my-product --version 1.0.0 --file sbom.cdx.json
craevidence status --product my-product --version 1.0.0
```

The default API URL is:

```text
https://api.craevidence.com
```

You can override it with:

```bash
export CRA_EVIDENCE_URL=https://api.craevidence.com
```

## Environment Variables

| Variable | Purpose |
|---|---|
| `CRA_EVIDENCE_API_KEY` | API key for account commands. |
| `CRA_EVIDENCE_URL` | CRA Evidence API URL. Defaults to `https://api.craevidence.com`. |
| `CRA_EVIDENCE_ORG` | Default organization slug. |
| `CRA_EVIDENCE_PRODUCT` | Default product slug for upload commands. |
| `CRA_EVIDENCE_VERSION` | Default product version for upload commands. |
| `CRA_EVIDENCE_COMPONENT` | Default component slug for component-aware uploads. |
| `CRA_EVIDENCE_COMPONENT_VERSION` | Default component release version. |
| `CRA_EVIDENCE_TIMEOUT` | HTTP request timeout in seconds for account commands. Defaults to `60`. |
| `CRA_NO_WARN` | Set to any value to suppress API URL configuration warnings. |

Credentials can also be stored in `~/.cra-evidence/config.yaml`. Keep that file
private, for example with `chmod 600 ~/.cra-evidence/config.yaml`.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success. For local gates, no configured blocking finding was present in this local snapshot. |
| 1 | General error. |
| 2 | Authentication error. |
| 3 | API error. |
| 4 | Validation error. |
| 5 | File not found. |
| 6 | Configuration error. |
| 7 | security.txt validation failed. |
| 10 | Critical vulnerabilities found. |
| 11 | High vulnerabilities found. |
| 12 | Medium vulnerabilities found. |
| 13 | Low vulnerabilities found. |
| 14 | SBOM quality score below the configured threshold. |
| 15 | Local scan engine unavailable. |
| 16 | License policy threshold exceeded. |
| 17 | Known-exploited vulnerabilities found. |
| 18 | Candidate secrets found. |
| 19 | Insecure-default config findings found. |
| 20 | CRA status is not ready when a status gate is enabled. |
| 21 | Structured evidence mapping was required but was not populated. |
| 22 | SBOM signature trust was required but verification was not trusted. |
| 23 | SBOM signing failed or no Sigstore OIDC identity was available. |
| 24 | CRA legal floor is met but the configured release policy is not. |
| 25 | Mandatory Annex I requirement is not addressed. |
| 26 | Annex I Part I(2) requirement is marked not-applicable without a justification. |

Exit 0 != compliance. Local output is a snapshot for review and CI policy, not
a legal conclusion.

## Data Sources

| Source | Use |
|---|---|
| FIRST EPSS | Exploit-probability enrichment. |
| CISA KEV | Known-exploited vulnerability enrichment. |
| OSV.dev | Open source vulnerability data when the OSV path is used. |
| Anchore Grype | Local vulnerability matching when installed. |
| Anchore Syft | SBOM generation from directories and images when installed or included in the Docker image. |
| endoflife.date | End-of-life and support-cycle data for `eol-check`. |

## Support

- Website: https://craevidence.com
- Email: support@craevidence.com

## License

MIT License. See the package license file for details.
