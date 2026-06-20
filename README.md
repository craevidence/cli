# CRA Evidence CLI

Command-line tool for CI/CD integration with [CRA Evidence](https://craevidence.com), helping manufacturers meet EU Cyber Resilience Act requirements.

![Running craevidence check on an SBOM: a local security snapshot that matches with Grype and enriches with CISA KEV and FIRST EPSS, gating CI on known-exploited CVEs with exit code 17.](docs/demo.gif)

Try it live in your browser, no install required:
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/craevidence/cli)

## Local Security Check (no account)

`craevidence check` scans a project directory, a container image, or an existing SBOM for known
vulnerabilities and prints a local security snapshot: **no account and no API key.**
It never contacts CRA Evidence. It uses the network for vulnerability data: it matches
with Grype when Grype is installed (which may download or update the Grype database), falls back to
OSV.dev when Grype is unavailable, and consults CISA KEV and FIRST EPSS for enrichment.
It generates the SBOM for you with [Syft](https://github.com/anchore/syft),
matches vulnerabilities with [Grype](https://github.com/anchore/grype) (used automatically when
installed)
or the free [OSV.dev](https://osv.dev) database, and flags **known-exploited** CVEs ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog))
and exploit probability ([FIRST EPSS](https://www.first.org/epss/)).

It is deliberately honest: it never claims "compliant," the machine report carries detailed
review metadata, and verbose output shows **what a local snapshot cannot tell you**.

Where it earns its place in a developer's workflow:

- Drop it into CI as a real gate: pick a threshold with `--fail-on` and the build stops on its own.
- Mute the false positives you've already triaged with a `--vex` file, before the gate runs.
- Commit a `.cra/check.yaml` once and every run and every teammate share the same gates and ignore list.
- Findings land inline on the pull or merge request with `--annotations github|gitlab`.
- Only the vulnerabilities that are new since `--baseline` block you, so an old backlog doesn't.
- Hand the same run to other tools with `--output sarif|json` (code scanning, dashboards) and keep the SBOM via `--sbom-output`.

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

**Example output:**

```text
Local SBOM Check

Summary
Components: 2 | Vulnerabilities: 8 (critical=0, high=0, medium=8) | Known-exploited: 0

Top actions
- requests 2.20.0: upgrade to 2.31.0
- jinja2 3.1.3: upgrade to 3.1.4

Reviewed dimensions
- Needs Review:    SBOM exists and is machine-readable
- Action required: Known vulnerability snapshot
- Action required: Remediation information
- Needs Review:    Third-party component inventory

What this local snapshot cannot tell you
- Intended purpose, foreseeable misuse, and CRA product classification.
- Whether the product risk assessment has been completed and approved.
- Whether technical file review or sign-off has been completed.
  ...

Data provenance and source credits: see --output json and the README.

Exit 0 means no configured blocking findings in this local snapshot.
```

Each dimension carries a plain-English message and its exact CRA citation ids in the
`--output json` report; the human summary stays uncluttered.

By default the check uses the network: Grype matches against its vulnerability database (updating it
when online), or OSV.dev is queried as a fallback when Grype is not installed, with CISA KEV and FIRST
EPSS consulted for enrichment.
Add `--output json|sarif|markdown` for machine-readable CI output, and `--baseline previous.json` to
show what changed since the last run. See [Local commands](docs/local-commands.md#check) for the full
flag and exit-code reference.

**What an account adds** (the `check` command does not require one): trend across
versions, vulnerability **reachability**, VEX lifecycle, attestation tracking, and
notified-body / technical-file export. The local check is an honest snapshot; the platform is the
system of record.

## Free commands (no account, no API key)

Everything below runs fully client-side. No CRA Evidence account, no API key, no upload.
Full flags, output, and CRA citations for each are in [docs/local-commands.md](docs/local-commands.md).

| Command | What it does |
|---|---|
| [`check`](docs/local-commands.md#check) | Scan a directory, image, or SBOM and print a local security summary; gate CI with `--fail-on`. |
| [`eol-check`](docs/local-commands.md#eol-check) | Flag end-of-life and support status of SBOM components (endoflife.date). |
| [`egress-check`](docs/local-commands.md#egress-check) | Inventory external interfaces and data-egress indicators in code and dependencies. |
| [`secrets-check`](docs/local-commands.md#secrets-check) | Scan the working tree for candidate hard-coded secrets. |
| [`config-check`](docs/local-commands.md#config-check) | Audit Dockerfile / Terraform / Kubernetes config for insecure defaults. |
| [`draft`](docs/local-commands.md#draft) | Scaffold VEX, security.txt, advisory, risk-assessment, and threat-model drafts for manual completion. |
| [`compliance-as-code template --offline`](docs/local-commands.md#compliance-as-code-template---offline) | Build a starter compliance YAML (risk/threat/policy) locally from an SBOM. |
| [`db update`](docs/local-commands.md#db-update) / [`db status`](docs/local-commands.md#db-status) | Manage and inspect the local Grype vulnerability database cache. |
| [`version`](docs/local-commands.md#version) | Show CLI version information. |

## See it in action

Every command below runs locally with no account and no API key.

**End-of-life and support status** (`eol-check`):

![craevidence eol-check flags components past end-of-life and without a known support cycle.](docs/demo-eol-check.gif)

**Insecure-default config audit** (`config-check`):

![craevidence config-check flags a Dockerfile that fetches a remote URL and runs as root.](docs/demo-config-check.gif)

**Scaffold a risk catalog, offline** (`compliance-as-code template`):

![craevidence compliance-as-code template builds a starter risk catalog YAML from an SBOM with no network.](docs/demo-scaffold.gif)

## Use it as a CI gate (free)

The local `check` gate needs no account and no API key: install the CLI and fail the build on a
threshold you choose.

```yaml
# GitHub Actions: .github/workflows/cra-check.yml (no API key)
jobs:
  cra-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pipx install craevidence
      - run: craevidence check . --fail-on known-exploited
```

```yaml
# GitLab CI (no API key)
cra-check:
  image: python:3.12-slim
  script:
    - pip install craevidence
    - craevidence check . --fail-on known-exploited
```

The packaged GitHub Action and GitLab Component (which also upload evidence with an API key), plus
Docker, Jenkins, OpenSSF Scorecard, and complyctl integrations, are in [docs/ci-cd.md](docs/ci-cd.md).

## With a CRA Evidence account (API key)

These commands talk to the CRA Evidence API and need `CRA_EVIDENCE_API_KEY` (or OIDC in GitHub
Actions). Full reference: [docs/account-commands.md](docs/account-commands.md).

| Area | Commands |
|---|---|
| Upload evidence | [`upload-sbom`](docs/account-commands.md#upload-sbom), `upload-hbom`, `upload-vex`, `upload-sarif`, `upload-attestation`, `upload-document`, `upload-diagram` |
| Scan & status | [`scan`](docs/account-commands.md#scan), `status`, `maturity`, `wait-ready` |
| Release lifecycle | [`release`](docs/account-commands.md#release), `export`, `compare` |
| Distributor & profile | [`distributor`](docs/account-commands.md#distributor), `setup-profile`, `show-profile`, `evidence` |
| Validation & verification | [`validate`](docs/account-commands.md#validate), `verify run`, `compliance-as-code` upload |

## Install

```bash
pip install craevidence                     # PyPI
pipx install craevidence                    # PyPI, isolated (recommended for a CLI)
brew install craevidence/tap/craevidence    # Homebrew (via tap)
docker run --rm craevidence/cli:latest --help   # Docker (Syft bundled)
```

Container registries, building from source, and SBOM generation from Docker images are covered in
[docs/installation.md](docs/installation.md).

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `CRA_EVIDENCE_API_KEY` | API key for authentication | (required) |
| `CRA_EVIDENCE_URL` | CRA Evidence base URL | `https://api.craevidence.com` |
| `CRA_EVIDENCE_ORG` | Default organization slug | (optional) |
| `CRA_EVIDENCE_TIMEOUT` | Request timeout in seconds | `60` |

### Config File

Location: `~/.cra-evidence/config.yaml`

```yaml
# API configuration
api_key: cra_key_xxx
url: https://api.craevidence.com

# Default organization (optional)
default_org: my-org

# Output preferences (optional)
output_format: json

# HTTP settings (optional)
timeout: 60
```

> **Security note:** `chmod 600 ~/.cra-evidence/config.yaml` so no other user on the system can read your API key.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error |
| 2 | Authentication error |
| 3 | API error |
| 4 | Validation error |
| 5 | File not found |
| 6 | Configuration error |
| 7 | security.txt validation found errors (`draft security.txt --validate --fail-on-invalid`) |
| 10 | Critical vulnerabilities found (`--fail-on critical`) |
| 11 | High vulnerabilities found (`--fail-on high`) |
| 12 | Medium vulnerabilities found (`--fail-on medium`) |
| 13 | Low vulnerabilities found (`--fail-on low`) |
| 14 | SBOM quality score below `--fail-on-score` threshold |
| 15 | Local scan engine unavailable for no-key `check` |
| 16 | License policy threshold exceeded |
| 17 | Known-exploited vulnerabilities found (`check --fail-on known-exploited`) |
| 18 | Candidate secrets found (`secrets-check --fail-on-match`) |
| 19 | Insecure-default config findings (`config-check --fail-on-match`) |
| 20 | CRA status is not `ready` when `--fail-on` is set to anything other than `none` |
| 21 | Structured evidence mapping was required but the upload did not populate mapped fields |
| 22 | SBOM signature trust required but verification was not trusted |
| 23 | SBOM signing failed or no Sigstore OIDC identity was available |
| 24 | CRA legal floor is met but the organisation's release policy is not (`--fail-on` set) |

## Documentation

- [Local commands (no account)](docs/local-commands.md)
- [Account commands (API key)](docs/account-commands.md)
- [CI/CD integration](docs/ci-cd.md)
- [Installation](docs/installation.md)
- [Troubleshooting](docs/troubleshooting.md)

## Credits and data sources

The local check builds on open data and tooling, credited here rather than in every run's output:

- [Grype](https://github.com/anchore/grype) and [Syft](https://github.com/anchore/syft), Apache-2.0 projects from Anchore, for vulnerability matching and SBOM generation.
- [OSV.dev](https://osv.dev) for the no-Grype fallback; OSV records retain their originating database licenses.
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CC0 public-domain data) for known-exploited flags.
- [FIRST EPSS](https://www.first.org/epss/) for exploit-probability scores; EPSS data is provided by FIRST.org.

## Support

- Documentation: https://docs.craevidence.com/cli
- Issues: https://github.com/craevidence/cli/issues
- Email: support@craevidence.com

## License

MIT License. See LICENSE file for details.
