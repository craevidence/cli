# Account commands (require an API key)

The commands below talk to the CRA Evidence API, so they need a
`CRA_EVIDENCE_API_KEY` (or an OIDC identity in GitHub Actions). They are
separate from the no-account `craevidence check` local security check. Set your
key as described under Authentication, then use any command below.

Back to the [README](../README.md).

## Authentication

The CLI supports four authentication methods. They are evaluated in the
following precedence order (highest wins):

1. **Command-line flags** (highest priority):

   ```bash
   craevidence --api-key cra_key_xxx --url https://api.craevidence.com upload-sbom ...
   ```

2. **Environment variables** (recommended for CI/CD):

   ```bash
   export CRA_EVIDENCE_API_KEY=cra_key_xxx
   export CRA_EVIDENCE_URL=https://api.craevidence.com
   ```

3. **Config file** (`~/.cra-evidence/config.yaml`):

   ```yaml
   api_key: cra_key_xxx
   url: https://api.craevidence.com
   default_org: my-org
   ```

   > **Security note:** Restrict config file permissions so only your user can read it: `chmod 600 ~/.cra-evidence/config.yaml`

4. **OIDC identity** (GitHub Actions only):

   Pass `--oidc` as a global flag. The CLI exchanges the GitHub Actions OIDC
   token (audience `https://github.com/craevidence`) for a short-lived access
   token that works for all commands in the session. The job needs:

   ```yaml
   permissions:
     id-token: write
     contents: read
   ```

   `--oidc` can be combined with `--sign` for signed-SBOM uploads (which also
   requires `id-token: write`), but it is not limited to upload commands. Use
   it whenever you want keyless authentication from a GitHub Actions workflow.

### Global `--output` option

`--api-key`, `--url`, `--oidc`, and `--output` are **global options** and must
appear **before** the subcommand name. The output format option (`--output
json|text|sarif|markdown`) controls the format for the following subcommand.

```bash
craevidence --output json status --product my-app --version 1.0
craevidence --output sarif check --sbom sbom.json
```

The per-command reference sections below omit `--output` from their synopses;
use the global placement shown above.

### Product and version identity resolution

Most commands accept `--product` and `--version` flags. When those flags are
omitted, the CLI resolves them from the following sources in order (highest
wins):

1. Explicit `--product` / `--version` / `--component` flag
2. `CRA_EVIDENCE_PRODUCT` / `CRA_EVIDENCE_VERSION` / `CRA_EVIDENCE_COMPONENT`
   environment variables
3. `.cra/evidence.yaml` in the working directory (or any parent directory)

The README contains the full `.cra/evidence.yaml` reference.

### Upload an SBOM

```bash
# Upload an existing SBOM file
craevidence upload-sbom \
  --product my-product \
  --version 1.2.3 \
  --file sbom.json

# Generate an SBOM from a Docker image and upload (requires Syft)
craevidence upload-sbom \
  --product my-product \
  --version 1.2.3 \
  --image nginx:latest

# Upload, scan, and fail the pipeline on high vulnerabilities
# (--fail-on requires --scan; polls until the scan completes)
craevidence upload-sbom \
  --product my-product \
  --version 1.2.3 \
  --file sbom.json \
  --scan \
  --fail-on high

# Product and version are created automatically by default.
# New products require target markets. Use --no-create-product or
# --no-create-version to disable auto-creation.
craevidence upload-sbom \
  --product my-new-product \
  --version 1.0.0 \
  --file sbom.json \
  --target-markets DE,FR,ES

craevidence upload-sbom \
  --product existing-product \
  --version 1.0.0 \
  --file sbom.json \
  --no-create-product \
  --no-create-version
```

## `upload-sbom`

Upload a Software Bill of Materials. Accepts an existing SBOM file or generates one from a Docker image via Syft.

```
craevidence upload-sbom
  --product <slug-or-id>
  --version <version-number>
  --file <path>              # Upload existing file (mutually exclusive with --image, --source)
  --image <docker-image>     # Generate SBOM from image (requires Syft)
  --source <directory>       # Generate SBOM from source directory (requires Syft)
  [--format cyclonedx|spdx]  # SBOM format for Syft generation (default: cyclonedx). Ignored when uploading with --file.
  [--component <slug>]       # Component slug for multi-repo products
  [--no-create-product]      # Disable auto-creation of product (creation is on by default)
  [--no-create-version]      # Disable auto-creation of version (creation is on by default)
  [--target-markets DE,FR]   # Required when auto-creating a product
  [--scan]                   # Trigger vulnerability scan after upload
  [--fail-on critical|high|medium|low]  # Require --scan; polls until scan completes (default wait: 300s)
  [--scan-timeout <seconds>] # Max seconds to wait for scan completion when --fail-on is set (default: 300, min: 1)
  [--sign]                   # Create a Sigstore bundle before upload, then verify it
  [--signature-on]            # Verify <SBOM>.sigstore.json using signer policy from env vars
  [--signature-bundle <path>] # Verify Sigstore bundle after upload
  [--signature-identity <id>] # Expected signer identity for trusted verification
  [--signature-issuer <url>]  # Expected OIDC issuer for trusted verification
  [--fail-untrusted]          # Exit 22 unless signature verification is trusted
  [--sbomqs-check]           # Pre-upload BSI TR-03183-2 v2 score via sbomqs binary
  [--fail-on-score <0-100>]  # Exit 14 if sbomqs score is below this threshold (requires --sbomqs-check)
  [--supersedes <version>]   # Version superseded by this upload (archives the old version)
  [--kernel-config <path>]   # Linux kernel .config for CVE filtering
  [--firmware <path>]        # Firmware binary to extract embedded kernel .config from
  # CRA classification
  [--category default|important_class_i|important_class_ii|critical]
  [--subcategory <value>]    # CRA Annex III/IV subcategory; auto-derives --category
  [--product-type software|hardware|mixed]
  [--cra-role manufacturer|importer|distributor]
  [--product-group <name>]   # Assign to a product group
  # CI metadata (auto-detected in most CI environments)
  [--commit <sha>]
  [--branch <name>]
  [--pipeline-id <id>]
  [--repository <url-or-name>]
  [--repo-path <subdir>]     # Monorepo subdirectory
  [--no-ci-detect]           # Disable automatic CI environment detection
  # Version metadata
  [--environment production|staging|development|testing]
  [--tags <comma-separated>] # Arbitrary metadata tags
  # Upload metadata (release_notes, release_date, external_url only applied on version creation)
  [--release-notes <text>]
  [--release-date <YYYY-MM-DD>]
  [--external-url <url>]
  [--release-state draft|pending_review|approved|released|deprecated|end_of_life]
  [--no-inherit]             # Do not inherit compliance artifacts from previous version
```

**`--fail-on` requires `--scan`.** Using `--fail-on` without `--scan` is a usage
error (exit 2). When both are set, the command waits for the asynchronous
server-side scan to finish (polling every 5 seconds) before evaluating the gate.
Use `--scan-timeout` to adjust the maximum wait (default 300 seconds, minimum 1).
On timeout the command exits 3 with a message indicating the last scan state.

Exit codes when `--fail-on` is set:

| Code | Meaning |
|------|---------|
| 0 | No threshold exceeded |
| 3 | Scan failed, scan disabled, or scan timed out |
| 10 | Critical vulnerabilities found |
| 11 | High vulnerabilities found |
| 12 | Medium vulnerabilities found |
| 13 | Low vulnerabilities found |

`--release-state` on upload is a lifecycle shortcut. It is not a CRA-readiness
gate and does not prove the version is compliant. CRA Evidence applies the same
lifecycle transition validation as the dedicated `release-state` command.

Signed SBOM evidence is optional. The easiest path is to let the CLI create the
Sigstore bundle from the CI job's OIDC identity, then let CRA Evidence verify
that bundle against the stored SBOM bytes:

```bash
craevidence upload-sbom \
  --product my-product \
  --version 1.2.3 \
  --file sbom.json \
  --sign
```

In GitHub Actions, the signing step also needs `id-token: write` (same
permission required for `--oidc`; see the Authentication section above).

The CLI uses the current Sigstore signer identity from the created certificate
when no explicit policy is supplied. That creates signed evidence, but it is not
a pinned release gate. For `--fail-untrusted`, pin the expected signer policy:

```bash
export CRA_EVIDENCE_SIGNATURE_IDENTITY="https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main"
export CRA_EVIDENCE_SIGNATURE_ISSUER="https://token.actions.githubusercontent.com"

craevidence upload-sbom \
  --product my-product \
  --version 1.2.3 \
  --file sbom.json \
  --sign \
  --fail-untrusted
```

`--fail-untrusted` with `--sign` requires the explicit policy above. Run once
without `--fail-untrusted` to print the signer identity and issuer, then pin
those values in CI.

For CI systems that expose an OIDC token but are not detected automatically, set
`CRA_EVIDENCE_SIGSTORE_IDENTITY_TOKEN` or `SIGSTORE_ID_TOKEN` in the job
environment. Treat that value as sensitive.

Teams that already use Cosign can keep their existing signing step. In that
case, `--signature-on` expects the bundle next to the SBOM as
`<SBOM file>.sigstore.json`, for example `sbom.json.sigstore.json`. Use
`--signature-bundle` when the bundle has a different path. Use
`--signature-identity` and `--signature-issuer` when you need explicit policy
overrides; otherwise the same `CRA_EVIDENCE_SIGNATURE_*` environment variables
are used.

The two `CRA_EVIDENCE_SIGNATURE_*` values are not GitHub-only. Set them to the
identity and issuer that appear in the Sigstore certificate for your CI system
or signing identity. GitHub Actions commonly uses
`https://token.actions.githubusercontent.com`; GitLab, Buildkite, CircleCI, GCP,
or another OIDC-capable signer can use different issuer and identity values.
CRA Evidence checks the values you provide against the bundle; it does not
assume GitHub.

Signed SBOM verification performs a second API operation after upload:
CRA Evidence fetches the stored SBOM by the returned artifact id and verifies
the bundle over those exact bytes.

Use Cosign's `--new-bundle-format` flag. Cosign's legacy blob bundle shape
(`base64Signature`, `cert`, `rekorBundle`) is rejected by the verifier;
the supported Sigstore bundle shape includes `mediaType` and
`verificationMaterial`.

**JSON output example:**

```json
{
  "product": {"name": "my-product", "created": false},
  "version": {"number": "1.2.3", "created": true},
  "artifact_id": "uuid",
  "artifact_type": "sbom",
  "component_count": 142,
  "quality_score": 85,
  "scan_results": {
    "status": "completed",
    "vulnerabilities": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 12
    }
  },
  "cra_status": "incomplete",
  "cra_missing_items": ["EU Declaration of Conformity (CRA Art. 28)"]
}
```

When CRA Evidence returns `supplier_review`, the CLI shows supplier names found
in SBOM component metadata as review candidates. These names do not satisfy
supplier due diligence; upload `supplier_due_diligence` evidence or complete the
manual supplier review workflow where applicable.

### Optional BSI TR-03183-2 v2 pre-upload check (`--sbomqs-check`)

Opt-in score gate for German BSI / EU regulated procurement. When set, the CLI
shells to the [`sbomqs`](https://github.com/interlynk-io/sbomqs) binary, runs
`sbomqs score -c bsi-v2.0 --json`, prints the score (0-100) and the three
worst-scoring checks, then optionally fails the CI job when the score is below
`--fail-on-score N`. The check runs **before** the upload network call so a
failing score does not produce a server-side row.

`sbomqs` is not bundled in the CLI Docker image. Install it separately:

```bash
go install github.com/interlynk-io/sbomqs@latest
# or
brew install interlynk-io/interlynk/sbomqs
# or download a release from https://github.com/interlynk-io/sbomqs/releases
```

CI snippet (fails the job if the SBOM scores below 60/100):

```bash
craevidence upload-sbom \
  --product my-product --version 1.2.3 \
  --file sbom.cdx.json \
  --sbomqs-check --fail-on-score 60
```

Sample output (failing the threshold):

```
sbomqs bsi-v2.0: 47.9/100 (sbom.cdx.json, 107 components)
  worst: comp_with_supplier 0/10, comp_with_source_code_uri 0/10, comp_with_executable_uri 0/10
Error: sbomqs BSI TR-03183-2 v2 score 47.9 is below threshold 60.0
```

The sbomqs check covers ~10 BSI/CRA-relevant signals the platform's own
`quality_score` does not compute (per-component VCS/executable URIs and hashes,
dependency-graph completeness, SBOM authors / build-phase / bomlinks /
signature). It complements rather than duplicates the platform score.

## `upload-hbom`

Upload a Hardware Bill of Materials. Provide **either** an existing CycloneDX
HBOM with `--file`, **or** a components CSV with `--csv` (parsed and built into
a CycloneDX HBOM server-side). The two are mutually exclusive; exactly one is
required.

```
# Upload an existing CycloneDX HBOM JSON
craevidence upload-hbom --product my-product --version 1.2.3 --file hbom.json

# Build an HBOM from a components CSV (maintain parts.csv in your repo)
craevidence upload-hbom --product my-product --version 1.2.3 --csv parts.csv
```

The CSV uses the canonical HBOM schema (download the template from a version's
HBOM tab → **CSV template**, or `GET …/hboms/csv-template`). Only `name` is
required; per-component firmware is captured via the `firmware_version` /
`firmware_purl` / `has_firmware` / `firmware_updateable` columns. Invalid rows
are reported per-row and nothing is uploaded until they are fixed.

```
craevidence upload-hbom
  --product <slug-or-id>
  --version <version-number>
  (--file <path> | --csv <path>)   # exactly one; mutually exclusive
  [--no-create-product]      # Disable auto-creation of product (creation is on by default)
  [--no-create-version]      # Disable auto-creation of version (creation is on by default)
  # CRA classification
  [--category default|important_class_i|important_class_ii|critical]
  [--subcategory <value>]    # CRA Annex III/IV subcategory; auto-derives --category
  [--product-type software|hardware|mixed]
  [--cra-role manufacturer|importer|distributor]
  [--product-group <name>]   # Assign to a product group
  # CI metadata (auto-detected in most CI environments)
  [--commit <sha>]
  [--branch <name>]
  [--pipeline-id <id>]
  [--repository <url-or-name>]
  [--repo-path <subdir>]
  [--no-ci-detect]
  # Version metadata (applied on version creation only)
  [--release-notes <text>]
  [--release-date <YYYY-MM-DD>]
  [--external-url <url>]
  [--release-state draft|pending_review|approved|released|deprecated|end_of_life]
  [--environment production|staging|development|testing]
  [--tags <comma-separated>]
  [--no-inherit]
```

## `upload-vex`

Upload a VEX (Vulnerability Exploitability eXchange) document to CRA Evidence.

The product and version must already exist before uploading VEX; there are no
`--create-product` or `--create-version` flags on this command.

All CRA classification, CI metadata, and environment options listed below are
transmitted to the server when provided.

```
craevidence upload-vex
  --product <slug-or-id>
  --version <version-number>
  --file <path>
  # CRA classification
  [--category default|important_class_i|important_class_ii|critical]
  [--subcategory <value>]
  [--product-type software|hardware|mixed]
  [--cra-role manufacturer|importer|distributor]
  [--product-group <name>]
  # CI metadata (auto-detected in most CI environments)
  [--commit <sha>]
  [--branch <name>]
  [--pipeline-id <id>]
  [--repository <url-or-name>]
  [--repo-path <subdir>]
  [--no-ci-detect]
  [--environment production|staging|development|testing]
  [--tags <comma-separated>]
  [--no-inherit]
```

Text output includes a "Vulnerabilities" row with the count of VEX statements
in the uploaded file, plus any CRA status warnings returned by the server.

## `upload-sarif`

Upload SARIF security scan results to CRA Evidence. Supports SARIF 2.1.0 output from tools like CodeQL, Semgrep, Bandit, and govulncheck.

The product and version must already exist.

```
craevidence upload-sarif
  --product <slug-or-id>
  --version <version-number>
  --file <path>              # Path to SARIF file (.json or .sarif)
```

> **Note:** `upload-sarif` accepts only `--product`, `--version`, and `--file`.
> CI metadata, environment, tags, and classification options are not available
> on this command. Passing any removed option is a usage error (exit 2).

## `upload-attestation`

Upload DSSE/in-toto attestation metadata for an existing product version.

The product and version must already exist. This command does not auto-create
resources. The upload is stored as provenance metadata; it is not verified
provenance unless CRA Evidence returns `verification_status: "valid"`.

```
craevidence upload-attestation
  --product <slug-or-id>
  --version <version-number>
  --file <path>              # Path to DSSE/in-toto file (.json or .jsonl)
```

## `upload-document`

Upload a supporting compliance document (e.g. test report, declaration of conformity).

```
craevidence upload-document
  --product <slug-or-id>
  --version <version-number>
  --file <path>
  --type <document-type>
  [--no-create-product]      # Disable auto-creation of product (creation is on by default)
  [--no-create-version]      # Disable auto-creation of version (creation is on by default)
  # CRA classification
  [--category default|important_class_i|important_class_ii|critical]
  [--subcategory <value>]
  [--product-type software|hardware|mixed]
  [--cra-role manufacturer|importer|distributor]
  [--product-group <name>]
  # CI metadata (auto-detected in most CI environments)
  [--commit <sha>]
  [--branch <name>]
  [--pipeline-id <id>]
  [--repository <url-or-name>]
  [--repo-path <subdir>]
  [--no-ci-detect]
  # Version metadata (applied on version creation only)
  [--release-notes <text>]
  [--release-date <YYYY-MM-DD>]
  [--external-url <url>]
  [--release-state draft|pending_review|approved|released|deprecated|end_of_life]
  [--environment production|staging|development|testing]
  [--tags <comma-separated>]
  [--no-inherit]
  [--require-structured-mapping]
```

`--require-structured-mapping` is an optional CI guardrail for supported
structured evidence. The upload still completes, then the CLI exits with code
21 unless structured evidence fields were accepted and mapped. Leave this
flag off for manual PDFs, upload-only evidence, and compliance YAML files that
are meant to be stored as document evidence only.

Supported `--type` values:

| Type | CRA Requirement |
|------|----------------|
| `risk_assessment` | Art. 10(2) |
| `eu_declaration_of_conformity` | Art. 28 |
| `technical_documentation` | Annex VII |
| `harmonised_standards` | Annex VII §5 - **mandatory** |
| `update_mechanism_documentation` | Annex VII §2b - **mandatory** |
| `uii` | Annex II - **mandatory** (renamed from `security_datasheet` to match CRA Annex II terminology) |
| `supplier_due_diligence` | Art. 13(5) - required before `third_party_due_diligence_confirmed` |
| `vulnerability_policy` | Art. 14 |
| `coordinated_disclosure_policy` | Art. 14 |
| `user_manual` | Annex II |
| `test_report` | Conformity assessment |
| `third_party_audit` | Conformity assessment (Module B/H) |
| `security_advisory` | Vulnerability handling |
| `secure_development_policy` | Annex I §1(b) - SSDLC evidence |
| `penetration_test_report` | Conformity assessment |
| `architecture_diagram` | Annex I §1 - security architecture |
| `threat_model` | Annex I §1 - threat modelling |
| `conformity_certificate` | Annex IV - notified body output |
| `support_period_justification` | Art. 13(8) - declared support period rationale |
| `other` | Catch-all for evidence not listed above |

> **Note:** `uii`, `harmonised_standards`, `update_mechanism_documentation`, and `supplier_due_diligence` are required to reach `cra_status: ready`.
>
> **Removed in v3.3.1**: `compliance_certificate`, `integration_guide`, `deployment_guide`, `api_documentation`, `release_notes`, and `patch_notes` are not supported document types. Use `conformity_certificate` for assessment certificates and `other` for general supporting documentation.

## `upload-diagram`

Upload a Mermaid architecture diagram as `architecture_diagram` technical
documentation (CRA Annex II §1). When `mmdc` (mermaid-cli) is on PATH the
`.mmd` is rendered to PNG before upload; otherwise the raw source is
uploaded with a warning.

```
craevidence upload-diagram
  --product <slug-or-id>
  --version <version-number>
  --file <path.mmd>
  [--render | --no-render]              # Default: render
  [--create-product | --no-create-product]
  [--create-version | --no-create-version]
  # CI metadata (auto-detected)
  [--commit <sha>] [--branch <name>] [--pipeline-id <id>]
  [--repository <url>] [--repo-path <subdir>] [--no-ci-detect]
```

Install mermaid-cli for rendered PNGs: `npm install -g @mermaid-js/mermaid-cli`.
The CLI Docker image does not bundle mermaid-cli (avoids the ~200MB Node.js
dependency); in Docker-based CI use `--no-render` to upload the raw `.mmd`.

## `status`

Show the current CRA compliance status and vulnerability summary for a product version.

```
craevidence status
  --product <slug-or-id>
  --version <version-number>
  [--fail-on critical|high|medium|low|none]  # default: none
```

When `--fail-on` is set to anything other than `none`, the command also gates
on CRA readiness. Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No threshold exceeded |
| 10-13 | Vulnerability threshold exceeded (critical/high/medium/low) |
| 20 | CRA legal floor not met (CRA status is not `ready`) |
| 24 | CRA legal floor met but release policy not met |

Exit 24 applies when the server returns a `release_policy_status` field that is
not `ready` while `cra_floor_status` is `ready`. This means the product passes
the CRA Regulation's baseline requirements but the organisation's own release
policy adds stricter conditions that are not yet satisfied.

When CRA Evidence reports retained source YAML provenance in
`document_artifacts`, text output shows the explicit `download-source` command
for that document. CRA Evidence only reports that URL to credentials that can
read documents; the CLI does not infer retained source availability from
document type names or filenames.

When CRA Evidence returns `artifact_inventory`, text output shows a scope-aware
evidence inventory for uploaded families such as SBOM, HBOM, VEX, SARIF/static
analysis, documents, and attestations. HBOM, VEX, and static-analysis entries
are shown as scope gaps when the credential lacks their read scope. SBOM,
document, and attestation entries follow the CI status endpoint's
existing `sbom:read` boundary.

**JSON output example:**

```json
{
  "product": "my-product",
  "version": "1.2.3",
  "cra_status": "ready",
  "vulnerability_summary": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 8
  }
}
```

## `maturity`

Show the **advisory** CRA secure-development maturity scorecard for a product (or a specific
version). Read-only: it grades practices from evidence already collected plus declared org
practices. It has **no `--fail-on` gate**, so it never fails a pipeline based on the maturity
result (genuine errors: bad credentials, product not found, network/5xx; still exit non-zero).
It does not affect readiness or release gating.

```
craevidence maturity
  --product <slug-or-id>
  [--version <version-number>]   # default: the product's reference version
```

Text output prints the overall band/coverage, per-CRA-family coverage, and a per-practice table
with each practice's status (`met` / `not_met` / `not_applicable` / `unknown`) and confidence
(`verified` = derived from real artifacts, `declared` = self-attested, `unknown` = no evidence yet).
The numbers match the web UI (`/products/{id}` maturity card and the version "Maturity" tab).

## `evidence`

Read uploaded evidence inventory metadata from existing API endpoints. This
does not download document bytes and does not infer compliance from filenames or
repository layout.

```
craevidence evidence list
  --product <slug-or-id>
  --version <version-number>

craevidence evidence hboms
  --product <slug-or-id>
  --version <version-number-or-id>

craevidence evidence vex
  --product <slug-or-id>
  --version <version-number-or-id>

craevidence evidence static-analysis
  --product <slug-or-id>
  --version <version-number-or-id>
  [--limit <1-1000>]
  [--offset <n>]
  [--tool-name <name>]
  [--severity <level>]
  [--rule-id <id>]
  [--file-path <path-fragment>]
  [--suppressed|--unsuppressed]
  [--min-severity-rank <0-4>]
  [--summary-only]

craevidence evidence documents
  --product <slug-or-id>
  --version <version-number>

craevidence evidence check
  --config <checker.yaml>
  [--out-dir craevidence-check]
  [--fail-on failed|needs-review|none]
```

Scope boundaries match API permissions: `hboms` needs `hardware:read`,
`vex` needs `vex:read`, `static-analysis` needs `vuln:read`, and `documents`
uses `/ci/status` metadata under `sbom:read`. Document and structured source
downloads remain on the existing `document:read` commands. The current API
static-analysis routes also require a member-role credential, even for
`vuln:read`.

`evidence check` is local and does not require an API key. It reads only files
declared in the checker config, calculates SHA-256 for each declared artifact,
and writes `evaluation-log.yaml`, `evidence-results.json`, and
`evidence-report.md`. The generated EvaluationLog is intended for
`compliance-as-code upload` as evidence/review. Normal CLI checker output is not
a trusted auto-confirmation source.

## `wait-ready`

Poll until a product version reaches CRA `ready` status or a timeout is exceeded. Useful after triggering an async scan.

```
craevidence wait-ready
  --product <slug-or-id>
  --version <version-number>
  [--timeout <seconds>]      # Default: 300
  [--interval <seconds>]     # Poll interval, default: 10
```

During polling, each non-ready response prints a progress line to stdout showing
elapsed time and the current status. The gate label is "Policy Status" when the
server returns a `release_policy_status` field, or "CRA Status" otherwise.
On success, the command prints which gate passed (Policy Status or CRA Status)
before exiting 0. On timeout, the command exits 1.

## `release`

Transition a product version to a new release state.

The release command updates lifecycle state. It does not prove readiness or
block `released` when CRA status is incomplete; use `status`, `wait-ready`, or
your own CI gate before release where required.

```
craevidence release
  --product <slug-or-id>
  --version <version-number>
  --state draft|pending_review|approved|released|deprecated|end_of_life
  [--superseded-by <version>]  # Record successor version; only valid with deprecated/end_of_life
```

`--superseded-by` may only be used when `--state` is `deprecated` or
`end_of_life`; passing it with any other state is a usage error (exit 2).

When `--state deprecated` is used with `--superseded-by`, the old version is
also archived (marked as replaced by the successor). Archiving does not occur
for `end_of_life` state, even when `--superseded-by` is provided.

## `scan`

Trigger a vulnerability scan on an already-uploaded SBOM without re-uploading.

```
craevidence scan
  --product <slug-or-id>
  --version <version-number>
  [--component <slug>]              # Multi-repo: scan the SBOM attributed to this component
  [--fail-on critical|high|medium]  # Exit non-zero if vulnerabilities at or above this level are found
  [--scan-timeout <seconds>]        # Max seconds to wait for scan completion (default: 300, min: 1)
```

`--component` takes a `ProductComponent` slug. When set, the scan targets
the latest SBOM whose `component_id` matches that component, so multi-repo
products can scan each component independently. When omitted, the latest
SBOM for the version is used regardless of component (unchanged default).
Archived components are not eligible.

When `--fail-on` is set, the command triggers the server-side scan and then
polls `GET /ci/status` every 5 seconds until the scan reaches a terminal
state. Progress lines go to stderr. Use `--scan-timeout` to control how long
to wait (default 300 seconds).

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | No threshold exceeded |
| 3 | Scan failed, scan disabled, or timed out |
| 10 | Critical vulnerabilities found |
| 11 | High vulnerabilities found |
| 12 | Medium vulnerabilities found |

## `export`

Export a compliance artifact (SBOM data, compliance report, or technical file bundle).

```
craevidence export
  --product <slug-or-id>
  --version <version-number>
  [--format technical-file|compliance-report|sbom-data]  # default: technical-file
  [-o|--output <file-path>]  # Write to file (auto-named if not specified)
```

Export formats:
- `technical-file`: Complete CRA technical file (Annex VII) as ZIP
- `compliance-report`: Compliance status report as PDF
- `sbom-data`: SBOM data in original format

## `compare`

Compare vulnerability or compliance state between two versions of the same product.

```
craevidence compare
  --product <slug-or-id>
  --version-a <version>
  --version-b <version>
```

## `distributor`

Manage distributor verification workflows. The following sub-commands are available.

### `distributor create`

Create a new distributor verification record. Either link to a product in CRA Evidence (`--product` + `--version`) or create a verification for an external product (`--external-product`).

```
craevidence distributor create
  [--product <slug-or-id>]             # For products in CRA Evidence
  [--version <version-number>]         # Required when using --product
  [--external-product <name>]          # For products not in CRA Evidence
  [--external-manufacturer <name>]     # External manufacturer name
  [--product-identifier <sku>]         # Product identifier (SKU, model number)
```

### `distributor update`

Update a distributor verification checklist. `VERIFICATION_ID` is a positional argument.

```
craevidence distributor update VERIFICATION_ID
  # CE marking
  [--ce-marking|--no-ce-marking]
  [--ce-location <text>]
  [--ce-evidence-type photo|document|reference|attestation|not_applicable]
  [--ce-reference-url <url>]
  [--ce-attestation <text>]
  [--ce-notes <text>]
  # EU Declaration of Conformity
  [--eu-doc|--no-eu-doc]
  [--eu-doc-location <text>]
  # Manufacturer
  [--manufacturer-contact|--no-manufacturer-contact]
  [--manufacturer-name <name>]
  [--manufacturer-address <address>]
  # Importer
  [--from-outside-eu|--from-eu]
  [--importer-contact|--no-importer-contact]
  [--importer-name <name>]
  # Compliance issues
  [--no-issues|--has-issues]
  [--issues-description <text>]
```

### `distributor complete`

Mark a verification as complete. `VERIFICATION_ID` is a positional argument.

```
craevidence distributor complete VERIFICATION_ID
```

### `distributor stop-ship`

Issue a stop-ship flag on a verification. `VERIFICATION_ID` is a positional argument.

```
craevidence distributor stop-ship VERIFICATION_ID
  --reason <text>
```

### `distributor list`

List distributor verifications.

```
craevidence distributor list
  [--status draft|verified|issues_found|stop_ship]
  [--limit <int>]            # Default: 20, max: 100
```

Verification numbers are shown in full in both text and JSON output.

### `distributor get`

Get details of a single verification. `VERIFICATION_ID` is a positional argument.

```
craevidence distributor get VERIFICATION_ID
```

## `components`

Inspect product components (multi-repo support). Read-only: shows which
components a product has and which have already pushed SBOM evidence for the
most recent version.

```
craevidence components list
  --product <slug-or-id>
  [--include-archived]       # Include soft-archived components in the output
```

The `--component <slug>` flag on `upload-sbom` and `scan` refers to the slug
shown by `components list`. See the README for the full multi-repo workflow.

## `setup-profile`

Set up or update the CRA compliance profile for a product. Configures conformity assessment type, support period, CE marking, Annex I attestations, and webhooks.

Three modes are supported:

1. **Interactive**: prompts for each field when only `--product` is given
2. **From version**: copies CRA settings from an existing version (`--from-version`)
3. **Direct flags**: non-interactive, for CI/CD pipelines

```
craevidence setup-profile
  --product <slug-or-id>                   # Required
  [--from-version <version-number>]        # Copy settings from this version
  [--conformity-type self_assessment|third_party_type_examination|third_party_full_qa|eu_certification]
  [--support-years <int>]                  # CRA minimum is 5 years
  [--ce-marking|--no-ce-marking]
  [--support-communicated|--no-support-communicated]
  [--secure-by-default|--no-secure-by-default]
  [--webhook-url <url>]                    # Pass empty string to clear
  [--webhook-secret <secret>]              # Pass empty string to clear
  [--confirm-all]                          # Set all Annex I attestations to confirmed
  [--attestation KEY=true|false]           # Set individual attestation; repeatable
```

## `show-profile`

Display the CRA compliance profile for a product.

The product heading in text output shows the slug or ID supplied by the user,
not the internal UUID from the API response.

```
craevidence show-profile
  --product <slug-or-id>     # Required
```

## `validate`

Validate an SBOM file against the CRA Evidence ingestion pipeline. Reports format, spec version, component count, PURL coverage, and any warnings or errors.

```
craevidence validate
  --sbom <path>
```

Exits with code 1 if the SBOM is invalid.

## `verify run`

Scan a directory with Syft and compare the generated SBOM against the declared SBOM already uploaded for the product version.

```
craevidence verify run <directory>
  --product <slug-or-id>
  --version <version-number>
  [--format cyclonedx|spdx]       # SBOM format for binary scan (default: cyclonedx)
  [--fail-on-discrepancies]        # Exit 1 if any discrepancies found
```

The product and version must already exist with a declared SBOM uploaded. Requires Syft installed or Docker socket mounted.

## Common upload flags

`upload-sarif` accepts only `--product`, `--version`, and `--file`. The flags
below do not apply to it.

| Flag | Applies To | Description |
|---|---|---|
| `--no-inherit` | upload-sbom, upload-hbom, upload-vex, upload-document | Skip inheriting compliance artifacts from the previous version |
| `--product-group <name>` | upload-sbom, upload-hbom, upload-vex, upload-document | Assign the product to a named product group |
| `--environment <env>` | upload-sbom, upload-hbom, upload-vex, upload-document | Target a specific deployment environment (e.g. `production`, `staging`) |
| `--tags <comma-separated>` | upload-sbom, upload-hbom, upload-vex, upload-document | Attach arbitrary metadata tags |
| `--no-create-product` | upload-sbom, upload-hbom, upload-document | Disable auto-creation of the product (creation is on by default) |
| `--no-create-version` | upload-sbom, upload-hbom, upload-document | Disable auto-creation of the version (creation is on by default) |
| `--target-markets <codes>` | upload-sbom, upload-hbom, upload-document | Comma-separated EU country codes required when auto-creating a product, e.g. `DE,FR,ES` |

## `compliance-as-code` upload

CRA Evidence stores a complyctl EvaluationLog as a version-scoped `test_report`
document via `compliance-as-code upload`.

```bash
# After authoring a ControlCatalog and running the provider
complyctl evaluate \
  --provider gemara-provider \
  --output-format yaml \
  > .cra/evaluation-log.yaml

craevidence compliance-as-code validate \
  --file .cra/evaluation-log.yaml

craevidence compliance-as-code upload \
  --file .cra/evaluation-log.yaml \
  --product my-product \
  --version 1.2.0 \
  --require-structured-mapping
```

`--require-structured-mapping` is optional. Use it only when CI must fail unless
CRA Evidence confirms that the structured file populated mapped fields; without
the flag, accepted compliance YAML files can remain document evidence with manual
follow-ups.

Compliance YAML `ControlCatalog` uploads are declaration/intent evidence. They
do not auto-confirm CRA Annex I fields; use a passed `EvaluationLog` mapping or
manual review for that confirmation.

The `citation_ids` in local `check` output are CLI-local, human-readable labels
for review. They are not a bundled CRA source index and are not machine-traceable
to the local CRA source files.

When CRA Evidence renders a compliance YAML upload to PDF, it retains the
original YAML as provenance. Download it only by explicit document ID:

```bash
craevidence compliance-as-code download-source \
  --document-id <document-id> \
  --output evidence/source.yaml
```

This is read-only provenance access. It does not reprocess the YAML, update CRA
readiness, or infer compliance.

complyctl is not bundled in the CLI Docker image; install it in your CI
environment alongside the `craevidence/cli` image when this workflow is
needed.
