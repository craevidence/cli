# CI/CD integration

This page collects the CI/CD recipes for running the CLI in your pipelines. The
local `check` gate (available through the GitHub Action and GitLab component, or
by calling `craevidence check` directly) is free: it needs no API key and does
not call the CRA Evidence API. The upload steps shown below send artefacts to
CRA Evidence and require `CRA_EVIDENCE_API_KEY` (and optionally
`CRA_EVIDENCE_URL`).

Back to the [README](../README.md).

## Branch and release jobs

Use separate jobs for checks and release evidence:

| Pipeline | Command | Result |
|---|---|---|
| Pull request or branch | `craevidence check` | Runs locally. No CRA Evidence product or version is created. |
| Release or tag | `craevidence upload-*` | Uploads evidence to the release version and can create that version. |
| Intentional development evidence | `craevidence upload-* --environment development` | Uploads to a controlled development version. |

SBOM, HBOM, and document uploads create missing versions by default. Do not
pass a raw branch name as `--version` unless you intentionally want that
version record. In GitHub Actions, `${{ github.ref_name }}` is the tag name in
a tag-triggered job and the branch name in a branch-triggered job. Docker runs
the same CLI, so Docker upload commands have the same version creation
behavior.

## Usage in CI/CD

### GitHub Action

The packaged action installs this Python CLI and calls the same
`craevidence upload-*` commands as direct CLI usage.

```yaml
name: release-evidence

on:
  push:
    tags:
      - "v*"

jobs:
  release-evidence:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - name: Build SBOM
        run: |
          # Replace this with the SBOM command your build already uses.
          your-sbom-command > sbom.cdx.json
      - uses: craevidence/cli@v3
        with:
          api-key: ${{ secrets.CRA_EVIDENCE_API_KEY }}
          product: my-product
          version: ${{ github.ref_name }}
          file: sbom.cdx.json
          artifact-type: sbom
          scan: true
          fail-on: high
          sign: true
          signature-identity: https://github.com/acme/router/.github/workflows/release.yml@refs/heads/main
          signature-issuer: https://token.actions.githubusercontent.com
          fail-untrusted: true
```

For first setup, run once without `fail-untrusted`, copy the signer identity
and issuer printed by the CLI, then pin those values in the action inputs.

### GitLab Component

Store `CRA_EVIDENCE_API_KEY` as a masked CI/CD variable, then include the
component:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/craevidence/cli/v3.8.0/gitlab-ci-component.yml'
    inputs:
      product: $CI_PROJECT_NAME
      version: $CI_COMMIT_TAG
      file: sbom.cdx.json
      target-markets: DE,FR,ES
      artifact-type: sbom
      scan: true
      fail-on: high
      sign: true
      signature-identity: https://gitlab.com/acme/router//.gitlab-ci.yml@refs/tags/v2.4.1
      signature-issuer: https://gitlab.com
      fail-untrusted: true
```

Once the component is published to the GitLab CI/CD Catalog, you can also
use the catalog include form instead of the raw URL. The component provides
separate `.cra-evidence-upload` and `.cra-evidence-check` job templates; extend
the one you need (or include both).

The component requests GitLab's `SIGSTORE_ID_TOKEN` with audience `sigstore`
for the upload job. Teams that already create their own bundle can use
`signature-on: true` or `signature-bundle: path/to/bundle.sigstore.json`
instead of `sign: true`.

The catalog upload job runs automatically on tags. If you extend
`.cra-evidence-upload` directly, add your own `rules:` so branch pipelines do
not upload release evidence unless that is intentional.

### GitHub Actions (Docker)

```yaml
name: CRA Compliance
on:
  release:
    types: [published]

jobs:
  cra-upload:
    runs-on: ubuntu-latest
    env:
      IMAGE_NAME: my-image
    steps:
      - uses: actions/checkout@v4

      - name: Upload to CRA Evidence
        run: |
          docker run --rm \
            -e CRA_EVIDENCE_API_KEY=${{ secrets.CRA_EVIDENCE_API_KEY }} \
            -v /var/run/docker.sock:/var/run/docker.sock \
            craevidence/cli:latest \
            upload-sbom \
              --product my-product \
              --version ${{ github.ref_name }} \
              --image ${{ env.IMAGE_NAME }}:${{ github.sha }} \
              --scan \
              --fail-on high
```

Generating an SBOM directly from a built Docker image (set `IMAGE_NAME` in the
job-level `env:` block or replace with the literal image reference):

```yaml
      - name: Generate and Upload SBOM from Image
        run: |
          docker run --rm \
            -e CRA_EVIDENCE_API_KEY=${{ secrets.CRA_EVIDENCE_API_KEY }} \
            -v /var/run/docker.sock:/var/run/docker.sock \
            craevidence/cli:latest \
            upload-sbom \
              --product my-product \
              --version ${{ github.ref_name }} \
              --image ${{ env.IMAGE_NAME }}:${{ github.sha }} \
              --scan \
              --fail-on high
```

### GitLab CI (Docker)

```yaml
upload-sbom:
  image: craevidence/cli:latest
  variables:
    CRA_EVIDENCE_API_KEY: $CRA_EVIDENCE_API_KEY
  script:
    - craevidence upload-sbom
        --product $CI_PROJECT_NAME
        --version $CI_COMMIT_TAG
        --file sbom.json
        --scan
        --fail-on high
  rules:
    - if: $CI_COMMIT_TAG

upload-sbom-from-image:
  image: craevidence/cli:latest
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2375
    CRA_EVIDENCE_API_KEY: $CRA_EVIDENCE_API_KEY
  script:
    - craevidence upload-sbom
        --product $CI_PROJECT_NAME
        --version $CI_COMMIT_TAG
        --image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
        --scan
  rules:
    - if: $CI_COMMIT_TAG
```

### Jenkins

```groovy
pipeline {
  agent any
  environment {
    CRA_EVIDENCE_API_KEY = credentials('cra-evidence-api-key')
  }
  stages {
    stage('Upload SBOM') {
      steps {
        script {
          docker.image('craevidence/cli:latest').inside {
            sh '''
              craevidence upload-sbom \
                --product my-product \
                --version ${BUILD_NUMBER} \
                --file sbom.json \
                --scan
            '''
          }
        }
      }
    }
  }
}
```

---

## Vulnerability DB caching

When the check gate runs, the local scanner downloads a vulnerability database
on its first run. Subsequent runs skip the download if the database is current.
Caching the database directory between CI jobs reduces network traffic and
speeds up cold starts.

**GitHub Action** (engine and DB stored under `$RUNNER_TEMP/craevidence-*`):

```yaml
- uses: actions/cache@v4
  with:
    path: ${{ runner.temp }}/craevidence-grype-db
    key: vuln-db-${{ runner.os }}-${{ runner.arch }}
    restore-keys: vuln-db-${{ runner.os }}-
```

Place this step before the `craevidence/cli@v3` action step.

**GitLab CI component** (engine and DB stored under `/tmp/craevidence/*`):

```yaml
cache:
  key: vuln-db-${CI_RUNNER_EXECUTABLE_ARCH}
  paths:
    - /tmp/craevidence/grype-db/
```

The vulnerability database refreshes daily. A cached copy younger than 24
hours is reused without a download. Caching is optional: jobs without a warm
cache still succeed but download the database each run.

---

## Compliance Pipeline Integrations

The CLI accepts artefacts produced by upstream OpenSSF/EU tooling without
needing new commands: `upload-sarif` and `compliance-as-code upload` already
cover the wire formats. The recipes below show how to wire two common
producers into a CI job.

### OpenSSF Scorecard → SARIF → CRA Evidence

[Scorecard](https://github.com/ossf/scorecard) emits SARIF 2.1.0 covering
SDLC security checks (branch protection, dependency review, CI tests, code
review, signed releases, among 20 checks total). These map to CRA Annex I,
Part I (design and development with an appropriate level of cybersecurity)
and Annex I, Part II, point 3 (effective and regular tests and reviews of
the security of the product). Push the SARIF to CRA Evidence via the
existing `upload-sarif` command.

```yaml
# GitHub Actions
- name: Run OpenSSF Scorecard
  uses: ossf/scorecard-action@v2.4.0
  with:
    results_file: scorecard.sarif
    results_format: sarif
    publish_results: false

- name: Push Scorecard results to CRA Evidence
  run: |
    craevidence upload-sarif \
      --product ${{ env.CRA_PRODUCT }} \
      --version ${{ env.CRA_VERSION }} \
      --file scorecard.sarif
  env:
    CRA_EVIDENCE_API_KEY: ${{ secrets.CRA_EVIDENCE_API_KEY }}
    CRA_EVIDENCE_URL: ${{ secrets.CRA_EVIDENCE_URL }}
```

No CLI code change is required: `upload-sarif` accepts any SARIF 2.1.0
file regardless of producer.

### complyctl EvaluationLog → CRA Evidence

[complyctl](https://github.com/complytime/complyctl) runs compliance-as-code
providers and emits an `EvaluationLog` describing which controls passed or
failed. CRA Evidence stores the log as a version-scoped `test_report`
document via `compliance-as-code upload`.

Scaffold starter compliance YAML with `compliance-as-code template`. By default it
pre-fills real product, org, and SBOM-component data from your account; add
`--offline` (with `--product`/`--org`) to generate locally with no API key and
no network. Add `--sbom <sbom.json>` with `--offline` to seed RiskCatalog or
ThreatCatalog subjects from local components; without `--sbom`, offline output
uses placeholders you must replace. Install `cue` for local validation.

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
