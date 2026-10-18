# AGENTS.md

Guidance for anyone, human or coding agent, changing this repository. This repository
is public: every file, comment, docstring, string, test and commit message is read by
users. Write for them.

## Before changing a command

- Read the command module under `cra_evidence_cli/commands/` and the client method it
  calls in `cra_evidence_cli/client.py`.
- `POST /api/v1/ci/scan` and `POST /api/v1/ci/release-state` take form fields. The
  client sends them with `data=`, never `json=`.
- The environment variables `CRA_EVIDENCE_API_KEY` and `CRA_EVIDENCE_URL` are a public
  interface. Keep their names.
- The published images are multi-architecture, including ARM64. Check that the image
  still builds after a change to the `Dockerfile` or its inputs.

## Writing code, docs and tests

- Comments and docs describe what this CLI does. They do not describe the internals or
  limitations of any server it talks to.
- Claims must match the code. Never state that the tool proves compliance. Network
  behaviour as implemented: `check` never contacts CRA Evidence. By default it uses the
  network: Grype for matching when it is installed (Grype may update its database),
  OSV.dev as the fallback when Grype is absent or fails, and CISA KEV and FIRST EPSS for
  enrichment. A pre-cached Grype database with `GRYPE_DB_AUTO_UPDATE=false` stops Grype
  database updates; `check` still requests KEV and EPSS and may use the OSV fallback.
  `check` has no `--offline` flag; `gemara` does. Update this paragraph and the README
  in the same change when that behaviour changes.
- Keep every disclaimer as written: "not an audit", "exit 0 does not prove compliance"
  and "What this local snapshot cannot tell you". Do not weaken them.
- Credentials come only from the environment. Never hardcode them, and mask API keys
  on every output path with `mask_api_key`.
- Tests assert behaviour and fail when it regresses. No assertions guarded by a
  condition such as `if mock.called`, and no `if ...: pass` tests.
- Style: no em dashes anywhere, no decorative banner comments, no docstrings that only
  restate a signature, no filler words ("simply", "robust", "comprehensive",
  "seamless", "leverage", "powerful"), and no emoji except the CLI status glyphs ✓
  and ✗.

## Commits and releases

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), with an optional
  scope, imperative subject of at most 72 characters, and a body that explains why for
  non-trivial changes. Releases are `chore(release): X.Y.Z`.
- One complete, self-contained commit per logical change: code, tests and docs
  together. Never mix a fix with a feature or a refactor, and never land work-in-progress
  or fixup commits on `main`.
- Push, tag and publish only with the maintainer's explicit approval for that push.
- Pushed history is not rewritten. A correction is a new commit.
- No `Signed-off-by` trailers.
- Before publishing, run every applicable validation gate from
  `.github/workflows/ci.yml` and the scripts it invokes, using the publishing-build
  conditions rather than the pull-request fallback. `docs/releasing.md` ("Before
  pushing anything") lists the commands. Use `scripts/check-image-gate.sh <image>` for
  the image scan: it applies the pinned scanner, its checksum, the database policy and
  the suppressions in `.github/grype.yaml` (loaded through `GRYPE_CONFIG` inside that
  script). A gate that cannot run is unverified, not passed.
- Pre-publish checklist: clean working tree; build from a fresh clone; inspect both the
  sdist and the wheel for stray files; disclaimers match the code; tests pass; `ruff`
  is clean apart from `S101` in `tests/`.

## Root layout

Only these files may exist at the root: `AGENTS.md`, `CLAUDE.md` (imports this file
for Claude Code), `Dockerfile`, `pyproject.toml`,
`README.md`, `LICENSE`, `CHANGELOG.md` (Keep a Changelog), `action.yml` (GitHub
Action), `gitlab-ci-component.yml` (GitLab CI component), `.gitignore`,
`.pre-commit-config.yaml`. Directories: `cra_evidence_cli/` (package), `tests/`,
`scripts/` (helper scripts run locally or in CI), `docs/` (guides and README media),
`.cra/` (this CLI's own compliance-as-code evidence, public on purpose),
`.devcontainer/`, `.github/` (community files, templates, workflows, `release.yml`,
`grype.yaml` and `grype-watchlist.yaml`). Do not add `.grype.yaml` at the root.
`*.egg-info/` is a build artifact and stays ignored. Any other root-level file or
directory needs a maintainer decision first.
