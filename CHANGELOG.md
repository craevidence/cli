# Changelog

All notable changes to the CRA Evidence CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.2.0] - 2026-08-14

### Breaking changes

- `code-check --fail-on` can now fail source that passed under 4.1.0 because
  more rules are enabled by default. A finding at the configured threshold
  exits 27, while missing required semantic evidence exits 29. The 50 broader
  rules remain opt-in through `--include-experimental`.

### Added

- A default JavaScript and TypeScript rule reports assigned odd integer
  literals above the exact binary64 safe-integer boundary. At pinned ESLint
  commit `87f66f4435c4df7f4f6815c939d153196ec03e3c`, it detects 24 of 46 official
  invalid cases and none of 79 official valid cases. Its fixture independently
  verifies all reported values lose precision when converted to `Number`, and
  its documented scope leaves broader numeric analysis out of the default tier.

- `code-evidence --language cpp` uses a distinct supported libclang C++17 profile
  and evidence schema. A narrow default rule reports direct decimal-literal
  assignments outside a fixed `uint8_t` array only after an exact source-file
  array-bounds diagnostic. Active preprocessing, application element aliases,
  included-header diagnostics, stale sources, and cross-language evidence are
  covered by fail-closed tests. A second default rule reports a direct system
  `printf` or `std::printf` call only in global `main` and only when the complete
  format argument is bound to that declaration's own second parameter.
  Application homonyms, macro redirects, inactive code, wrong scopes, and
  shadowed parameters fail closed. A third default applies the same proof to a
  direct system-shell command and covers both `system` and `std::system`. The
  four broader C++ rules remain experimental.

- `code-evidence --language c` loads an exact hashed supported libclang frontend
  with fixed C17 options and hashed system-header roots. A narrow default rule
  reports direct decimal-literal assignments outside a fixed `uint8_t` array only when
  the compiler emits its array-bounds diagnostic at the exact candidate range.
  A compiling macro redirect is rejected, and diagnostics from included
  headers cannot attest a source-file candidate. The producer does not run a build
  system, linker, compiler plugin, or target binary; unsupported includes,
  compiler errors, stale source, and missing frontend assets fail closed. The
  same frontend now attests a second default rule only for a direct system
  `printf` call in global `main` whose complete format argument is bound to
  that declaration's own second parameter. Application homonyms, macro
  redirects, inactive code, and wrong scopes fail closed. A third default
  applies the same proof to a direct system-shell command. The four broader C
  rules remain experimental.

- The DHI and public fallback containers include exact Debian 13 libclang
  18.1.8 frontend libraries and required C/C++ headers. They can generate and
  consume the separate C17 and C++17 evidence profiles without a compiler
  driver, linker, plugin, project build, target-code execution, or network
  access. Exact Debian package records and copyright files are retained for
  SBOM and vulnerability inventory. Native Ubuntu 18.1.3 profiles remain
  supported, and cross-profile evidence fails closed.

- `code-evidence --language rust` statically binds one narrow default TLS rule
  to Rust 2018, 2021, or 2024 absolute extern-prelude paths and the exact
  crates.io reqwest 0.12.24 package checksum. It does not invoke Cargo, rustc,
  build scripts, proc macros, target code, or the network. Workspaces,
  dependency overrides, application-owned extern aliases, unsupported Cargo
  configuration, stale source, and malformed evidence fail closed. The broader
  reqwest method-name rule and six other Rust rules remain experimental.

- `code-evidence --language csharp` compiles a shipped Roslyn analyzer directly
  with .NET SDK 8.0.423 and the trusted net8.0 reference pack. It does not load
  projects, restore packages, invoke MSBuild, run generators, load plugins, or
  execute target code. A narrow default rule reports direct assignment of the
  framework's accept-any certificate validator only when both properties
  resolve to the signed `System.Net.Http.HttpClientHandler` type. Application
  shadows are rejected, while missing and ambiguous semantic ranges degrade
  coverage. The broader callback rule and framework MD5 rule remain
  experimental.

- A narrow PHP rule enabled by default detects the literal fully qualified
  global `\unserialize` spelling when its focused first argument is derived
  from a reviewed HTTP superglobal source. Executable PHP namespace probes
  distinguish the built-in from an application-owned namespaced homonym and
  verify that the global function cannot be redeclared. The broader
  short-name rule remains experimental, and unsupported dynamic, alias,
  multiline, concatenated, and complex-argument forms are disclosed as misses.

- `code-evidence` generates a versioned Java semantic-evidence envelope with
  the local JDK compiler API. It disables annotation processing, implicit
  compilation, the class path, and the source path, and never invokes Gradle or
  Maven. A narrow default weak-digest finding is emitted only when the
  compiler resolves `MessageDigest.getInstance` to the top-level
  `java.security.MessageDigest` type in the `java.base` module. Compiler errors,
  source changes, stale evidence, and application-owned lookalikes fail closed.
  The promotion is bound to 51 semantically attested NIST Juliet cases, 96
  strong-literal controls, 89 true positives and 0 false positives on the
  independent OWASP lane, compiling shadow controls, and a clean pinned Spring
  Petclinic run. Eight broader Java rules remain experimental.
  The CLI container consumes envelopes produced by a Java-enabled job or host;
  it does not include a JDK.

- `code-check` can consume a versioned C# semantic-evidence envelope without
  executing .NET or an analyzer. The verifier binds the pinned adapter,
  isolation profile, successful restore and build results, source and index
  digests, and exact SCIP occurrence before it emits the narrow framework
  `MD5.Create` candidate. Application-owned lookalikes are rejected; missing,
  stale, ambiguous, build-failed, or workspace-failed evidence reports degraded
  coverage. The candidate remains experimental while a normal isolated
  evidence-generation path and promotion measurements are incomplete.

- A default Go rule detects direct import-bound `crypto/tls` dial calls whose
  inline configuration sets `InsecureSkipVerify` to `true` without a custom
  verification callback. In-repository compiling adversarial fixtures bind
  import aliases, reject an application package exposing the same `tls.Config`
  and `tls.Dial` names, and reject an unrelated import path ending in
  `crypto/tls`. A fail-closed evidence record ties the non-Python default tier
  to those fixtures, their semantic compile test, the experimental companion,
  and the applicable real-project lane. Broader TLS construction, callback, and
  assignment cases remain experimental.

- Platform wheels and the CLI container now include the official Opengrep
  1.26.0 executable. Release builds verify fixed SHA-256 hashes and Sigstore
  signatures bound to Opengrep's exact release workflow identity, package its
  LGPL-2.1 license notice, and attach a deterministic build-source bundle from
  the exact commit and pinned submodules. The non-build Semgrep rule-test
  corpus is excluded and recorded in the bundle manifest.
- The bundled rule pack now tests Go, JavaScript/TypeScript, Java, C, C++, Rust,
  PHP, and C# alongside the default Python group. Those eight groups contain 48
  experimental rules, and Python contains another two, including focused
  injection, path, SSRF, deserialization, TLS, cryptography, filesystem, and
  secret-key detections. Each experimental rule requires
  `--include-experimental`.
- Reproducible evidence gates now scan pinned revisions of nine representative
  projects twice and score applicable Java rules against the OWASP Benchmark
  with raw TP, FP, FN, and TN counts. A second gate verifies the official NIST
  Juliet Java 1.3 archive, retains its CC0 legal text, repairs only two pinned
  malformed manifest lines, and records per-rule case recall and flaw-location
  corroboration. The recorded evidence blocks promotion when parser errors,
  false positives, or detection gaps remain.
- Java rules now recognize qualified filesystem, message-digest, JDBC batch,
  and JDBC overload APIs. The pinned OWASP Benchmark measures 172 of 660
  applicable vulnerable cases and 24 false positives across the complete Java
  group. Only the semantically resolved literal weak-digest rule is enabled by
  default. Each Java rule declares its exact scope and engine limitations.
  Rules with known safe-case findings or no independent precision measurement
  are warnings instead of build-breaking errors.
- The GitHub Action accepts `command: code-check`, and the GitLab component
  provides `.cra-evidence-code-check` for a source-code CI gate without a
  separate scanner installation.

### Changed

- Rule-pack review leaves 50 rules behind `--include-experimental`; the default
  tier now contains 42 Python rules, the narrowly import-bound Go TLS dial
  rule, the compiler-attested Java JDK weak-digest rule, the narrow PHP global
  `\unserialize` rule, and the Roslyn-attested C# framework accept-any
  certificate-validator assignment, and the crates.io-bound Rust reqwest TLS
  rule, three compiler-attested rules for each of C and C++, and the
  language-intrinsic JavaScript and TypeScript unsafe-integer rule. Neutral
  probes showed that promoted Go, Java, and C# rules can report application or
  third-party types whose written names resemble framework APIs. The review
  also removed unsound path and TLS callback suppressions, expanded shell
  wrapper and case coverage, and recorded unsupported helper flows as misses.
- Benchmark scoring now binds Juliet, CodeQL, gosec, and preprocessed-corpus
  findings to the rule declared by each benchmark. A CodeQL finding can cover
  at most one alert, and the only accepted CWE alias is bound to its reviewed
  corpus. The executable Go integer fixture gate observes the value entering
  each narrowing conversion, including conversions that wrap to zero.
- `code-check` resolves `CRA_EVIDENCE_OPENGREP`, then the bundled executable,
  then `PATH`. Custom excludes are additive, and `--rule-timeout` is separate
  from the whole-scan timeout. Engine-free source installs no longer skip an
  unavailable Opengrep engine with exit 0; install a supported platform wheel,
  use the container, or provide the executable through the environment or PATH.
- Text and JSON output now report scanned files, skipped files, language counts,
  enabled rules by language, rule tiers, and engine errors. Recoverable parse
  errors report degraded coverage while preserving real findings; missing
  engines, timeouts, fatal engine errors, and zero-file scans exit 1.
- Mixed-language scans now inventory visible source files and report files that
  Opengrep did not select or whose language has no enabled rules. Explicitly
  excluded paths remain excluded by user choice. Under `--fail-on`, engine
  errors or unanalysed source files exit 29 instead of producing a green gate.
- An explicit `--fail-on` policy exits 29 when recoverable parser errors degrade
  coverage, even if no finding reaches the selected severity. Python preflight
  accepts UTF-8 byte-order marks, contains parser resource failures, and names
  the host CPython grammar in text, JSON, and SARIF.
- `code-check` labels Opengrep's path count as engine target selection rather
  than parser coverage. Python syntax collapse is reported as degraded
  coverage, and text, JSON, and SARIF carry the same advisory limitations.
- The batch rule gate now copies fixtures outside Opengrep's ignored `tests`
  path, requires positive scan and finding counts, records exact locations,
  asserts Opengrep 1.26.0, and rejects untriaged cross-rule safe-line findings.
  Every taint rule also
  has a same-file helper-to-sink fixture under the production intrafile flag.
- Rule evidence now includes qualified-name, shadowed-sanitizer, `char **argv`,
  API-overload, and safe near-miss variants across Python, Java, C, C++, Rust,
  PHP, and C#. The version ledger binds both rule bodies and fixture bytes.
- Rule-specific tiers no longer force every rule in a language to move together.
  Experimental rules remain opt-in until their own evidence supports promotion.
  Sanitizer declarations now require nearby executable safe fixtures across the
  whole pack, including Django `conditional_escape` and `nh3.clean` coverage.
- Experimental coverage now includes whole-superglobal PHP flows, additional
  Java API forms, import-resolved JavaScript command execution, `tempnam`, inline
  C# deserialization, and tested control-flow guards for Rust and C# paths.
- Evidence gates verify the resolved Opengrep executable against the official
  release SHA-256, reject empty benchmark inputs, validate every CWE identifier
  against MITRE CWE 4.20, and bind annotation exceptions to nearby canonical
  fixture lines.
- Release validation enforces the manylinux glibc floor, separate musl assets,
  an 80 MiB wheel release limit, upstream copyright notices, and a native
  dependency inventory. Executable signatures and the independently hashed
  source archive are recorded as separate provenance facts.
- Container builds fail when the Opengrep native-dependency inventory is empty.
  Release workflows bind and attach the matching source archive before pushing
  an immutable image.
- `code-check --upload` removes source snippets, absolute workspace paths,
  command arguments, and environment variables from SARIF while retaining
  finding and taint-flow locations. Related locations and automatic fixes are
  removed because they can carry source text.
- PyPI publishing uses one supported Trusted Publishing action invocation for
  all missing distributions in a release or resume run.
- Go and JavaScript/TypeScript rules are experimental by default. The JavaScript
  `eval` review rule is warning-level, and the Go descriptions state the
  syntactic limits that prevent security-intent claims.


- SBOM generation and local vulnerability matching now require the compatible
  CRA Evidence Grype engine. The engine uses its embedded Syft library for
  package cataloguing, so the CLI no longer invokes a standalone Syft
  executable or accepts stock Grype as a product engine.
- Native engine support is limited to Linux AMD64/ARM64 and macOS AMD64/ARM64.
  Native Windows generation and local engine scanning are no longer supported;
  commands that consume an existing SBOM remain available without an engine.
- PyPI installs now select a platform wheel containing the engine. Linux ships
  separate manylinux and musllinux tags over the same static bytes; macOS ships
  x86_64 and arm64 wheels. The source distribution remains engine-free.
- `check` now names the reason on stderr whenever it skips the local matcher.
  It warns before attempting the OSV.dev fallback that network access may occur
  and that findings can differ.
- Generation accepts directory, file, archive, Docker-daemon, Podman, OCI and
  registry sources and honours the default container credential keychain.
  Standalone-Syft application configuration is not forwarded: `SYFT_*`
  variables, a Syft config file, an explicit platform, custom TLS or
  insecure-registry settings, path exclusions and source aliases have no effect.
  Generate with your own tooling and upload with `--file` if you need them.
- Internal: the `SBOMGenerationResult.generation_method` value changed from
  `syft`/`docker` to `craevidence-grype`. This is a library-level dataclass
  field; no CLI output serializes it.
- `upload-sbom --sbomqs-check` and `check --sbom-quality` now run
  `sbomqs compliance --bsi-v2 --json`. The report interface was validated with
  sbomqs v1.3.0 and v2.0.11; installation and release checks pin v2.0.11.
  Scores keep the 0-100 scale but can change between sbomqs versions, so CI
  users relying on `--fail-on-score` must pin the same version and may need to
  review existing thresholds.
- The dev container now installs sbomqs 2.0.11 with checksum verification.
  Editable installs use `CRA_EVIDENCE_ENGINE` when engine testing is required.
- `setup-profile` no longer offers the nonfunctional CE marking default. CE
  marking is declared per version, and the API no longer accepts the retired
  `ce_marking_standard` product-profile field.

### Fixed

- Source-distribution builds now fail if a bundled engine executable is present,
  and the distribution content gate independently rejects such an archive.

## [4.1.0] - 2026-08-07

### Added

- `draft vex --format cyclonedx` emits a CycloneDX VEX skeleton, for tooling
  that expects CycloneDX rather than OpenVEX or CSAF. Every package named in
  `affects[].ref` is also emitted as a component so the reference resolves.

### Changed

- The Docker image bundles CRA Evidence's grype fork with improvements as its
  scan engine. Scan behavior and results are unchanged.

### Fixed

- `draft vex` collapses entries per vulnerability across OpenVEX, CSAF, and
  CycloneDX while preserving every affected package, alias, and package-specific
  fix recommendation.

## [4.0.0] - 2026-08-01

Adds commands for reading and closing a risk assessment review cycle, adds
`create-version` for preparing a draft version before any new evidence is
uploaded, and makes product creation an explicit choice on every upload
command. The last item is a breaking change for pipelines that relied on a
product being created implicitly.

### Added

- `trust-attestation-key`: lets an organisation admin register a public-only
  Cosign ECDSA P-256 key for Build Provenance verification. Private-key PEM
  files are rejected before the key is sent to CRA Evidence.
- `verify-attestation`: re-checks the latest stored Bundle or raw DSSE by
  product slug and version, with an optional attestation ID override.
- `create-version`: creates a draft version under an existing product without
  uploading new evidence, scanning, approving, or releasing it. Reusable
  product-level documents and templates are linked by the platform. The product
  is never created, so classification and ownership stay a deliberate step.
  Optional creation metadata includes environment, release dates, release type,
  external URL, and explicit version-to-version inheritance, which happens only
  when `--inherit-from` is passed. `--reuse-existing` supports repeatable CI
  preparation without changing the existing version, including a concurrent
  create resolved through the API's duplicate-resource response. JSON output
  includes a stable `created` boolean, and in `--output json` mode error
  diagnostics go to stderr so stdout is always either valid JSON or empty. This
  makes it possible to attach `code-check --upload` findings to a version before
  any SBOM exists.
- `ra status`: reads the structured risk assessment status for a product
  version (assessment status, review status, completion, sign-off summary,
  asset/threat/risk counts, and process coverage when the server includes
  it). `--fail-on unreviewed` exits 28 when the review status is still
  `needs_review`; a version with no risk assessment recorded yet prints a
  note and exits 0 regardless of `--fail-on`. An unknown product or version
  is told apart from a genuinely missing risk assessment and still fails as
  a normal error (exit 3), so a typo in `--product`/`--version` is never
  reported as "no risk assessment yet". In `--output json` mode, every error
  path (identity, credentials, or the API call) prints its diagnostics to
  stderr only, so stdout is always either valid JSON or empty.
- `ra review`: walks the open risk assessment review cycle for a product
  version item by item (new/removed/updated components, VEX status changes,
  vulnerability candidates, context changes, stale evidence citations, and
  five release questions), prompting for a disposition per unresolved item
  in an interactive terminal. Refreshes automatically if the evidence
  changes mid-review. `--non-interactive` (or a non-terminal session) only
  reads the current review state (a plain GET; it never opens, refreshes, or
  otherwise records anything) and reports how many items still need a
  decision, exiting 28 if any do, 0 otherwise. Error paths follow the same
  stdout/stderr split as `ra status` in `--output json` mode.
- `ra finalize`: closes the open review cycle once every item carries a
  disposition and marks the assessment reviewed. Requires an organisation
  admin or owner role, from a human session or an API key holding the
  `ra:finalize` scope. Error paths follow the same stdout/stderr split as
  `ra status` in `--output json` mode.
- `--target-markets` on `upload-diagram` and `compliance-as-code upload`,
  which take the same comma-separated EU country codes as `upload-sbom`.
  `--create-product` can now create a product from either command instead of
  only working against one that already exists. Product-level compliance
  uploads (`Policy`, `GuidanceCatalog`, or `ControlCatalog` without
  `--version`) still require a product that exists.

### Changed

- `upload-attestation` help now identifies Cosign/Sigstore bundles and DSSE
  in-toto JSON as the supported inputs, states that product slugs and version
  numbers must match existing resources exactly, and includes a direct
  `cosign attest-blob --bundle` example. A bundle signed by a matching active
  key registered with `trust-attestation-key` can return `valid`; accepted
  `pending` provenance remains explicitly distinct from verified provenance.
- **BREAKING:** `--create-product` on `upload-sbom`, `upload-hbom`,
  `upload-document`, `upload-diagram`, and `compliance-as-code upload` now
  defaults to disabled instead of enabled. Creating a product sets its
  classification, ownership, and compliance context, so it is now always an
  explicit decision, matching the same never-auto-create rule `create-version`
  already applies to products. `--create-version` is unaffected and still
  defaults to enabled, since a draft version is low-stakes and CI tag
  pipelines rely on it. Uploading to a product that does not exist yet, and
  that was previously created implicitly, now fails with an error that names
  `--create-product` as the fix. **Migration:** pipelines that relied on
  implicit product creation must add `--create-product` plus
  `--target-markets <codes>` (for example `--create-product --target-markets
  DE,FR,ES`) to the upload command, or the equivalent `create-product: true`
  / `CRA_CREATE_PRODUCT: 'true'` input to the GitHub Action or GitLab CI
  component.
- Errors returned when a product cannot be resolved or created now name the
  CLI flag that fixes them instead of the API form field: a rejected creation
  without target markets reports `--target-markets` and `--create-product`.
  The rewrite covers `upload-sbom`, `upload-hbom`, `upload-document`,
  `upload-diagram`, and `compliance-as-code upload`.
- Bundled Syft updated to 1.50.0 and Grype to 0.116.1 everywhere the tools are
  pinned: the Docker image, the GitHub Action, the GitLab CI component, the
  Codespaces setup, the demo workflow, the Syft fallback container image, and
  the image gate scanner. The rebuilt binaries carry `golang.org/x/text`
  0.40.0 and `google.golang.org/grpc` 1.82.1, which clears two fixed High
  findings that the image gate reported against the previous binaries.
- Docker Hardened Images base digests refreshed to the current
  `python:3.14-dev` and `python:3.14` builds. The refreshed runtime base ships
  expat 2.8.2, clearing the fixed expat findings the gate reported against the
  previous base.
- Release pipeline: the pinned cosign is upgraded from 2.6.3 to 3.1.2.
  Signatures created from now on use the Sigstore bundle format: verifying
  them requires cosign 2.6 or newer, where 2.6.0 to 2.6.2 need the
  `--new-bundle-format` flag and 2.6.3 and newer detect the format
  automatically. All previously published signatures remain valid and
  verifiable as they are. Signing idempotence is now verification-first,
  which covers both the legacy and the bundle-format signature storage.

## [3.8.2] - 2026-07-18

Corrects regulatory reference text in command output and documentation,
refreshes the compliance evidence pack, and rebuilds the release pipeline
around resumable, authenticated publishing. No scanning or API behavior
changes.

### Added

- Release pipeline: a manual resume mode (workflow dispatch input
  `resume_release`) that completes a partially published release with current
  pipeline code. The release tag is resolved to a commit once at validation
  and bound to the published artifacts. Every publishing run trusts immutable
  or authenticated state only: a reused registry digest must carry the exact
  release tag signature, a checkpointed distribution must verify against its
  signed bundle, SBOM assets are signed and verified against their bundles,
  and rebuilding anything new on a resume requires an immutable GitHub
  release; a state with no such anchor needs a new patch release instead.
  Canonical distribution bytes are checkpointed on the GitHub release before
  any PyPI upload, each distribution is published on its own, a lost
  attestation sidecar is recovered from the provenance PyPI accepted, and the
  post-publish check also verifies PyPI Trusted Publishing provenance for
  both distributions. Prereleases are rejected before any publishing job in
  both modes.

### Changed

- Release pipeline: registry reads and cross-registry copies use a pinned
  crane binary through a fail-closed classifier, the cosign version is pinned
  explicitly, and the post-publish PyPI check verifies exactly the two
  released distributions by name and hash.
- Conformity route labels in `setup-profile show` now use the official
  procedure names: Internal Control (Module A), EU-Type Examination followed
  by Conformity to EU-Type based on Internal Production Control (Modules B
  and C), Full Quality Assurance (Module H), and European Cybersecurity
  Certification Scheme, all under Article 32.
- The `distributor stop-ship` output states the two distinct duties
  separately: withhold the product on reason to believe non-conformity, and
  additionally inform the manufacturer and market surveillance authorities
  when the product poses a significant cybersecurity risk.
- The `.cra/` evidence pack describes duties in plain language, aligns the
  distribution channels with the release policy (PyPI, GHCR, Docker Hub,
  Quay), documents the free local command set accurately, states the
  single-supported-line patch policy, couples security advisories to the
  fixed release, and re-evaluates the product against release 3.8.1,
  including the signed 3.8.1 artifacts.
- Documentation: the upload type table describes each document type by
  purpose, and the hosted documentation links point to the correct signed-in
  reference page.

### Fixed

- References to Regulation (EU) 2024/2847 in command output, docstrings,
  and documentation now cite the final numbering of the provision or state
  the duty in plain language. A test keeps citations out of the `.cra/`
  evidence pack and restricts them to files whose function is requirement
  mapping.

### Removed

- The standalone release recovery and retro-signing workflows. The resume
  mode replaces the recovery workflow, and the retro-signing workflow
  completed its bounded task: the Docker Hub and Quay copies of 3.6.0, 3.6.1,
  and 3.7.0 are signed and verified.

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

[Unreleased]: https://github.com/craevidence/cli/compare/v4.2.0...HEAD
[4.2.0]: https://github.com/craevidence/cli/compare/v4.1.0...v4.2.0
[4.1.0]: https://github.com/craevidence/cli/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/craevidence/cli/compare/v3.8.2...v4.0.0
[3.8.2]: https://github.com/craevidence/cli/compare/v3.8.1...v3.8.2
[3.8.1]: https://github.com/craevidence/cli/compare/v3.8.0...v3.8.1
[3.8.0]: https://github.com/craevidence/cli/compare/v3.7.0...v3.8.0
[3.7.0]: https://github.com/craevidence/cli/compare/v3.6.1...v3.7.0
[3.6.1]: https://github.com/craevidence/cli/compare/v3.6.0...v3.6.1
[3.6.0]: https://github.com/craevidence/cli/releases/tag/v3.6.0
