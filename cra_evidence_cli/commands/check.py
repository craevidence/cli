"""No-key local security check command."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import click
from click.core import ParameterSource
from rich.console import Console

from cra_evidence_cli.exceptions import (
    CRAEvidenceError,
    KevGateExceeded,
    LicensePolicyExceeded,
    SbomqsThresholdExceeded,
    ScanEngineUnavailable,
    VulnerabilityThresholdExceeded,
)
from cra_evidence_cli.local.annotations import (
    github_annotations,
    github_step_summary,
    gitlab_codequality,
    resolve_mode,
)
from cra_evidence_cli.local.enrich import (
    apply_cve_alias_enrichment,
    fetch_epss_scores,
    fetch_kev_catalog,
)
from cra_evidence_cli.local.models import CoverageSource, LocalCheckResult, summarize_findings
from cra_evidence_cli.local.osv import OSVClient, OSVClientError
from cra_evidence_cli.local.policy import ignored_set, load_policy
from cra_evidence_cli.local.report import print_text_report, render
from cra_evidence_cli.local.sbom import SBOMParseError, load_sbom
from cra_evidence_cli.local.scanner import GrypeLocalScanner
from cra_evidence_cli.local.signal import assert_no_cra_pass, build_dimensions, mark_stale_sources
from cra_evidence_cli.local.vex import VexParseError, apply_vex, load_vex
from cra_evidence_cli.sbom_generator import (
    SBOMGenerationError,
    _get_syft_version,
    generate_sbom_from_directory,
    generate_sbom_from_image,
)
from cra_evidence_cli.sbomqs_check import run_sbomqs

console = Console()


def _split_csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


@click.command("check")
@click.argument("path", required=False, type=click.Path(path_type=Path), default=Path("."))
@click.option("--image", help="Container image reference to scan.")
@click.option("--sbom", "sbom_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--baseline", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "known-exploited"], case_sensitive=False),
)
@click.option(
    "--fail-on-new",
    type=click.Choice(["critical", "high", "medium", "any"], case_sensitive=False),
    help="With --baseline: fail only on vulnerabilities introduced since the baseline.",
)
@click.option(
    "--deny-license",
    default="",
    help="Comma-separated SPDX license IDs to fail on (exit 16), e.g. AGPL-3.0-only,GPL-3.0-only.",
)
@click.option(
    "--sbom-quality",
    is_flag=True,
    help="Score the SBOM with sbomqs (BSI TR-03183-2 v2) when the binary is installed.",
)
@click.option(
    "--fail-on-score",
    type=click.IntRange(0, 100),
    help="Fail (exit 14) if the sbomqs quality score is below N. Implies --sbom-quality.",
)
@click.option("--strict", is_flag=True, help="Fail on stale or unavailable consulted sources.")
@click.option(
    "--vex",
    "vex_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="OpenVEX/CSAF document; suppress not_affected (with justification)/fixed "
    "findings before gates.",
)
@click.option(
    "--policy-file",
    "policy_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Policy file of defaults (default: auto-load .cra/check.yaml). "
    "Explicit flags override it.",
)
@click.option(
    "--annotations",
    type=click.Choice(["github", "gitlab", "auto"], case_sensitive=False),
    help="Emit PR/MR inline annotations (output formatting only; does not change exit codes).",
)
@click.option(
    "--annotations-file",
    "annotations_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="GitLab Code Quality report path (default gl-code-quality-report.json).",
)
@click.option(
    "--sbom-output",
    "sbom_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Also write a copy of the Syft-generated SBOM here (no-op when --sbom is supplied).",
)
@click.option(
    "--output-file",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        "Write the machine-readable report to this file; "
        "the human summary still prints to stdout."
    ),
)
@click.option(
    "--json-output",
    "json_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Also write the JSON report to this path, regardless of --output (one scan, many files).",
)
@click.option(
    "--sarif-output",
    "sarif_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Also write the SARIF report to this path, regardless of --output.",
)
@click.option(
    "--markdown-output",
    "markdown_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Also write the Markdown report to this path, regardless of --output.",
)
@click.option(
    "-v",
    "--verbose",
    "verbose_opt",
    is_flag=True,
    help="Show reviewed dimensions, the coverage denominator, and what the "
    "snapshot cannot tell you. The default output is concise.",
)
@click.pass_context
def check(
    ctx: click.Context,
    path: Path,
    image: str | None,
    sbom_file: Path | None,
    baseline: Path | None,
    fail_on: str | None,
    fail_on_new: str | None,
    deny_license: str,
    sbom_quality: bool,
    fail_on_score: int | None,
    strict: bool,
    vex_file: Path | None,
    policy_file: Path | None,
    annotations: str | None,
    annotations_file: Path | None,
    sbom_output: Path | None,
    output_file: Path | None,
    json_output: Path | None,
    sarif_output: Path | None,
    markdown_output: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Run a client-side security check without an API key."""
    # Only a PATH the user actually typed on the command line counts as an input
    # mode; the default "." (or a directly-invoked callback) does not.
    explicit_path = ctx.get_parameter_source("path") == ParameterSource.COMMANDLINE
    if sum(1 for item in (bool(image), bool(sbom_file), explicit_path) if item) > 1:
        msg = "Use only one input mode: PATH, --image, or --sbom."
        raise click.UsageError(msg)

    # Policy file supplies defaults; explicit CLI flags (and env vars) override it.
    policy = load_policy(policy_file)
    fail_on = _effective(ctx, "fail_on", fail_on, policy.fail_on if policy else None)
    fail_on_new = _effective(
        ctx, "fail_on_new", fail_on_new, policy.fail_on_new if policy else None
    )
    fail_on_score = _effective(
        ctx, "fail_on_score", fail_on_score, policy.fail_on_score if policy else None
    )
    sbom_quality = _effective(
        ctx, "sbom_quality", sbom_quality, policy.sbom_quality if policy else None
    )
    if _source_is_default(ctx, "deny_license") and policy and policy.deny_license:
        deny_license_list = list(policy.deny_license)
    else:
        deny_license_list = _split_csv(deny_license)
    if vex_file is None and policy and policy.vex:
        vex_file = Path(policy.vex)
        if not vex_file.exists():
            msg = f"Policy 'vex' path does not exist: {vex_file} (from {policy.source_path})"
            raise click.UsageError(
                msg
            )
    ignore_ids = ignored_set(policy)

    if fail_on_new and not baseline:
        msg = "--fail-on-new requires --baseline."
        raise click.UsageError(msg)
    sbom_quality = bool(sbom_quality) or fail_on_score is not None

    verbose = verbose_opt or bool(ctx.obj.get("verbose"))
    output_format = ctx.obj["config"].output_format
    try:
        result = run_local_check(
            target_path=path,
            image=image,
            sbom_file=sbom_file,
            baseline=baseline,
            strict=strict,
            sbom_quality=sbom_quality,
            verbose=verbose,
            vex_file=vex_file,
            ignore_ids=ignore_ids,
            sbom_output=sbom_output,
        )
    except (SBOMGenerationError, SBOMParseError, OSVClientError, ScanEngineUnavailable) as exc:
        if isinstance(exc, ScanEngineUnavailable):
            click.echo(f"Error: {exc}", err=True)
            sys.exit(exc.exit_code)
        raise click.ClickException(str(exc)) from exc
    except VexParseError as exc:
        msg = f"VEX parse error: {exc}"
        raise click.ClickException(msg) from exc

    # Surface KEV findings suppressed by VEX loudly - never let VEX hide an exploited vuln.
    for record in result.suppressions:
        if record.get("kev_conflict"):
            click.echo(
                f"Warning: VEX suppressed a known-exploited (KEV) finding: {record['vuln_id']} "
                f"({record['status']})",
                err=True,
            )

    machine = render(result, output_format, verbose=verbose)
    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(machine)
        click.echo(render(result, "text", verbose=verbose))
        click.echo(f"Wrote {output_format} report to {output_file}", err=True)
    elif output_format == "text" and console.is_terminal:
        print_text_report(console, result, verbose=verbose)
    else:
        click.echo(machine)

    _write_reports(
        result,
        json_output=json_output,
        sarif_output=sarif_output,
        markdown_output=markdown_output,
        verbose=verbose,
    )

    if annotations:
        # Annotations are output formatting only: a failure here (e.g. an
        # unwritable report path) must never change the exit code or mask a
        # vulnerability gate. Swallow and warn; the gate below decides the exit.
        try:
            _emit_annotations(result, annotations, annotations_file)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"Warning: failed to emit {annotations} annotations: {exc}", err=True)

    try:
        _enforce_gate(
            result,
            fail_on,
            strict,
            deny_license=deny_license_list,
            fail_on_new=fail_on_new,
            fail_on_score=fail_on_score,
        )
    except CRAEvidenceError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(exc.exit_code)


def _source_is_default(ctx: click.Context, name: str) -> bool:
    return ctx.get_parameter_source(name) == ParameterSource.DEFAULT


def _effective(ctx: click.Context, name: str, cli_value: Any, policy_value: Any) -> Any:
    """Explicit CLI/env value wins; otherwise fall back to the policy value."""
    if _source_is_default(ctx, name) and policy_value is not None:
        return policy_value
    return cli_value


def _emit_annotations(
    result: LocalCheckResult, choice: str, annotations_file: Path | None
) -> None:
    import os

    mode = resolve_mode(choice)
    if mode == "github":
        commands = github_annotations(result)
        if commands:
            click.echo(commands)
        step_summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        if step_summary_path:
            with open(step_summary_path, "a", encoding="utf-8") as handle:
                handle.write(github_step_summary(result) + "\n")
    elif mode == "gitlab":
        report = gitlab_codequality(result)
        target = annotations_file or Path("gl-code-quality-report.json")
        # CI side-output: unlike the report artifacts it does not create missing
        # parent dirs. A write failure here is caught and warned by the caller so
        # it can never mask a vulnerability gate.
        target.write_text(json.dumps(report, indent=2))
        click.echo(f"Wrote GitLab Code Quality report to {target}", err=True)
    else:
        click.echo(
            "No CI provider detected for --annotations auto; skipping annotations.", err=True
        )


def _write_reports(
    result: LocalCheckResult,
    *,
    json_output: Path | None,
    sarif_output: Path | None,
    markdown_output: Path | None,
    verbose: bool = False,
) -> None:
    """Write extra report files in fixed formats, independent of --output.

    A single scan can yield several artifacts in one pass (for example SARIF for
    code scanning plus JSON for archival), so a job no longer has to re-run the
    check once per format. Files are written before the gate runs so a failing
    gate still leaves the artifacts on disk.
    """
    for output_path, report_format in (
        (json_output, "json"),
        (sarif_output, "sarif"),
        (markdown_output, "markdown"),
    ):
        if output_path is None:
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(render(result, report_format, verbose=verbose), encoding="utf-8")
        click.echo(f"Wrote {report_format} report to {output_path}", err=True)


def run_local_check(
    target_path: Path,
    image: str | None,
    sbom_file: Path | None,
    baseline: Path | None,
    strict: bool,
    sbom_quality: bool = False,
    verbose: bool = False,
    vex_file: Path | None = None,
    ignore_ids: set[str] | None = None,
    sbom_output: Path | None = None,
) -> LocalCheckResult:
    generated_sbom = None
    target_type = "directory"
    target = str(target_path)
    if sbom_file:
        sbom_path = sbom_file
        target_type = "sbom"
        target = str(sbom_file)
    elif image:
        generated_sbom = generate_sbom_from_image(image, verbose=verbose)
        sbom_path = generated_sbom.file_path
        target_type = "image"
        target = image
    else:
        generated_sbom = generate_sbom_from_directory(
            str(target_path), verbose=verbose
        )
        sbom_path = generated_sbom.file_path

    # Keep a copy of the generated SBOM as a CI artifact (no-op for user-supplied --sbom).
    if sbom_output is not None:
        if generated_sbom is None:
            click.echo(
                "--sbom-output ignored: the SBOM was supplied with --sbom, not generated.",
                err=True,
            )
        else:
            sbom_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(generated_sbom.file_path, sbom_output)
            click.echo(f"Wrote generated SBOM copy to {sbom_output}", err=True)

    components, _raw_sbom = load_sbom(sbom_path)
    coverage: list[CoverageSource] = []
    sources_consulted: set[str] = set()
    scanner = GrypeLocalScanner()
    findings = []
    engine = "none"
    if scanner.is_available():
        findings, source = scanner.scan_sbom(sbom_path)
        coverage.append(source)
        sources_consulted.add("grype")
        engine = "grype-local"
    else:
        findings, source = OSVClient().query_components(components)
        coverage.append(source)
        sources_consulted.add("osv.dev")
        engine = "osv-online"

    cves = set().union(*(finding.cve_aliases for finding in findings)) if findings else set()
    try:
        kev_cves, kev_source = fetch_kev_catalog()
        apply_cve_alias_enrichment(findings, kev_cves=kev_cves)
        coverage.append(kev_source)
        sources_consulted.add("cisa-kev")
    except Exception as exc:
        coverage.append(CoverageSource("cisa-kev", "unavailable", detail=str(exc)))
    try:
        epss_scores, epss_source = fetch_epss_scores(cves)
        apply_cve_alias_enrichment(findings, epss_scores=epss_scores)
        coverage.append(epss_source)
        sources_consulted.add("first-epss")
    except Exception as exc:
        coverage.append(CoverageSource("first-epss", "unavailable", detail=str(exc)))

    # VEX suppression - runs after KEV/EPSS enrichment so kev_conflict is accurate,
    # and before gating. Suppressed findings are recorded, not silently dropped.
    suppressions: list[dict[str, Any]] = []
    if vex_file is not None:
        kept, records = apply_vex(findings, load_vex(vex_file))
        findings = kept
        suppressions = [record.to_dict() for record in records]

    # Policy ignore-list: tag (never drop) so the finding is still shown but not gated.
    if ignore_ids:
        wanted = {item.upper() for item in ignore_ids}
        for finding in findings:
            ids = {finding.id.upper()} | finding.cve_aliases
            if ids & wanted:
                finding.ignored_by_policy = True

    quality = None
    if sbom_quality:
        try:
            qs = run_sbomqs(sbom_path)
            quality = {
                "score": round(qs.score_out_of_100, 1),
                "components": qs.num_components,
                "weakest": [
                    f"{f.feature} {f.score:.0f}/{f.max_score:.0f}" for f in qs.worst_features
                ],
            }
            sources_consulted.add("sbomqs")
        except CRAEvidenceError as exc:
            coverage.append(CoverageSource("sbomqs", "unavailable", detail=str(exc)))

    mark_stale_sources(coverage)
    dimensions = build_dimensions(components, findings, coverage, sbom_quality=quality)
    assert_no_cra_pass(dimensions)
    provenance = {
        "engine": engine,
        "syft_version": _format_syft_version(_get_syft_version()),
        "sbom_path": str(sbom_path),
    }
    if quality is not None:
        provenance["sbom_quality"] = quality
    for source in coverage:
        provenance[source.source] = {"status": source.status, "as_of": source.as_of}
    result = LocalCheckResult(
        target=target,
        target_type=target_type,
        sbom_path=sbom_path,
        components=components,
        findings=findings,
        dimensions=dimensions,
        coverage=coverage,
        provenance=provenance,
        attributions=_attributions(sources_consulted),
        sources_consulted=sorted(sources_consulted),
        baseline=_baseline_delta(baseline, findings) if baseline else None,
        suppressions=suppressions,
    )
    if strict and any(source.status in {"stale", "unavailable"} for source in coverage):
        result.provenance["strict_failure"] = "stale or unavailable source"
    return result


SEVERITY_CODES = {"critical": 10, "high": 11, "medium": 12}


def _enforce_gate(
    result: LocalCheckResult,
    fail_on: str | None,
    strict: bool,
    deny_license: list[str] | None = None,
    fail_on_new: str | None = None,
    fail_on_score: int | None = None,
) -> None:
    if strict and any(source.status in {"stale", "unavailable"} for source in result.coverage):
        msg = "Strict mode failed because a consulted source is stale/unavailable"
        raise ScanEngineUnavailable(msg)

    # Policy-ignored findings are shown in the report but excluded from every gate below.
    gated_findings = [f for f in result.findings if not f.ignored_by_policy]

    # License policy (exit 16) - reads the per-component licenses already parsed from the SBOM.
    if deny_license:
        denied = {item.upper() for item in deny_license}
        violations = sorted(
            {
                f"{component.name}:{lic}"
                for component in result.components
                for lic in component.licenses
                if lic.upper() in denied
            }
        )
        if violations:
            shown = ", ".join(violations[:5]) + ("…" if len(violations) > 5 else "")
            msg = f"{len(violations)} component license(s) match the deny policy: {shown}"
            raise LicensePolicyExceeded(
                msg
            )

    # SBOM quality (exit 14) - only when sbomqs actually ran.
    if fail_on_score is not None:
        quality = result.provenance.get("sbom_quality") or {}
        score = quality.get("score")
        if score is not None and score < fail_on_score:
            raise SbomqsThresholdExceeded(float(score), float(fail_on_score))

    # Severity / known-exploited gate (exit 10/11/12/17).
    if fail_on:
        summary = summarize_findings(gated_findings)
        fail_on = fail_on.lower()
        if fail_on == "known-exploited" and summary["known_exploited"]:
            raise KevGateExceeded(summary["known_exploited"])
        if fail_on in SEVERITY_CODES:
            count = _count_at_or_above(gated_findings, fail_on)
            if count:
                raise VulnerabilityThresholdExceeded(fail_on, count, SEVERITY_CODES[fail_on])

    # "No new findings" ratchet (exit 10/11/12) - only the vulns introduced since the baseline.
    if fail_on_new and result.baseline:
        new_ids = set(result.baseline.get("new_vulnerabilities") or [])
        new_findings = [finding for finding in gated_findings if finding.id in new_ids]
        level = fail_on_new.lower()
        if level == "any":
            if new_findings:
                msg = "new"
                raise VulnerabilityThresholdExceeded(msg, len(new_findings), 12)
        else:
            count = _count_at_or_above(new_findings, level)
            if count:
                msg = f"new {level}"
                raise VulnerabilityThresholdExceeded(msg, count, SEVERITY_CODES[level])


def _count_at_or_above(findings: list[Any], severity: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2}
    threshold = ranks[severity]
    return sum(1 for finding in findings if finding.severity_rank >= threshold)


def _format_syft_version(version: tuple[int, int, int] | None) -> str:
    if version is None:
        return "unavailable"
    return ".".join(str(part) for part in version)


def _baseline_delta(path: Path | None, findings: list[Any]) -> dict[str, Any] | None:
    if not path:
        return None
    data = json.loads(path.read_text())
    previous_ids = {item["id"] for item in data.get("findings", []) if item.get("id")}
    current_ids = {item.id for item in findings}
    return {
        "new_vulnerabilities": sorted(current_ids - previous_ids),
        "removed_vulnerabilities": sorted(previous_ids - current_ids),
    }


def _attributions(sources: set[str]) -> list[str]:
    lines = []
    if "grype" in sources:
        lines.append("Grype and Syft are Apache-2.0 projects from Anchore.")
        lines.append("EPSS and CISA KEV data may be included through the Grype vulnerability DB.")
    if "osv.dev" in sources:
        lines.append("OSV.dev records retain their originating database licenses and attribution.")
    if "cisa-kev" in sources:
        lines.append(
            "CISA Known Exploited Vulnerabilities catalog is consulted as CC0 data; "
            "no seal/logo used."
        )
    if "first-epss" in sources:
        lines.append("EPSS scores are provided by FIRST and require attribution when rendered.")
    return lines or ["No external vulnerability source was consulted."]


if __name__ == "__main__":
    sys.exit(check())
