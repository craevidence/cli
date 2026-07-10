"""Source code security check command (advisory, no API key required).

Runs Opengrep on a local directory using a bundled set of CRA-relevant rules.
Findings are potential weaknesses to review, not a determination. Advisory by
default (exit 0 even when findings are reported); pass --fail-on to gate CI
(exit 27). Secrets and IaC checks live in secrets-check and config-check.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from cra_evidence_cli.config import validate_config
from cra_evidence_cli.display import warn_unsupported_output_format
from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.local.disclaimer import advisory_block
from cra_evidence_cli.local.rules_pack import PACK_VERSION
from cra_evidence_cli.local.sast_scanner import (
    OPENGREP_INSTALL_HINT,
    SASTReport,
    opengrep_path,
    run_scan,
)
from cra_evidence_cli.repo_config import resolve_identity

_SAST_EXIT_CODE = 27

_BUNDLED_RULES = Path(__file__).parent.parent / "local" / "rules"

_SCOPE_NOTE = (
    "Secrets and credential patterns are covered by secrets-check. "
    "Infrastructure-as-code misconfigurations are covered by config-check."
)

_HONEST_NOTE = (
    "Findings are potential weaknesses to review, not a determination. "
    "This is not an audit; a clean result does not prove the absence of "
    "vulnerabilities. Code is never sent to CRA Evidence unless --upload is passed."
)

_LEVEL_ORDER = {"error": 3, "warning": 2, "note": 1}


def _severity_label(level: str) -> str:
    return level.upper()


def _render_text(report: SASTReport, verbose: bool = False) -> str:
    lines = ["Source code security check"]
    lines.append(f"Engine: Opengrep {report.engine_version}")
    rules_line = f"Rules: {report.rules_path} ({report.rule_count} rules)"
    if report.pack_version:
        rules_line += f", pack {report.pack_version}"
    lines.append(rules_line)

    if report.scan_failed:
        lines.append(f"Scan failed: {report.failure_reason}")
        lines.append("No findings rendered.")
        return "\n".join(lines)

    finding_count = len(report.findings)
    lines.append(f"Findings: {finding_count}")

    if report.findings:
        by_severity: dict[str, list] = {}
        for f in report.findings:
            by_severity.setdefault(f.severity.lower(), []).append(f)

        for level in ("error", "warning", "note"):
            group = by_severity.get(level)
            if not group:
                continue
            lines.append(f"\n{_severity_label(level)} ({len(group)})")
            for f in group:
                where = f"{f.file}:{f.line}" if f.line else f.file
                cwe = ", ".join(f.cwe_list) if f.cwe_list else ""
                cwe_part = f" [{cwe}]" if cwe else ""
                lines.append(f"  {where}  {f.rule_id}{cwe_part}")
                lines.append(f"    {f.message}")
        for level, group in by_severity.items():
            if level not in ("error", "warning", "note"):
                lines.append(f"\n{_severity_label(level)} ({len(group)})")
                for f in group:
                    where = f"{f.file}:{f.line}" if f.line else f.file
                    lines.append(f"  {where}  {f.rule_id}")
                    lines.append(f"    {f.message}")
    else:
        lines.append("No findings matched.")

    lines.append("")
    lines.append(_SCOPE_NOTE)
    if verbose:
        lines.append(_HONEST_NOTE)
    return "\n".join(lines)


def _render_json(report: SASTReport) -> str:
    payload = {
        "schema_version": "craevidence.code_check.v1",
        "engine": f"Opengrep {report.engine_version}",
        "rules_path": report.rules_path,
        "rule_count": report.rule_count,
    }
    # The bundled pack version is only meaningful for the bundled rules.
    if report.pack_version:
        payload["pack_version"] = report.pack_version
    return json.dumps(
        {
            **payload,
            "scan_failed": report.scan_failed,
            "failure_reason": report.failure_reason,
            "finding_count": len(report.findings),
            "findings": [f.to_dict() for f in report.findings],
            "advisory": advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: SASTReport) -> str:
    if report.sarif_raw:
        return json.dumps(report.sarif_raw, indent=2)

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence code-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {"advisory": advisory_block()},
                    }
                },
                "results": [],
            }
        ],
    }
    return json.dumps(doc, indent=2)


_UPLOAD_SIZE_LIMIT = 10 * 1024 * 1024  # 10 MiB


@click.command("code-check")
@click.argument(
    "path",
    default=Path("."),
    type=click.Path(exists=True, path_type=Path),
    required=False,
)
@click.option(
    "--rules",
    "rules_path",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Path to an Opengrep rules directory or file. "
        "Defaults to the bundled CRA Evidence rule pack."
    ),
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["note", "warning", "error"], case_sensitive=False),
    help=(
        "Exit 27 if any finding at or above this severity is found. "
        "Advisory (exit 0) by default."
    ),
)
@click.option(
    "--timeout",
    "timeout",
    default=300,
    type=int,
    show_default=True,
    help="Maximum seconds to wait for the scan engine.",
)
@click.option(
    "--exclude",
    "excludes",
    multiple=True,
    help=(
        "Pattern to exclude from the scan (passed to --exclude). "
        "Repeatable. Overrides the default exclude list when provided."
    ),
)
@click.option(
    "--exclude-rule",
    "exclude_rules",
    multiple=True,
    help="Rule id to skip (passed to --exclude-rule). Repeatable.",
)
@click.option(
    "--upload",
    "upload",
    is_flag=True,
    default=False,
    help="Upload the SARIF results to CRA Evidence after a successful scan.",
)
@click.option(
    "--product",
    "product",
    default=None,
    help="Product slug or ID (required with --upload).",
)
@click.option(
    "--version",
    "version_number",
    default=None,
    help="Version number (required with --upload).",
)
@click.option(
    "-o",
    "--output-file",
    "output_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Write output to a file instead of stdout.",
)
@click.option(
    "-v",
    "--verbose",
    "verbose_opt",
    is_flag=True,
    help="Show scope and honesty notes. The default output is concise.",
)
@click.pass_context
def code_check(
    ctx: click.Context,
    path: Path,
    rules_path: Path | None,
    fail_on: str | None,
    timeout: int,
    excludes: tuple[str, ...],
    exclude_rules: tuple[str, ...],
    upload: bool,
    product: str | None,
    version_number: str | None,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Check source code for potential security weaknesses (no API key needed).

    Runs Opengrep on PATH using a bundled set of CRA-relevant rules covering SQL
    injection, OS command injection, unsafe deserialization, weak cryptographic
    algorithms, and disabled TLS verification. Pass a custom rules directory or
    file with --rules.

    Opengrep must be installed separately; if it is absent the command reports
    the install hint and exits 0 (advisory). Findings are potential weaknesses to
    review, not a determination. A clean result does not prove the absence of
    vulnerabilities.

    Advisory by default and exits 0 even when findings are reported. Pass
    --fail-on error|warning|note to exit 27 when any finding at or above that
    severity is found, so a CI job can gate on it.

    Secrets are not covered here; use secrets-check. Infrastructure-as-code
    misconfigurations are not covered here; use config-check. Code is never sent
    to CRA Evidence unless --upload is passed.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    warn_unsupported_output_format(output_format, ("text", "json", "sarif"))

    effective_rules = rules_path if rules_path is not None else _BUNDLED_RULES

    if opengrep_path() is None:
        click.echo(
            f"opengrep not found. {OPENGREP_INSTALL_HINT}",
            err=True,
        )
        if fail_on:
            # A gated run cannot pass when the engine is unavailable to evaluate it.
            message = (
                "cannot evaluate the --fail-on gate: opengrep is not installed"
            )
            raise click.ClickException(message)
        if upload:
            # An explicit upload cannot deliver evidence with no scan to upload.
            message = "cannot upload: opengrep is not installed, so no scan ran"
            raise click.ClickException(message)
        click.echo("Skipping source code check (opengrep not installed).")
        return

    effective_excludes = excludes if excludes else None

    report = run_scan(
        path=path,
        rules=effective_rules,
        timeout=timeout,
        excludes=effective_excludes,
        exclude_rules=exclude_rules,
    )
    # Show the bundled pack version when the bundled rules were used.
    if rules_path is None:
        report.pack_version = PACK_VERSION

    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        click.echo(f"Code check report written to {output_file}.", err=True)
    else:
        click.echo(rendered)

    if upload:
        if report.scan_failed:
            # The user explicitly asked to record evidence; a silent exit 0
            # would leave the evidence absent while CI stays green.
            message = (
                "cannot upload: the scan did not complete "
                f"({report.failure_reason})"
            )
            raise click.ClickException(message)
        _do_upload(ctx, config, product, version_number, report)

    if fail_on:
        if report.scan_failed:
            # A gated run must not pass when the scan itself failed.
            message = (
                f"scan did not complete ({report.failure_reason}); "
                "refusing to pass the --fail-on gate"
            )
            raise click.ClickException(message)
        if report.findings_at_or_above(fail_on):
            ctx.exit(_SAST_EXIT_CODE)


def _do_upload(ctx: click.Context, config, product, version_number, report: SASTReport) -> None:
    import tempfile

    from cra_evidence_cli.client import CRAEvidenceClient

    try:
        product, version_number, _ = resolve_identity(product, version_number, None)
    except CRAEvidenceError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(e.exit_code)

    try:
        validate_config(config)
    except CRAEvidenceError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(e.exit_code)

    sarif_text = _render_sarif(report)
    sarif_bytes = sarif_text.encode("utf-8")

    if len(sarif_bytes) > _UPLOAD_SIZE_LIMIT:
        mb = len(sarif_bytes) / (1024 * 1024)
        message = (
            f"cannot upload: SARIF output is {mb:.1f} MiB, which exceeds the "
            "10 MiB limit"
        )
        raise click.ClickException(message)

    with tempfile.NamedTemporaryFile(suffix=".sarif.json", delete=False) as tmp:
        tmp.write(sarif_bytes)
        tmp_path = Path(tmp.name)

    try:
        client = CRAEvidenceClient(config)
        asyncio.run(
            client.upload_sarif(
                product=product,
                version=version_number,
                file_path=tmp_path,
            )
        )
        click.echo("SARIF results uploaded to CRA Evidence.", err=True)
    except CRAEvidenceError as e:
        click.echo(f"Upload error: {e}", err=True)
        sys.exit(e.exit_code)
    finally:
        tmp_path.unlink(missing_ok=True)
