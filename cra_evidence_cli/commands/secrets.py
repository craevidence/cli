"""Secret-scan command (advisory, no API key required).

Scans the working tree and, for a git repository, its commit history for
candidate hard-coded credentials. Matches are candidate patterns only: the
command never verifies that a secret is live, and a clean run does not prove
the absence of secrets. Advisory by default (exit 0); pass --fail-on-match to
gate CI (exit 18).
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from cra_evidence_cli.local.disclaimer import (
    advisory_block,
)
from cra_evidence_cli.local.secrets import SecretsReport, evaluate

# Kept in the default output: the anti-over-claim caveat and the actionable
# rotation guidance.
_CANDIDATE_NOTE = (
    "Matches are candidate patterns only: a secret is never verified as live, and "
    "a clean run does not prove there are no secrets. Rotate any real secret found "
    "in history; deleting it from the latest commit does not remove it from the "
    "repository."
)

# Verbose-only weakness-class mapping.
_CRA_NOTE = (
    "Hard-coded credentials are a known weakness class (CWE-798); surfacing them "
    "helps review vulnerability exposure and protection of sensitive data."
)

_SECRET_EXIT_CODE = 18


def _render_text(report: SecretsReport, verbose: bool = False) -> str:
    lines = ["Secret scan"]
    scope = "working tree + git history" if report.history_scanned else "working tree"
    lines.append(
        f"Scanned: {scope} | Files: {report.files_scanned} | "
        f"Working-tree matches: {report.working_tree_hits} | "
        f"History matches: {report.history_hits}"
    )
    if report.capped:
        lines.append(
            f"Note: scan stopped at the {len(report.hits)}-match cap; results are partial."
        )
    for hit in report.hits:
        where = f"{hit.location}:{hit.line}" if hit.line else hit.location
        commit = f" (commit {hit.commit})" if hit.commit else ""
        lines.append(f"- [{hit.source}] {hit.detector}: {hit.redacted} in {where}{commit}")
    if not report.hits:
        lines.append("No candidate secrets matched.")
    lines.append(_CANDIDATE_NOTE)
    if verbose:
        lines.append(_CRA_NOTE)
    return "\n".join(lines)


def _render_json(report: SecretsReport) -> str:
    return json.dumps(
        {
            "schema_version": "craevidence.secrets.v1",
            "report": report.to_dict(),
            "advisory": advisory_block(),
        },
        indent=2,
    )


def _render_sarif(report: SecretsReport) -> str:
    results = []
    for hit in report.hits:
        physical: dict = {"artifactLocation": {"uri": hit.location}}
        if hit.line:
            physical["region"] = {"startLine": hit.line}
        message = f"Candidate {hit.detector} ({hit.source}): {hit.redacted}"
        if hit.commit:
            message += f" in commit {hit.commit}"
        results.append(
            {
                "ruleId": f"SECRET-{hit.detector}",
                "level": "warning",
                "message": {"text": message},
                "locations": [{"physicalLocation": physical}],
                "properties": hit.to_dict(),
            }
        )

    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "craevidence secrets-check",
                        "informationUri": "https://craevidence.com",
                        "properties": {"advisory": advisory_block()},
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


@click.command("secrets-check")
@click.argument(
    "path",
    default=Path("."),
    type=click.Path(exists=True, path_type=Path),
    required=False,
)
@click.option(
    "--no-git-history",
    "no_git_history",
    is_flag=True,
    default=False,
    help="Scan only the working tree; skip git commit history.",
)
@click.option(
    "--fail-on-match",
    "fail_on_match",
    is_flag=True,
    default=False,
    help="Exit 18 if any candidate secret is found (for CI gating). Advisory (exit 0) by default.",
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
    help="Show the CRA / weakness-class mapping note. The default output is concise.",
)
@click.pass_context
def secrets_check(
    ctx: click.Context,
    path: Path,
    no_git_history: bool,
    fail_on_match: bool,
    output_file: Path | None,
    verbose_opt: bool = False,
) -> None:
    """Scan for hard-coded secrets in the working tree and git history (no API key needed).

    Looks for high-confidence provider credential patterns (AWS, GitHub, Slack,
    Google, Stripe, private keys, JWTs) plus high-entropy values assigned to
    secret-like names. When the path is a git repository, commit history is
    scanned too, since a secret removed from the latest commit can still be
    recovered from history and must be rotated.

    Matches are candidate patterns only. The command never contacts a network
    to verify that a secret is live, and a clean run does not prove the absence
    of secrets. Matched values are redacted; the raw secret is never printed.

    Advisory by default and exits 0 even when matches are found. Pass
    --fail-on-match to exit 18 instead, so a CI job can gate on it.

    """
    config = ctx.obj["config"]
    output_format = config.output_format
    verbose = verbose_opt or ctx.obj.get("verbose", False)

    report = evaluate(path, scan_history=not no_git_history)

    if output_format == "json":
        rendered = _render_json(report)
    elif output_format == "sarif":
        rendered = _render_sarif(report)
    else:
        rendered = _render_text(report, verbose)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(rendered, encoding="utf-8")
        click.echo(f"Secret scan report written to {output_file}.", err=True)
    else:
        click.echo(rendered)

    if fail_on_match and report.hits:
        ctx.exit(_SECRET_EXIT_CODE)
