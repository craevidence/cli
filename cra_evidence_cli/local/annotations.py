"""Pure output formatters that turn a local check result into PR/MR annotations.

Every function here is side-effect free: no file writes, no printing, no
``sys.exit``. The caller (the CLI command) is responsible for emitting the
returned strings/structures to stdout, files, or workflow command streams.

Three output targets are supported:

* GitHub Actions workflow commands (``::error``/``::warning``) and a
  step-summary markdown table.
* GitLab Code Quality report entries (a list of dicts the caller json-dumps).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from ..ci_detect import detect_ci_environment
from .models import LocalCheckResult

# Severities treated as "error" level for GitHub annotations.
_GITHUB_ERROR_SEVERITIES = {"critical", "high"}

# Local-check severity -> GitLab Code Quality severity.
_GITLAB_SEVERITY_MAP = {
    "critical": "blocker",
    "high": "major",
    "medium": "minor",
    "low": "info",
    "unknown": "info",
}


def _findings(result: LocalCheckResult) -> list[dict[str, Any]]:
    return result.to_dict().get("findings", [])


def _short_title(finding: dict[str, Any]) -> str:
    title = finding.get("title")
    if title:
        return str(title)
    return str(finding.get("id", ""))


def _escape_github_data(value: str) -> str:
    """Escape a GitHub workflow-command message body (``%``, ``\\r``, ``\\n``).

    ``%`` must be substituted first so the inserted ``%25`` is not re-escaped.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_github_property(value: str) -> str:
    """Escape a GitHub workflow-command property value.

    Superset of message escaping: adds ``,`` and ``:``. ``%`` must be substituted first.
    """
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def github_annotations(result: LocalCheckResult) -> str:
    """Render findings as newline-joined GitHub workflow commands.

    One command per finding. ``::error`` for critical/high severity,
    ``::warning`` otherwise. The finding id is carried in the ``title=``
    property; no ``file=`` property is emitted because the local check has no
    source-file location for a finding.

    Returns ``""`` when there are no findings.
    """
    lines: list[str] = []
    for finding in _findings(result):
        severity = str(finding.get("severity", "unknown")).lower()
        command = "error" if severity in _GITHUB_ERROR_SEVERITIES else "warning"

        fid = str(finding.get("id", ""))
        package = str(finding.get("package", ""))
        version = "" if finding.get("version") is None else str(finding.get("version"))

        message = f"{package} {version}: {_short_title(finding)}"
        title_prop = _escape_github_property(fid)
        lines.append(
            f"::{command} title={title_prop}::{_escape_github_data(message)}"
        )
    return "\n".join(lines)


def github_step_summary(result: LocalCheckResult) -> str:
    """Render a GitHub-flavored markdown table of findings, or a no-findings notice."""
    findings = _findings(result)
    if not findings:
        return (
            "### Local SBOM Check\n\n"
            "No blocking findings were found in this local snapshot."
        )

    lines = [
        f"### Local SBOM Check - {len(findings)} findings",
        "",
        "| Package | Version | ID | Severity | KEV |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        package = "" if finding.get("package") is None else str(finding.get("package"))
        version = "" if finding.get("version") is None else str(finding.get("version"))
        fid = "" if finding.get("id") is None else str(finding.get("id"))
        severity = str(finding.get("severity", "unknown")).lower()
        kev = "yes" if finding.get("known_exploited") is True else ""
        lines.append(f"| {package} | {version} | {fid} | {severity} | {kev} |")
    return "\n".join(lines)


def gitlab_codequality(result: LocalCheckResult) -> list[dict[str, Any]]:
    """Render findings as GitLab Code Quality report entries.

    Uses the ``gl-code-quality-report.json`` format.
    """
    findings = _findings(result)
    if not findings:
        return []

    sbom_path = result.provenance.get("sbom_path") or "sbom.json"

    entries: list[dict[str, Any]] = []
    for finding in findings:
        fid = str(finding.get("id", ""))
        package = str(finding.get("package", ""))
        version = "" if finding.get("version") is None else str(finding.get("version"))
        severity = str(finding.get("severity", "unknown")).lower()
        gl_severity = _GITLAB_SEVERITY_MAP.get(severity, "info")

        fingerprint = hashlib.sha256(
            f"{fid}|{package}|{version}".encode()
        ).hexdigest()

        description = f"{fid}: {package} {version} - {_short_title(finding)}"

        entries.append(
            {
                "description": description,
                "severity": gl_severity,
                "fingerprint": fingerprint,
                "location": {
                    "path": str(sbom_path),
                    "lines": {"begin": 1},
                },
            }
        )
    return entries


def resolve_mode(
    choice: str,
    *,
    detect: Callable[[], Any] = detect_ci_environment,
) -> str:
    """Resolve an ``--annotations`` choice to a concrete output mode.

    ``"github"`` and ``"gitlab"`` pass through unchanged. ``"auto"`` resolves
    via ``detect()`` to the detected provider (``"github"``/``"gitlab"``/...),
    or ``"none"`` if no provider was detected. Any other value (including
    ``"none"``) is returned unchanged.
    """
    if choice == "auto":
        provider = detect().ci_provider
        return provider or "none"
    return choice
