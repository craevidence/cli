"""Deterministic local evidence checks from a declarative YAML config.

Emits Gemara EvaluationLog YAML plus JSON/Markdown outputs for CI diagnostics.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

RESULT_PASSED = "Passed"
RESULT_FAILED = "Failed"
RESULT_NEEDS_REVIEW = "Needs Review"

SUPPORTED_CHECK_TYPES = {
    "file_exists",
    "document_exists",
    "markdown_headings",
    "markdown_sections",
    "sbom",
    "sbom_parse",
    "sarif",
    "sarif_parse",
}


class EvidenceCheckerError(ValueError):
    """Raised when a checker config or declared artifact is invalid."""


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text())
    except OSError as exc:
        msg = f"Unable to read checker config {path}: {exc}"
        raise EvidenceCheckerError(msg) from exc
    except yaml.YAMLError as exc:
        msg = f"Invalid YAML in checker config {path}: {exc}"
        raise EvidenceCheckerError(msg) from exc
    if not isinstance(data, dict):
        msg = "Checker config must be a YAML mapping."
        raise EvidenceCheckerError(msg)
    return data


def _resolve_declared_path(config_dir: Path, raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        msg = "Check path must be a non-empty string."
        raise EvidenceCheckerError(msg)
    path = Path(raw_path)
    if not path.is_absolute():
        path = config_dir / path
    return path


def _normalise_heading(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _markdown_headings(path: Path) -> set[str]:
    headings: set[str] = set()
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        title = stripped.lstrip("#").strip()
        if title:
            headings.add(_normalise_heading(title))
    return headings


def _load_structured_file(path: Path) -> Any:
    text = path.read_text(errors="replace")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def _check_file_exists(check: dict[str, Any], path: Path) -> tuple[str, str, list[str]]:
    if not path.exists():
        return RESULT_FAILED, f"Declared evidence file does not exist: {check['path']}", []
    if not path.is_file():
        return RESULT_FAILED, f"Declared evidence path is not a file: {check['path']}", []
    if path.stat().st_size <= 0:
        return RESULT_FAILED, f"Declared evidence file is empty: {check['path']}", []
    return RESULT_PASSED, "Declared evidence file exists and is not empty.", [
        f"File size: {path.stat().st_size} bytes",
    ]


def _check_markdown_headings(check: dict[str, Any], path: Path) -> tuple[str, str, list[str]]:
    base_result, base_message, base_steps = _check_file_exists(check, path)
    if base_result == RESULT_FAILED:
        return base_result, base_message, base_steps
    expected = check.get("required_headings") or check.get("headings") or []
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        msg = f"Check {check['id']} requires required_headings as a list of strings."
        raise EvidenceCheckerError(
            msg
        )
    found = _markdown_headings(path)
    missing = [heading for heading in expected if _normalise_heading(heading) not in found]
    found_steps = [
        f"Found heading: {heading}"
        for heading in expected
        if heading not in missing
    ]
    steps = [*base_steps, *found_steps]
    if missing:
        steps.extend(f"Missing heading: {heading}" for heading in missing)
        return RESULT_FAILED, f"Markdown file is missing {len(missing)} required heading(s).", steps
    return RESULT_PASSED, "Markdown file contains all required headings.", steps


def _check_sbom(check: dict[str, Any], path: Path) -> tuple[str, str, list[str]]:
    base_result, base_message, base_steps = _check_file_exists(check, path)
    if base_result == RESULT_FAILED:
        return base_result, base_message, base_steps
    try:
        data = _load_structured_file(path)
    except Exception as exc:
        return RESULT_FAILED, f"SBOM could not be parsed as JSON/YAML: {exc}", base_steps
    if not isinstance(data, dict):
        return RESULT_FAILED, "SBOM root must be an object.", base_steps
    if data.get("bomFormat") == "CycloneDX":
        components = data.get("components") or []
        if not isinstance(components, list):
            return RESULT_FAILED, "CycloneDX SBOM components field must be a list.", base_steps
        return RESULT_PASSED, "CycloneDX SBOM parsed successfully.", [
            *base_steps,
            f"Components: {len(components)}",
        ]
    if isinstance(data.get("spdxVersion"), str):
        packages = data.get("packages") or []
        if not isinstance(packages, list):
            return RESULT_FAILED, "SPDX SBOM packages field must be a list.", base_steps
        return RESULT_PASSED, "SPDX SBOM parsed successfully.", [
            *base_steps,
            f"Packages: {len(packages)}",
        ]
    return RESULT_FAILED, "SBOM is neither CycloneDX nor SPDX.", base_steps


def _check_sarif(check: dict[str, Any], path: Path) -> tuple[str, str, list[str]]:
    base_result, base_message, base_steps = _check_file_exists(check, path)
    if base_result == RESULT_FAILED:
        return base_result, base_message, base_steps
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception as exc:
        return RESULT_FAILED, f"SARIF could not be parsed as JSON: {exc}", base_steps
    if not isinstance(data, dict):
        return RESULT_FAILED, "SARIF root must be an object.", base_steps
    if data.get("version") != "2.1.0":
        return RESULT_FAILED, "SARIF version must be 2.1.0.", base_steps
    runs = data.get("runs")
    if not isinstance(runs, list):
        return RESULT_FAILED, "SARIF runs field must be a list.", base_steps
    return RESULT_PASSED, "SARIF 2.1.0 parsed successfully.", [
        *base_steps,
        f"Runs: {len(runs)}",
    ]


def _expand_component_checks(config: dict[str, Any]) -> list[dict[str, Any]]:
    checks = list(config.get("checks") or [])
    components = config.get("components") or []
    if not isinstance(components, list):
        msg = "components must be a list when present."
        raise EvidenceCheckerError(msg)
    for component in components:
        if not isinstance(component, dict):
            msg = "Each component entry must be a mapping."
            raise EvidenceCheckerError(msg)
        sbom_path = component.get("sbom")
        if not sbom_path:
            continue
        component_id = component.get("slug") or component.get("id") or component.get("name")
        if not component_id:
            msg = "Component entries with sbom require id, slug, or name."
            raise EvidenceCheckerError(msg)
        checks.append(
            {
                "id": f"sbom-{component_id}",
                "title": f"SBOM parse for {component_id}",
                "type": "sbom",
                "path": sbom_path,
                "component": component_id,
            }
        )
    return checks


def _entry_id_for(check: dict[str, Any]) -> str:
    maps_to = check.get("maps_to")
    if isinstance(maps_to, str) and maps_to.strip():
        return maps_to.strip()
    return f"checker:{check['id']}"


def _reference_id_for(entry_id: str) -> str:
    if entry_id.startswith("cra:"):
        return "CRA"
    return "CHECKER"


def _result_for_mapping(raw_result: str, entry_id: str) -> str:
    if raw_result == RESULT_PASSED and entry_id.startswith("cra:"):
        return RESULT_NEEDS_REVIEW
    return raw_result


def _run_single_check(config_dir: Path, check: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(check, dict):
        msg = "Each check must be a mapping."
        raise EvidenceCheckerError(msg)
    check_id = check.get("id")
    check_type = check.get("type")
    if not isinstance(check_id, str) or not check_id.strip():
        msg = "Each check requires a non-empty id."
        raise EvidenceCheckerError(msg)
    if check_type not in SUPPORTED_CHECK_TYPES:
        msg = (
            f"Check {check_id} has unsupported type {check_type!r}. "
            f"Supported types: {sorted(SUPPORTED_CHECK_TYPES)}."
        )
        raise EvidenceCheckerError(
            msg
        )
    path = _resolve_declared_path(config_dir, check.get("path"))
    declared_path = str(check.get("path"))
    check = {**check, "id": check_id.strip(), "path": declared_path}

    if check_type in {"file_exists", "document_exists"}:
        raw_result, message, steps = _check_file_exists(check, path)
    elif check_type in {"markdown_headings", "markdown_sections"}:
        raw_result, message, steps = _check_markdown_headings(check, path)
    elif check_type in {"sbom", "sbom_parse"}:
        raw_result, message, steps = _check_sbom(check, path)
    else:
        raw_result, message, steps = _check_sarif(check, path)

    artifact: dict[str, Any] = {
        "path": declared_path,
        "exists": path.exists() and path.is_file(),
    }
    if artifact["exists"]:
        artifact["sha256"] = _sha256(path)
        artifact["byte_size"] = path.stat().st_size

    entry_id = _entry_id_for(check)
    result = _result_for_mapping(raw_result, entry_id)
    if raw_result == RESULT_PASSED and result == RESULT_NEEDS_REVIEW:
        message = (
            f"{message} Stored for review; this check is not allowed to "
            "auto-confirm CRA obligations."
        )

    return {
        "id": check["id"],
        "title": check.get("title") or check["id"].replace("-", " ").replace("_", " ").title(),
        "type": check_type,
        "component": check.get("component"),
        "entry_id": entry_id,
        "raw_result": raw_result,
        "result": result,
        "message": message,
        "steps": steps,
        "artifact": artifact,
    }


def _status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "passed": sum(1 for item in results if item["result"] == RESULT_PASSED),
        "failed": sum(1 for item in results if item["result"] == RESULT_FAILED),
        "needs_review": sum(1 for item in results if item["result"] == RESULT_NEEDS_REVIEW),
    }


def _aggregate_result(results: list[dict[str, Any]]) -> str:
    if any(item["result"] == RESULT_FAILED for item in results):
        return RESULT_FAILED
    if any(item["result"] == RESULT_NEEDS_REVIEW for item in results):
        return RESULT_NEEDS_REVIEW
    if all(item["result"] == RESULT_PASSED for item in results):
        return RESULT_PASSED
    return RESULT_UNKNOWN


RESULT_UNKNOWN = "Unknown"


def _build_evaluation_log(config: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    metadata = config.get("metadata") or {}
    if not isinstance(metadata, dict):
        msg = "metadata must be a mapping when present."
        raise EvidenceCheckerError(msg)
    target = config.get("target") or {}
    if not isinstance(target, dict):
        msg = "target must be a mapping when present."
        raise EvidenceCheckerError(msg)
    check_id = metadata.get("id") or config.get("id") or "cra-evidence-check"
    now = _utc_now()
    author = metadata.get("author") or {}
    if author and not isinstance(author, dict):
        msg = "metadata.author must be a mapping when present."
        raise EvidenceCheckerError(msg)
    author = {
        "id": author.get("id") or "craevidence-checker",
        "name": author.get("name") or "CRA Evidence Checker",
        "type": author.get("type") or "Software",
        "version": author.get("version") or "0.1.0",
    }

    evaluations = []
    for item in results:
        reference_id = _reference_id_for(item["entry_id"])
        requirement = {
            "reference-id": reference_id,
            "entry-id": item["entry_id"],
        }
        steps = list(item["steps"] or [item["message"]])
        artifact = item.get("artifact") or {}
        if artifact.get("path"):
            steps.append(f"Artifact path: {artifact['path']}")
        if artifact.get("sha256"):
            steps.append(f"Artifact SHA-256: {artifact['sha256']}")
        if artifact.get("byte_size") is not None:
            steps.append(f"Artifact byte size: {artifact['byte_size']}")
        assessment = {
            "requirement": requirement,
            "description": item["title"],
            "result": item["result"],
            "message": item["message"],
            "applicability": ["Declared evidence"],
            "steps": steps,
            "steps-executed": len(steps),
            "start": now,
            "end": now,
        }
        evaluations.append(
            {
                "name": item["title"],
                "result": item["result"],
                "message": item["message"],
                "control": {
                    "reference-id": reference_id,
                    "entry-id": item["entry_id"],
                },
                "assessment-logs": [assessment],
            }
        )

    mapping_references = [
        {
            "id": "CHECKER",
            "title": "CRA Evidence local checker",
            "version": "0.1.0",
            "description": "Local deterministic checks over explicitly declared evidence files.",
        }
    ]
    if any(item["entry_id"].startswith("cra:") for item in results):
        mapping_references.append(
            {
                "id": "CRA",
                "title": "CRA Evidence review mapping labels",
                "version": "1.0.0",
                "description": (
                    "CLI-local human-readable labels for review. They are not a "
                    "machine-readable CRA source index."
                ),
            }
        )

    return {
        "metadata": {
            "id": check_id,
            "type": "EvaluationLog",
            "gemara-version": "1.0.0",
            "version": str(metadata.get("version") or "1.0.0"),
            "date": now,
            "description": metadata.get("description") or "Local CRA Evidence checker output.",
            "author": author,
            "mapping-references": mapping_references,
        },
        "target": {
            "id": target.get("id") or metadata.get("target_id") or "local-workspace",
            "name": target.get("name") or metadata.get("target_name") or "Local workspace",
            "type": target.get("type") or "Software",
            **({"version": str(target["version"])} if target.get("version") else {}),
            **({"environment": str(target["environment"])} if target.get("environment") else {}),
        },
        "result": _aggregate_result(results),
        "evaluations": evaluations,
    }


def run_evidence_check(config_path: Path) -> dict[str, Any]:
    config_path = config_path.resolve()
    config = _load_yaml(config_path)
    checks = _expand_component_checks(config)
    if not checks:
        msg = "Checker config must declare at least one check or component SBOM."
        raise EvidenceCheckerError(
            msg
        )
    results = [_run_single_check(config_path.parent, check) for check in checks]
    counts = _status_counts(results)
    return {
        "config_path": str(config_path),
        "summary": {
            "total": len(results),
            **counts,
        },
        "results": results,
        "evaluation_log": _build_evaluation_log(config, results),
    }


def _render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# CRA Evidence Checker Report",
        "",
        f"Config: `{result['config_path']}`",
        "",
        "## Summary",
        "",
    ]
    summary = result["summary"]
    lines.extend(
        [
            f"- Total checks: {summary['total']}",
            f"- Passed: {summary['passed']}",
            f"- Failed: {summary['failed']}",
            f"- Needs review: {summary['needs_review']}",
            "",
            "## Checks",
            "",
        ]
    )
    for item in result["results"]:
        lines.extend(
            [
                f"### {item['title']}",
                "",
                f"- ID: `{item['id']}`",
                f"- Type: `{item['type']}`",
                f"- Result: {item['result']}",
                f"- Requirement: `{item['entry_id']}`",
                f"- Message: {item['message']}",
            ]
        )
        artifact = item.get("artifact") or {}
        if artifact:
            lines.append(f"- Artifact: `{artifact.get('path')}`")
            if artifact.get("sha256"):
                lines.append(f"- SHA-256: `{artifact['sha256']}`")
        if item.get("steps"):
            lines.append("")
            lines.append("Steps:")
            for step in item["steps"]:
                lines.append(f"- {step}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_checker_outputs(result: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evaluation_log = output_dir / "evaluation-log.yaml"
    results_json = output_dir / "evidence-results.json"
    report_md = output_dir / "evidence-report.md"

    evaluation_log.write_text(
        yaml.safe_dump(result["evaluation_log"], sort_keys=False, allow_unicode=False)
    )
    results_json.write_text(
        json.dumps(
            {"summary": result["summary"], "results": result["results"]},
            indent=2,
        )
    )
    report_md.write_text(_render_markdown(result))
    return {
        "evaluation_log": evaluation_log,
        "results_json": results_json,
        "report_md": report_md,
    }
