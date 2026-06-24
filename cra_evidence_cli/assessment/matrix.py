"""The versioned CRA assessment applicability matrix file.

A local, CLI-owned YAML that records, per canonical Annex I requirement, whether
it applies, how it is implemented, and any justification. It is deliberately a
separate file from the Gemara risk/threat catalogs: those describe risks and
threats, this records the Article 13(3) applicability decision the gate checks.

The schema is versioned (`schema_version`) so the format can evolve with
migrations. This is a starter the developer completes; a complete matrix is not
by itself a conformity assessment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cra_evidence_cli.assessment.requirements import BY_KEY, CANONICAL_KEYS, is_waivable
from cra_evidence_cli.local.disclaimer import DISCLAIMER_TEXT, DRAFT_WATERMARK

SCHEMA_VERSION = 1
KIND = "cra-assessment-applicability"

APPLICABILITY_STATUSES = ("applicable", "not_applicable")
IMPLEMENTATION_STATUSES = (
    "planned",
    "implemented",
    "not_implemented",
    "addressed_elsewhere",
    "not_applicable",
)
SOURCES = ("structured_ra", "document", "manual")


class MatrixError(ValueError):
    """Raised when an applicability matrix file cannot be parsed or is invalid."""


@dataclass
class RequirementEntry:
    """One row of the applicability matrix, keyed by a canonical requirement."""

    key: str
    applicability_status: str = "applicable"
    implementation_status: str = "planned"
    justification: str = ""
    how_applied: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    source: str = "structured_ra"

    def to_dict(self) -> dict[str, Any]:
        req = BY_KEY[self.key]
        return {
            "key": self.key,
            "annex_ref": req.annex_ref,
            "label": req.label,
            "applicability_status": self.applicability_status,
            "implementation_status": self.implementation_status,
            "justification": self.justification,
            "how_applied": self.how_applied,
            "evidence_refs": list(self.evidence_refs),
            "source": self.source,
        }


@dataclass
class AssessmentMatrix:
    """A parsed applicability matrix."""

    metadata: dict[str, Any]
    requirements: list[RequirementEntry]
    schema_version: int = SCHEMA_VERSION

    def by_key(self) -> dict[str, RequirementEntry]:
        return {entry.key: entry for entry in self.requirements}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": KIND,
            "metadata": self.metadata,
            "requirements": [entry.to_dict() for entry in self.requirements],
        }


def _require_str(value: Any, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        msg = f"{label} must be a string, got {type(value).__name__}."
        raise MatrixError(msg)
    return value


def _parse_entry(raw: Any, index: int) -> RequirementEntry:
    if not isinstance(raw, dict):
        msg = f"requirements[{index}] must be a mapping, got {type(raw).__name__}."
        raise MatrixError(msg)
    key = raw.get("key")
    if key not in CANONICAL_KEYS:
        msg = (
            f"requirements[{index}] has unknown or missing canonical key {key!r}. "
            f"Each key must be one of the 22 Annex I keys."
        )
        raise MatrixError(msg)

    applicability = _require_str(raw.get("applicability_status"), f"requirements[{index}]") \
        or "applicable"
    if applicability not in APPLICABILITY_STATUSES:
        msg = (
            f"requirements[{index}] applicability_status {applicability!r} is invalid; "
            f"expected one of {', '.join(APPLICABILITY_STATUSES)}."
        )
        raise MatrixError(msg)

    implementation = _require_str(raw.get("implementation_status"), f"requirements[{index}]") \
        or "planned"
    if implementation not in IMPLEMENTATION_STATUSES:
        msg = (
            f"requirements[{index}] implementation_status {implementation!r} is invalid; "
            f"expected one of {', '.join(IMPLEMENTATION_STATUSES)}."
        )
        raise MatrixError(msg)

    source = _require_str(raw.get("source"), f"requirements[{index}]") or "manual"
    if source not in SOURCES:
        msg = (
            f"requirements[{index}] source {source!r} is invalid; "
            f"expected one of {', '.join(SOURCES)}."
        )
        raise MatrixError(msg)

    evidence = raw.get("evidence_refs") or []
    if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
        msg = f"requirements[{index}] evidence_refs must be a list of strings."
        raise MatrixError(msg)

    return RequirementEntry(
        key=str(key),
        applicability_status=applicability,
        implementation_status=implementation,
        justification=_require_str(raw.get("justification"), f"requirements[{index}]"),
        how_applied=_require_str(raw.get("how_applied"), f"requirements[{index}]"),
        evidence_refs=[str(item) for item in evidence],
        source=source,
    )


def parse_matrix(data: Any) -> AssessmentMatrix:
    """Validate and parse a matrix mapping (already loaded from YAML)."""
    if not isinstance(data, dict):
        msg = f"matrix file must be a YAML mapping at the top level, got {type(data).__name__}."
        raise MatrixError(msg)
    if data.get("kind") != KIND:
        msg = f"matrix file must have kind: {KIND}."
        raise MatrixError(msg)
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        msg = (
            f"unsupported schema_version {version!r}; this CLI reads version {SCHEMA_VERSION}."
        )
        raise MatrixError(msg)
    raw_requirements = data.get("requirements")
    if not isinstance(raw_requirements, list):
        msg = "matrix 'requirements' must be a list."
        raise MatrixError(msg)

    entries = [_parse_entry(raw, index) for index, raw in enumerate(raw_requirements)]
    seen: set[str] = set()
    for entry in entries:
        if entry.key in seen:
            msg = f"duplicate requirement key {entry.key!r} in matrix."
            raise MatrixError(msg)
        seen.add(entry.key)

    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        msg = "matrix 'metadata' must be a mapping."
        raise MatrixError(msg)
    return AssessmentMatrix(metadata=metadata, requirements=entries, schema_version=SCHEMA_VERSION)


def load_matrix(path: Path) -> AssessmentMatrix:
    """Read and validate a matrix YAML file from disk."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"could not read matrix file {path}: {exc}"
        raise MatrixError(msg) from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"could not parse matrix file {path}: {exc}"
        raise MatrixError(msg) from exc
    return parse_matrix(data)


_HEADER = (
    f"# CRA assessment applicability matrix. {DRAFT_WATERMARK}.\n"
    f"# {DISCLAIMER_TEXT} A complete matrix is not a conformity assessment.\n"
    "# Records, per Annex I requirement, whether it applies and how it is implemented.\n"
)


def dump_matrix(matrix: AssessmentMatrix) -> str:
    """Render a matrix to YAML text with the review header."""
    body = yaml.safe_dump(matrix.to_dict(), sort_keys=False, allow_unicode=True)
    return f"{_HEADER}{body}"


def write_exclusive(path: Path, text: str) -> None:
    """Write text, refusing to overwrite an existing file (cookiecutter style).

    Uses O_EXCL so a concurrent or pre-existing file is never clobbered. Raises
    FileExistsError with an actionable message when the target already exists.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError as exc:
        msg = (
            f"refusing to overwrite existing file: {path}. "
            f"Choose a different output path, or remove the file first."
        )
        raise FileExistsError(msg) from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_matrix(
    *,
    product: str | None,
    template_id: str | None,
    not_applicable: dict[str, str] | None = None,
    how_applied: dict[str, str] | None = None,
) -> AssessmentMatrix:
    """Build a starter matrix with all 22 canonical rows.

    `not_applicable` maps waivable keys to a justification prompt (only Part I(2)
    keys are accepted; a non-waivable key raises). `how_applied` maps any key to a
    starter implementation prompt. Keys absent from both get generic prompts.
    """
    not_applicable = not_applicable or {}
    how_applied = how_applied or {}
    bad = [key for key in not_applicable if not is_waivable(key)]
    if bad:
        msg = (
            f"only Part I(2) requirements may be pre-marked not-applicable; "
            f"got mandatory key(s): {', '.join(sorted(bad))}."
        )
        raise MatrixError(msg)
    blank = [key for key, value in not_applicable.items() if not str(value).strip()]
    if blank:
        msg = (
            f"a not-applicable requirement needs a justification; "
            f"blank for: {', '.join(sorted(blank))}."
        )
        raise MatrixError(msg)

    entries: list[RequirementEntry] = []
    for key in CANONICAL_KEYS:
        req = BY_KEY[key]
        if key in not_applicable:
            entries.append(
                RequirementEntry(
                    key=key,
                    applicability_status="not_applicable",
                    implementation_status="not_applicable",
                    justification=not_applicable[key],
                    how_applied="",
                )
            )
        else:
            prompt = how_applied.get(key) or f"[Describe how {req.label} ({req.annex_ref}) is met]"
            entries.append(
                RequirementEntry(
                    key=key,
                    applicability_status="applicable",
                    implementation_status="planned",
                    how_applied=prompt,
                )
            )

    metadata: dict[str, Any] = {"product": product or "<product>"}
    if template_id:
        metadata["template"] = template_id
    metadata["generated_by"] = "craevidence assessment"
    return AssessmentMatrix(metadata=metadata, requirements=entries)
