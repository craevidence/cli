"""The inventory coverage statement that CRA Evidence engine SBOMs carry.

The engine names the files whose packages may be missing from the SBOM: files a
cataloger could not fully read, files not fully inspected because of a size or
analysis limit, and dependency manifests whose declared dependencies were not
shown to be resolved to packages. Its counts are coverage-gap entries, one per
file, reason code and reporting component, so one file can be counted more than
once; a dependency manifest has at most one entry. The statement never claims a
complete inventory, so a missing statement means "no coverage information", not
"complete".

This module only reads the statement. It never changes findings, gates or exit
codes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

STATEMENT_NAME = "craev:inventory-coverage"
SUPPORTED_VERSION = 1
_STATES = {"incomplete", "unknown"}

STATUS_REPORTED = "reported"
STATUS_ABSENT = "absent"
STATUS_UNINTERPRETABLE = "uninterpretable"

CODE_UNPARSED = "unparsed"
CODE_LIMIT_REFUSED = "limit_refused"
CODE_DECLARED_UNRESOLVED = "declared_unresolved"

CODE_HEADINGS = {
    CODE_DECLARED_UNRESOLVED: "Dependency manifests not shown to be resolved to packages",
    CODE_UNPARSED: "Package sources not fully read",
    CODE_LIMIT_REFUSED: "Package sources not fully inspected (size or analysis limit)",
}

_REASONS = {
    (CODE_DECLARED_UNRESOLVED, "manifest-without-lock"): (
        "declares dependencies and no lock file the generator reads covers it. "
        "Commit the lock file and run again."
    ),
    (CODE_DECLARED_UNRESOLVED, "lock-not-fully-read"): (
        "declares dependencies and the lock file that covers it could not be fully read."
    ),
    (CODE_DECLARED_UNRESOLVED, "manifest-not-catalogued"): (
        "lists dependencies in a file type the generator does not read."
    ),
    (CODE_DECLARED_UNRESOLVED, "requirements-not-fully-read"): (
        "install_requires has a requirement without an exact == pin, or a value the "
        "generator does not read; only exact pins are in the SBOM."
    ),
    (CODE_DECLARED_UNRESOLVED, "manifest-not-interpreted"): (
        "could not be read or interpreted, so its declared dependencies are not known."
    ),
    (CODE_DECLARED_UNRESOLVED, "declared-not-in-lock"): (
        "declares a dependency that is not among the packages the generator read from the "
        "lock file that covers it; the lock file may be out of date. Update it and run again."
    ),
    (CODE_DECLARED_UNRESOLVED, "coverage-not-established"): (
        "declares a dependency whose presence in the lock file the generator could not "
        "establish (for example a version catalog alias, a local path, or a dependency "
        "limited to some platforms or conditions)."
    ),
}
_CODE_REASONS = {
    CODE_DECLARED_UNRESOLVED: (
        "declares dependencies that were not shown to be resolved to packages."
    ),
    CODE_UNPARSED: "could not be fully read; packages read from the rest are kept.",
    CODE_LIMIT_REFUSED: "was not fully inspected because of a size or analysis limit.",
}


def coverage_reason(code: str, by: str) -> str:
    """The human reason for one entry. Unrecognised codes are shown as reported."""
    if (code, by) in _REASONS:
        return _REASONS[(code, by)]
    if code in _CODE_REASONS:
        return _CODE_REASONS[code]
    return f"was reported by the generator with reason code {code}."


def code_heading(code: str) -> str:
    return CODE_HEADINGS.get(code, f"Files reported with reason code {code}")


@dataclass(frozen=True)
class CoverageEntry:
    path: str
    code: str
    by: str

    def to_dict(self) -> dict[str, str]:
        return {
            "path": self.path,
            "code": self.code,
            "by": self.by,
            "reason": coverage_reason(self.code, self.by),
        }


@dataclass
class InventoryCoverage:
    status: str
    state: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    listed: int = 0
    omitted: int = 0
    entries: list[CoverageEntry] = field(default_factory=list)
    deliberate_omissions: dict[str, int] = field(default_factory=dict)
    detail: str | None = None

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def entries_for(self, code: str) -> list[CoverageEntry]:
        return [entry for entry in self.entries if entry.code == code]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "state": self.state,
            "counts": dict(sorted(self.counts.items())),
            "listed": self.listed,
            "omitted": self.omitted,
            "entries": [entry.to_dict() for entry in self.entries],
            "deliberate_omissions": dict(sorted(self.deliberate_omissions.items())),
            "detail": self.detail,
            "note": (
                "Coverage-gap entries the SBOM generator reported for files not resolved "
                "or not fully read; one file can have more than one entry. Their packages "
                "may be missing from the SBOM, so the vulnerability counts do not cover "
                "them. An absent statement is no coverage information, never a complete "
                "inventory."
            ),
        }


def _uninterpretable(detail: str) -> InventoryCoverage:
    return InventoryCoverage(status=STATUS_UNINTERPRETABLE, detail=detail)


def _statement_texts(data: dict[str, Any]) -> list[str] | None:
    """The raw statement values, or None when the document shape is not recognised."""
    if isinstance(data.get("components"), list):
        metadata = data.get("metadata")
        properties = metadata.get("properties") if isinstance(metadata, dict) else None
        if not isinstance(properties, list):
            return []
        return [
            item.get("value")
            for item in properties
            if isinstance(item, dict) and item.get("name") == STATEMENT_NAME
        ]
    if isinstance(data.get("packages"), list):
        annotations = data.get("annotations")
        if not isinstance(annotations, list):
            return []
        prefix = STATEMENT_NAME + " "
        return [
            item["comment"][len(prefix) :]
            for item in annotations
            if isinstance(item, dict)
            and isinstance(item.get("comment"), str)
            and item["comment"].startswith(prefix)
        ]
    return None


def _count_map(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    out: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or type(count) is not int or count < 0:
            return None
        out[key] = count
    return out


def read_inventory_coverage(data: dict[str, Any]) -> InventoryCoverage:
    """Decode the statement from a CycloneDX or SPDX 2 JSON document."""
    texts = _statement_texts(data)
    if not texts:
        return InventoryCoverage(status=STATUS_ABSENT)
    if len(texts) > 1:
        return _uninterpretable("the SBOM carries more than one inventory coverage statement")
    text = texts[0]
    if not isinstance(text, str):
        return _uninterpretable("the inventory coverage statement is not a string")
    try:
        statement = json.loads(text)
    except json.JSONDecodeError:
        return _uninterpretable("the inventory coverage statement is not valid JSON")
    if not isinstance(statement, dict):
        return _uninterpretable("the inventory coverage statement is not a JSON object")
    version = statement.get("v")
    if type(version) is not int or version != SUPPORTED_VERSION:
        return _uninterpretable(
            f"the inventory coverage statement version {version!r} is not supported by this CLI"
        )
    state = statement.get("state")
    counts = _count_map(statement.get("counts"))
    listed = statement.get("listed")
    omitted = statement.get("omitted")
    raw_entries = statement.get("entries")
    deliberate = _count_map(statement.get("deliberate_omissions", {}))
    if (
        not isinstance(state, str)
        or state not in _STATES
        or counts is None
        or deliberate is None
        or type(listed) is not int
        or type(omitted) is not int
        or listed < 0
        or omitted < 0
        or not isinstance(raw_entries, list)
    ):
        return _uninterpretable("the inventory coverage statement has missing or invalid fields")
    entries = []
    for item in raw_entries:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(key), str) for key in ("p", "c", "by")
        ):
            return _uninterpretable("an inventory coverage entry has missing or invalid fields")
        entries.append(CoverageEntry(path=item["p"], code=item["c"], by=item["by"]))
    total = sum(counts.values())
    listed_by_code: dict[str, int] = {}
    for entry in entries:
        listed_by_code[entry.code] = listed_by_code.get(entry.code, 0) + 1
    if (
        listed != len(entries)
        or listed + omitted != total
        or any(listed_by_code[code] > counts.get(code, 0) for code in listed_by_code)
        or (state == "incomplete") != (total > 0)
    ):
        return _uninterpretable("the inventory coverage statement contradicts its own counts")
    return InventoryCoverage(
        status=STATUS_REPORTED,
        state=state,
        counts=counts,
        listed=listed,
        omitted=omitted,
        entries=entries,
        deliberate_omissions=deliberate,
    )


def declared_unresolved_summary(coverage: InventoryCoverage, limit: int = 5) -> str | None:
    """One sentence naming manifests whose dependencies were not resolved, or None."""
    entries = coverage.entries_for(CODE_DECLARED_UNRESOLVED)
    count = coverage.counts.get(CODE_DECLARED_UNRESOLVED, 0)
    if coverage.status != STATUS_REPORTED or not count:
        return None
    shown = "; ".join(
        f"{entry.path} {coverage_reason(entry.code, entry.by)}" for entry in entries[:limit]
    )
    more = count - min(len(entries), limit)
    suffix = f" ({more} more not shown)" if more > 0 else ""
    return (
        f"{count} dependency manifest(s) were not shown to be resolved to packages: {shown}{suffix}"
    )
