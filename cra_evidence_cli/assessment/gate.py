"""The assessment gate: lint an applicability matrix for CRA Annex I gaps.

Pure evaluation, no I/O. Two blocking conditions:

  - missing_mandatory (exit 25): a Part I(1) or Part II requirement that is
    absent, marked not-applicable (which is not permitted for a mandatory
    requirement), or applicable with no implementation recorded. The eight Part
    II vulnerability-handling duties are the Article 13(8) floor.
  - unjustified_waiver (exit 26): a Part I(2) requirement marked not-applicable
    with no justification, in the matrix or in the exceptions file (Article 13(4)
    requires a clear justification).

Conditions listed in the gate config's `fail_on` block the build; any others are
reported as advisory findings that do not change the exit code. Passing the gate
checks only these structural gaps; it is not an audit and exit 0 is not proof of
compliance.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cra_evidence_cli.assessment.config import (
    CONDITION_MISSING_MANDATORY,
    CONDITION_UNJUSTIFIED_WAIVER,
    FAIL_ON_CHOICES,
    ExceptionsFile,
)
from cra_evidence_cli.assessment.matrix import AssessmentMatrix, RequirementEntry
from cra_evidence_cli.assessment.requirements import BY_KEY, CANONICAL_KEYS, is_waivable

EXIT_MISSING_MANDATORY = 25
EXIT_UNJUSTIFIED_WAIVER = 26

CONDITION_INCOMPLETE = "incomplete"  # advisory only, never blocking

_ADDRESSED_IMPLEMENTATION = {"implemented", "addressed_elsewhere"}


@dataclass
class Finding:
    """One gap (or advisory note) the gate found for a requirement."""

    key: str
    annex_ref: str
    label: str
    condition: str
    blocking: bool
    message: str


@dataclass
class GateResult:
    """The outcome of evaluating a matrix against the gate."""

    findings: list[Finding] = field(default_factory=list)

    @property
    def blocking(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.blocking]

    @property
    def advisory(self) -> list[Finding]:
        return [finding for finding in self.findings if not finding.blocking]

    def exit_code(self) -> int:
        conditions = {finding.condition for finding in self.blocking}
        if CONDITION_MISSING_MANDATORY in conditions:
            return EXIT_MISSING_MANDATORY
        if CONDITION_UNJUSTIFIED_WAIVER in conditions:
            return EXIT_UNJUSTIFIED_WAIVER
        return 0


def _entry_addresses(entry: RequirementEntry) -> bool:
    """True if the matrix row records an implementation for the requirement."""
    has_text = bool(entry.how_applied.strip() or entry.justification.strip())
    return entry.implementation_status in _ADDRESSED_IMPLEMENTATION and has_text


def evaluate_gate(
    matrix: AssessmentMatrix,
    exceptions: ExceptionsFile,
    fail_on: tuple[str, ...] = FAIL_ON_CHOICES,
) -> GateResult:
    """Evaluate every canonical requirement against the matrix and exceptions."""
    entries = matrix.by_key()
    result = GateResult()

    for key in CANONICAL_KEYS:
        req = BY_KEY[key]
        entry = entries.get(key)
        exception = exceptions.by_key.get(key)

        if not is_waivable(key):
            _evaluate_mandatory(result, key, req.annex_ref, req.label, entry, exception, fail_on)
        else:
            _evaluate_waivable(result, key, req.annex_ref, req.label, entry, exception, fail_on)

    return result


def _evaluate_mandatory(
    result: GateResult,
    key: str,
    annex_ref: str,
    label: str,
    entry: RequirementEntry | None,
    exception: object,
    fail_on: tuple[str, ...],
) -> None:
    blocking = CONDITION_MISSING_MANDATORY in fail_on
    addressed_elsewhere = exception is not None and getattr(
        exception, "status", None
    ) == "addressed_elsewhere"

    if entry is None and not addressed_elsewhere:
        result.findings.append(
            Finding(
                key, annex_ref, label, CONDITION_MISSING_MANDATORY, blocking,
                f"{annex_ref} ({label}) is mandatory but has no entry in the matrix.",
            )
        )
        return
    if entry is not None and entry.applicability_status == "not_applicable" \
            and not addressed_elsewhere:
        result.findings.append(
            Finding(
                key, annex_ref, label, CONDITION_MISSING_MANDATORY, blocking,
                f"{annex_ref} ({label}) is mandatory and cannot be marked not-applicable.",
            )
        )
        return
    if addressed_elsewhere:
        return
    if entry is not None and not _entry_addresses(entry):
        result.findings.append(
            Finding(
                key, annex_ref, label, CONDITION_MISSING_MANDATORY, blocking,
                f"{annex_ref} ({label}) is mandatory but no implementation is recorded "
                f"(implementation_status={entry.implementation_status}).",
            )
        )


def _evaluate_waivable(
    result: GateResult,
    key: str,
    annex_ref: str,
    label: str,
    entry: RequirementEntry | None,
    exception: object,
    fail_on: tuple[str, ...],
) -> None:
    if entry is None:
        result.findings.append(
            Finding(
                key, annex_ref, label, CONDITION_INCOMPLETE, False,
                f"{annex_ref} ({label}) has no applicability decision recorded.",
            )
        )
        return

    if entry.applicability_status == "not_applicable":
        justified = bool(entry.justification.strip()) or exception is not None
        if not justified:
            result.findings.append(
                Finding(
                    key, annex_ref, label, CONDITION_UNJUSTIFIED_WAIVER,
                    CONDITION_UNJUSTIFIED_WAIVER in fail_on,
                    f"{annex_ref} ({label}) is marked not-applicable without a justification.",
                )
            )
        return

    # applicable Part I(2): not yet implemented is advisory, not a gate failure.
    if not _entry_addresses(entry):
        result.findings.append(
            Finding(
                key, annex_ref, label, CONDITION_INCOMPLETE, False,
                f"{annex_ref} ({label}) is applicable but no implementation is recorded yet.",
            )
        )
