"""
Optional BSI TR-03183-2 v2 pre-upload check via the sbomqs binary.

Wraps `sbomqs compliance --bsi-v2 --json <file>` so `upload-sbom` can score
an SBOM locally before sending it to the platform. Surfaces the BSI
requirement areas the platform's own `quality_score` does not compute
(per-component identity, license and hash fields, level of detail, SBOM
build metadata and signature). The report interface is available in sbomqs
v1.3.0 and has been validated with v1.3.0 and v2.0.11. Installations pin
v2.0.11 because scores can change between sbomqs versions.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cra_evidence_cli.exceptions import CRAEvidenceError

SBOMQS_BINARY = "sbomqs"
SBOMQS_TIMEOUT_SECONDS = 120
SBOMQS_INSTALL_HINT = (
    "Install the pinned sbomqs v2.0.11 release to use --sbomqs-check: "
    "`go install github.com/interlynk-io/sbomqs/v2@v2.0.11`, or download "
    "v2.0.11 from https://github.com/interlynk-io/sbomqs/releases."
)


@dataclass(frozen=True)
class FeatureScore:
    feature: str
    score: float
    max_score: float


@dataclass(frozen=True)
class SbomqsResult:
    file_name: str
    num_components: int
    score_out_of_100: float
    worst_features: list[FeatureScore]


def _numeric_field(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"sbomqs JSON missing numeric '{field}'"
        raise CRAEvidenceError(msg, exit_code=1)
    number = float(value)
    if not math.isfinite(number):
        msg = f"sbomqs JSON contains non-finite '{field}'"
        raise CRAEvidenceError(msg, exit_code=1)
    return number


def discover_sbomqs() -> str:
    """Return the absolute path to the sbomqs binary or raise."""
    path = shutil.which(SBOMQS_BINARY)
    if path is None:
        msg = f"sbomqs binary not found on PATH. {SBOMQS_INSTALL_HINT}"
        raise CRAEvidenceError(
            msg,
            exit_code=2,
        )
    return path


def run_sbomqs(sbom_path: Path, binary: str | None = None) -> SbomqsResult:
    """Run the sbomqs BSI TR-03183-2 v2 compliance check and parse the result.

    Raises CRAEvidenceError when the binary is missing, the subprocess
    fails, the output is unparseable, or the expected report shape is
    absent.
    """
    sbomqs_bin = binary or discover_sbomqs()
    try:
        completed = subprocess.run(  # noqa: S603
            [sbomqs_bin, "compliance", "--bsi-v2", "--json", str(sbom_path)],
            capture_output=True,
            text=True,
            timeout=SBOMQS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        msg = f"sbomqs timed out after {SBOMQS_TIMEOUT_SECONDS}s scoring {sbom_path}"
        raise CRAEvidenceError(
            msg,
            exit_code=1,
        ) from exc
    except FileNotFoundError as exc:
        msg = f"sbomqs binary disappeared at runtime: {sbomqs_bin}. {SBOMQS_INSTALL_HINT}"
        raise CRAEvidenceError(
            msg,
            exit_code=2,
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        msg = f"sbomqs exited {completed.returncode}: {stderr or '(no stderr)'}"
        raise CRAEvidenceError(
            msg,
            exit_code=1,
        )

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        msg = f"sbomqs returned non-JSON output: {exc.msg}"
        raise CRAEvidenceError(
            msg,
            exit_code=1,
        ) from exc

    if not isinstance(payload, dict):
        msg = "sbomqs JSON root must be an object"
        raise CRAEvidenceError(msg, exit_code=1)

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        msg = "sbomqs JSON missing object 'summary'"
        raise CRAEvidenceError(msg, exit_code=1)
    total_score = _numeric_field(summary.get("total_score"), "summary.total_score")
    max_score = _numeric_field(summary.get("max_score"), "summary.max_score")
    if max_score <= 0:
        msg = "sbomqs JSON 'summary.max_score' must be greater than zero"
        raise CRAEvidenceError(msg, exit_code=1)
    if total_score < 0 or total_score > max_score:
        msg = "sbomqs JSON 'summary.total_score' is outside the report score range"
        raise CRAEvidenceError(msg, exit_code=1)

    # Sections carry one row per requirement element; component-level rows
    # repeat per component with the component as element_id, while
    # document-level rows use the literal "SBOM".
    sections = payload.get("sections")
    if not isinstance(sections, list):
        msg = "sbomqs JSON missing array 'sections'"
        raise CRAEvidenceError(msg, exit_code=1)
    if not sections:
        msg = "sbomqs JSON 'sections' must not be empty"
        raise CRAEvidenceError(msg, exit_code=1)
    scores_by_area: dict[str, list[float]] = {}
    component_ids: set[str] = set()
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            msg = f"sbomqs JSON 'sections[{index}]' must be an object"
            raise CRAEvidenceError(msg, exit_code=1)
        area = section.get("section_title")
        if not isinstance(area, str) or not area.strip():
            msg = f"sbomqs JSON missing text 'sections[{index}].section_title'"
            raise CRAEvidenceError(msg, exit_code=1)
        score = _numeric_field(section.get("score"), f"sections[{index}].score")
        if score < 0 or score > max_score:
            msg = (
                f"sbomqs JSON 'sections[{index}].score' is outside "
                "the report score range"
            )
            raise CRAEvidenceError(msg, exit_code=1)
        scores_by_area.setdefault(area, []).append(score)
        element_id = section.get("element_id")
        if element_id is not None and not isinstance(element_id, str):
            msg = f"sbomqs JSON 'sections[{index}].element_id' must be text"
            raise CRAEvidenceError(msg, exit_code=1)
        if element_id and element_id != "SBOM":
            component_ids.add(element_id)

    features = [
        FeatureScore(
            feature=area,
            score=sum(scores) / len(scores),
            max_score=max_score,
        )
        for area, scores in scores_by_area.items()
        if scores
    ]
    # Worst-first: lowest score/max_score ratio.
    worst = sorted(features, key=lambda f: f.score / f.max_score)[:3]

    run_info = payload.get("run")
    if run_info is None:
        run_info = {}
    if not isinstance(run_info, dict):
        msg = "sbomqs JSON 'run' must be an object"
        raise CRAEvidenceError(msg, exit_code=1)
    file_name = run_info.get("file_name")
    if file_name is not None and not isinstance(file_name, str):
        msg = "sbomqs JSON 'run.file_name' must be text"
        raise CRAEvidenceError(msg, exit_code=1)
    return SbomqsResult(
        file_name=file_name or str(sbom_path),
        num_components=len(component_ids),
        score_out_of_100=float(total_score) * (100.0 / max_score),
        worst_features=worst,
    )


def format_summary(result: SbomqsResult) -> str:
    """One-line-plus-worst summary suitable for CI logs."""
    head = (
        f"sbomqs bsi-v2.0: {result.score_out_of_100:.1f}/100 "
        f"({Path(result.file_name).name}, {result.num_components} components)"
    )
    if not result.worst_features:
        return head
    worst = ", ".join(
        f"{f.feature} {f.score:.0f}/{f.max_score:.0f}"
        for f in result.worst_features
    )
    return f"{head}\n  worst: {worst}"
