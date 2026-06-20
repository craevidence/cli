"""
Optional BSI TR-03183-2 v2 pre-upload check via the sbomqs binary.

Wraps `sbomqs score -c bsi-v2.0 --json <file>` so `upload-sbom` can score
an SBOM locally before sending it to the platform. Surfaces ~10 BSI/CRA
checks the platform's own `quality_score` does not compute (per-component
VCS/executable URIs and hashes, dependency-graph completeness, SBOM
authors/build-phase/bomlinks/signature).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cra_evidence_cli.exceptions import CRAEvidenceError

SBOMQS_BINARY = "sbomqs"
SBOMQS_TIMEOUT_SECONDS = 120
SBOMQS_INSTALL_HINT = (
    "Install sbomqs to use --sbomqs-check: "
    "`go install github.com/interlynk-io/sbomqs@latest`, "
    "`brew install interlynk-io/interlynk/sbomqs`, or download a release "
    "from https://github.com/interlynk-io/sbomqs/releases."
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
    """Run sbomqs against the SBOM and return the parsed result.

    Raises CRAEvidenceError when the binary is missing, the subprocess
    fails, the output is unparseable, or the expected `files[0]` shape
    is absent.
    """
    sbomqs_bin = binary or discover_sbomqs()
    try:
        completed = subprocess.run(  # noqa: S603
            [sbomqs_bin, "score", "-c", "bsi-v2.0", "--json", str(sbom_path)],
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

    files = payload.get("files") or []
    if not files:
        msg = "sbomqs returned no scored files in JSON output"
        raise CRAEvidenceError(
            msg,
            exit_code=1,
        )

    first = files[0]
    avg_score = first.get("avg_score")
    if not isinstance(avg_score, (int, float)):
        msg = "sbomqs JSON missing 'avg_score' on files[0]"
        raise CRAEvidenceError(
            msg,
            exit_code=1,
        )

    scores_raw = first.get("scores") or []
    features = [
        FeatureScore(
            feature=str(s.get("feature", "?")),
            score=float(s.get("score") or 0),
            max_score=float(s.get("max_score") or 0),
        )
        for s in scores_raw
        if not s.get("ignored", False) and (s.get("max_score") or 0) > 0
    ]
    # Worst-first: lowest score/max_score ratio.
    worst = sorted(features, key=lambda f: f.score / f.max_score)[:3]

    return SbomqsResult(
        file_name=str(first.get("file_name") or sbom_path),
        num_components=int(first.get("num_components") or 0),
        score_out_of_100=float(avg_score) * 10,
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
