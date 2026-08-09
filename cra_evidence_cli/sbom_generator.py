"""SBOM generation from container images or source directories."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cra_evidence_cli.engine import engine_installation_message, inspect_engine
from cra_evidence_cli.exceptions import CRAEvidenceError

_GENERATION_TIMEOUT_SECONDS = 300


class SBOMGenerationError(CRAEvidenceError):
    """Error during SBOM generation."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message, exit_code)


@dataclass
class SBOMGenerationResult:
    """Result of SBOM generation."""

    file_path: Path
    component_count: int
    format_type: str
    generation_method: str


def cleanup_generated_sbom(file_path: str | Path) -> None:
    """Remove the private temp directory holding a generated SBOM.

    Only directories created by generate_sbom_from_* (mkdtemp under the
    system temp dir with the sbom_ prefix) are removed, so a user-supplied
    SBOM path can never cause project files to be deleted.
    """
    parent = Path(file_path).parent
    try:
        in_tmp = parent.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    except OSError:
        return
    if in_tmp and parent.name.startswith("sbom_"):
        shutil.rmtree(parent, ignore_errors=True)


def _count_components(sbom_path: Path) -> int:
    """Count components in a CycloneDX or SPDX SBOM."""
    try:
        with open(sbom_path) as f:
            data = json.load(f)
        return len(data.get("components", data.get("packages", [])))
    except (json.JSONDecodeError, KeyError):
        return 0


def get_embedded_syft_version() -> str | None:
    inspection = inspect_engine()
    if inspection.identity is None:
        return None
    return inspection.identity.syft_version


def _generate_sbom_with_engine(
    source: str,
    output_format: str,
    output_path: Path,
    verbose: bool = False,
    offline: bool = False,
) -> None:
    format_map = {
        "cyclonedx": "cyclonedx-json",
        "spdx": "spdx-json",
    }
    engine_format = format_map.get(output_format, "cyclonedx-json")

    inspection = inspect_engine()
    if inspection.identity is None:
        raise SBOMGenerationError(engine_installation_message(inspection.reason))

    cmd = [
        inspection.identity.path,
        "sbom",
        source,
        "--output",
        engine_format,
        "--file",
        str(output_path),
    ]
    if verbose:
        cmd.append("-v")
    if offline:
        cmd.append("--offline")

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=_GENERATION_TIMEOUT_SECONDS,
            env={**os.environ, "GRYPE_CHECK_FOR_APP_UPDATE": "false"},
        )
    except subprocess.TimeoutExpired:
        msg = (
            f"SBOM generation timed out for source '{source}'. "
            "The source may be very large or its registry may be slow."
        )
        raise SBOMGenerationError(msg) from None
    except FileNotFoundError:
        msg = engine_installation_message("the engine executable disappeared from PATH")
        raise SBOMGenerationError(msg) from None

    if result.returncode != 0:
        error_msg = result.stderr.strip() or result.stdout.strip()
        if "unknown command" in error_msg and "sbom" in error_msg:
            msg = engine_installation_message(
                "the installed CRA Evidence engine does not support SBOM generation"
            )
        else:
            msg = f"CRA Evidence engine failed to generate SBOM: {error_msg}"
        raise SBOMGenerationError(msg)


def _validate_format(output_format: str) -> None:
    if output_format not in ("cyclonedx", "spdx"):
        msg = f"Unsupported format '{output_format}'. Use 'cyclonedx' or 'spdx'."
        raise SBOMGenerationError(msg)


def _generate_sbom(
    source: str,
    target_label: str,
    output_format: str,
    verbose: bool,
    offline: bool,
) -> SBOMGenerationResult:
    temp_dir = tempfile.mkdtemp(prefix="sbom_")
    os.chmod(temp_dir, 0o700)
    output_path = Path(temp_dir) / "sbom.json"

    try:
        _generate_sbom_with_engine(
            source,
            output_format,
            output_path,
            verbose,
            offline=offline,
        )
        if not output_path.exists() or output_path.stat().st_size == 0:
            msg = f"SBOM generation produced no output for {target_label}"
            raise SBOMGenerationError(msg)

        return SBOMGenerationResult(
            file_path=output_path,
            component_count=_count_components(output_path),
            format_type=output_format,
            generation_method="craevidence-grype",
        )
    except SBOMGenerationError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        msg = f"Unexpected error generating SBOM: {exc}"
        raise SBOMGenerationError(msg) from exc


def generate_sbom_from_directory(
    directory: str,
    output_format: str = "cyclonedx",
    verbose: bool = False,
    offline: bool = False,
) -> SBOMGenerationResult:
    """Generate an SBOM from a source directory using the CRA Evidence engine."""
    _validate_format(output_format)

    dir_path = Path(directory)
    if not dir_path.is_dir():
        msg = f"Directory '{directory}' does not exist or is not a directory."
        raise SBOMGenerationError(msg)

    return _generate_sbom(
        source=f"dir:{directory}",
        target_label=f"directory '{directory}'",
        output_format=output_format,
        verbose=verbose,
        offline=offline,
    )


def generate_sbom_from_image(
    image: str,
    output_format: str = "cyclonedx",
    verbose: bool = False,
) -> SBOMGenerationResult:
    """Generate an SBOM from a container image using the CRA Evidence engine."""
    _validate_format(output_format)
    return _generate_sbom(
        source=image,
        target_label=f"image '{image}'",
        output_format=output_format,
        verbose=verbose,
        offline=False,
    )
