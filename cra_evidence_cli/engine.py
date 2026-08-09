"""Identity verification for the CRA Evidence Grype engine."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_VERSION_TIMEOUT_SECONDS = 10
_SYFT_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SBOM_USAGE = "grype sbom SOURCE"
_SBOM_OFFLINE_FLAG = "--offline"


@dataclass(frozen=True)
class EngineIdentity:
    path: str
    version: str
    syft_version: str


@dataclass(frozen=True)
class EngineInspection:
    identity: EngineIdentity | None
    reason: str


def _bundled_engine_path() -> Path:
    return Path(__file__).resolve().parent / "_engine" / "grype"


def _resolve_engine_path(path: str | None = None) -> tuple[str | None, str | None]:
    if path:
        return path, None

    configured = os.getenv("CRA_EVIDENCE_ENGINE")
    if configured:
        return configured, None

    bundled = _bundled_engine_path()
    if bundled.is_file():
        if not os.access(bundled, os.X_OK):
            return None, "the bundled engine is not executable"
        return str(bundled), None

    return shutil.which("grype"), None


def inspect_engine(path: str | None = None) -> EngineInspection:
    resolved, resolution_error = _resolve_engine_path(path)
    if resolution_error:
        return EngineInspection(None, resolution_error)
    if not resolved:
        return EngineInspection(None, "the CRA Evidence engine is not installed")

    try:
        result = subprocess.run(  # noqa: S603
            [resolved, "version", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return EngineInspection(None, f"could not read engine identity: {exc}")

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return EngineInspection(None, detail or "engine identity command failed")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return EngineInspection(None, "engine identity output is not valid JSON")
    if not isinstance(payload, dict):
        return EngineInspection(None, "engine identity output is not a JSON object")

    if payload.get("application") != "grype":
        return EngineInspection(None, "the executable does not identify as Grype")

    version = str(payload.get("version") or "").strip()
    if not version.startswith("craevidence-"):
        return EngineInspection(None, "stock or unstamped Grype is not a supported engine")

    syft_version = str(payload.get("syftVersion") or "").strip().lstrip("v")
    if not _SYFT_VERSION_PATTERN.fullmatch(syft_version):
        return EngineInspection(None, "the embedded Syft version is missing or invalid")

    try:
        capability = subprocess.run(  # noqa: S603
            [resolved, "sbom", "--help"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return EngineInspection(None, f"could not verify SBOM generation support: {exc}")
    capability_output = f"{capability.stdout}\n{capability.stderr}"
    if (
        capability.returncode != 0
        or _SBOM_USAGE not in capability_output
        or _SBOM_OFFLINE_FLAG not in capability_output
    ):
        return EngineInspection(
            None,
            "the installed CRA Evidence engine does not support the required "
            "SBOM generation options",
        )

    return EngineInspection(
        EngineIdentity(
            path=resolved,
            version=version,
            syft_version=syft_version,
        ),
        "",
    )


def engine_installation_message(reason: str) -> str:
    return (
        "A compatible CRA Evidence engine is required. Install this CLI from a "
        "supported platform wheel, use the CRA Evidence CLI container, or set "
        f"CRA_EVIDENCE_ENGINE to a verified engine path. Detected state: {reason}."
    )
