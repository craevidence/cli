"""SBOM generation from Docker images or source directories using Syft."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cra_evidence_cli.exceptions import CRAEvidenceError

_SYFT_IMAGE = "anchore/syft:v1.44.0"


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
    generation_method: str  # "syft" or "docker"


def check_syft_installed() -> bool:
    return shutil.which("syft") is not None


def check_docker_installed() -> bool:
    return shutil.which("docker") is not None


def _count_components(sbom_path: Path) -> int:
    """Count components in a CycloneDX or SPDX SBOM."""
    try:
        with open(sbom_path) as f:
            data = json.load(f)
        # CycloneDX uses "components", SPDX uses "packages"
        return len(data.get("components", data.get("packages", [])))
    except (json.JSONDecodeError, KeyError):
        return 0


def _get_syft_version() -> tuple[int, int, int] | None:
    """Get the installed Syft version as a (major, minor, patch) tuple."""
    try:
        result = subprocess.run(
            ["syft", "version", "--output", "json"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            version_str = data.get("version", "")
            parts = version_str.lstrip("v").split(".")
            if len(parts) >= 3:
                return (int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:  # noqa: S110
        pass
    return None


def _generate_sbom_with_local_syft(
    image: str,
    output_format: str,
    output_path: Path,
    verbose: bool = False,
    offline: bool = False,
) -> None:
    """Generate SBOM using locally installed Syft."""
    # Map format names to Syft output format
    format_map = {
        "cyclonedx": "cyclonedx-json",
        "spdx": "spdx-json",
    }
    syft_format = format_map.get(output_format, "cyclonedx-json")

    cmd = [
        "syft",
        "scan",
        image,
        "-o",
        f"{syft_format}={output_path}",
    ]

    # Exclude file-level catalogers to keep SBOMs package-focused.
    # These catalogers (file-content, file-digest, file-executable, file-metadata)
    # were added in Syft v1.18+. On older versions they don't exist, so passing
    # their names to --select-catalogers causes a hard error. Only add the exclusion
    # when running a version that supports them.
    syft_version = _get_syft_version()
    if syft_version and syft_version >= (1, 18, 0):
        cmd += [
            "--select-catalogers",
            "-file-content-cataloger,-file-digest-cataloger,"
            "-file-executable-cataloger,-file-metadata-cataloger",
        ]

    if verbose:
        cmd.append("-v")

    # In offline mode, disable Syft's GitHub application-update check so the
    # generation step makes no network call. A directory scan otherwise reads
    # only local files.
    env = {**os.environ}
    if offline:
        env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            env=env,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            msg = f"Syft failed to generate SBOM: {error_msg}"
            raise SBOMGenerationError(
                msg
            )

    except subprocess.TimeoutExpired:
        msg = (
            f"SBOM generation timed out for image '{image}'. "
            "The image may be very large or the Docker daemon may be slow."
        )
        raise SBOMGenerationError(
            msg
        ) from None
    except FileNotFoundError:
        msg = (
            "Syft binary not found. Please install Syft: "
            "https://github.com/anchore/syft#installation"
        )
        raise SBOMGenerationError(
            msg
        ) from None


def _generate_sbom_with_docker(
    image: str,
    output_format: str,
    output_path: Path,
    verbose: bool = False,
) -> None:
    """Generate SBOM using Syft via Docker container."""
    format_map = {
        "cyclonedx": "cyclonedx-json",
        "spdx": "spdx-json",
    }
    syft_format = format_map.get(output_format, "cyclonedx-json")

    print(
        "WARNING: Using Docker socket fallback to run Syft. "
        "Mounting /var/run/docker.sock grants the container elevated access to the "
        "Docker daemon, equivalent to root on the host. "
        "Install Syft locally to avoid this risk: "
        "https://github.com/anchore/syft#installation",
        file=sys.stderr,
    )

    # Run syft in a container, mounting the Docker socket
    cmd = [
        "docker",
        "run",
        "--rm",
        "--security-opt=no-new-privileges",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        _SYFT_IMAGE,
        image,
        "-o",
        syft_format,
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            if "Cannot connect to the Docker daemon" in error_msg:
                msg = "Docker daemon is not running. Please start Docker and try again."
                raise SBOMGenerationError(
                    msg
                )
            if "manifest unknown" in error_msg or "not found" in error_msg.lower():
                msg = (
                    f"Image '{image}' not found. Ensure the image exists and "
                    "you have access to pull it."
                )
                raise SBOMGenerationError(
                    msg
                )
            msg = f"Failed to generate SBOM with Docker: {error_msg}"
            raise SBOMGenerationError(
                msg
            )

        with open(output_path, "w") as f:
            f.write(result.stdout)

    except subprocess.TimeoutExpired:
        msg = f"SBOM generation timed out for image '{image}'."
        raise SBOMGenerationError(
            msg
        ) from None
    except FileNotFoundError:
        msg = "Docker is not installed. Please install Docker or Syft directly."
        raise SBOMGenerationError(
            msg
        ) from None


def generate_sbom_from_directory(
    directory: str,
    output_format: str = "cyclonedx",
    verbose: bool = False,
    offline: bool = False,
) -> SBOMGenerationResult:
    """
    Generate an SBOM from a source directory using Syft.

    Syft accepts `dir:/path` as input to scan source directories for dependencies.
    This does not require Docker - only Syft needs to be installed (bundled in CLI image).

    Args:
        directory: Path to source directory to scan
        output_format: SBOM format ("cyclonedx" or "spdx")
        verbose: Enable verbose output

    Returns:
        SBOMGenerationResult with path to generated SBOM file

    Raises:
        SBOMGenerationError: If SBOM generation fails
    """
    if output_format not in ("cyclonedx", "spdx"):
        msg = f"Unsupported format '{output_format}'. Use 'cyclonedx' or 'spdx'."
        raise SBOMGenerationError(
            msg
        )

    dir_path = Path(directory)
    if not dir_path.is_dir():
        msg = f"Directory '{directory}' does not exist or is not a directory."
        raise SBOMGenerationError(
            msg
        )

    if not check_syft_installed():
        msg = (
            "Syft is not installed. Install: https://github.com/anchore/syft#installation\n"
            "When using the CRA Evidence Docker image, Syft is bundled automatically."
        )
        raise SBOMGenerationError(
            msg
        )

    # Create a private temporary directory (0o700) and place the SBOM file inside it
    temp_dir = tempfile.mkdtemp(prefix="sbom_")
    os.chmod(temp_dir, 0o700)
    output_path = Path(temp_dir) / "sbom.json"

    try:
        _generate_sbom_with_local_syft(
            f"dir:{directory}", output_format, output_path, verbose, offline=offline
        )

        if not output_path.exists() or output_path.stat().st_size == 0:
            msg = f"SBOM generation produced no output for directory '{directory}'"
            raise SBOMGenerationError(
                msg
            )

        component_count = _count_components(output_path)

        return SBOMGenerationResult(
            file_path=output_path,
            component_count=component_count,
            format_type=output_format,
            generation_method="syft",
        )

    except SBOMGenerationError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        msg = f"Unexpected error generating SBOM: {e}"
        raise SBOMGenerationError(msg) from e


def generate_sbom_from_image(
    image: str,
    output_format: str = "cyclonedx",
    verbose: bool = False,
) -> SBOMGenerationResult:
    """
    Generate an SBOM from a Docker image.

    This function tries to use locally installed Syft first. If Syft is not
    available, it falls back to running Syft via Docker.

    Args:
        image: Docker image reference (e.g., "nginx:latest", "alpine:3.19")
        output_format: SBOM format ("cyclonedx" or "spdx")
        verbose: Enable verbose output

    Returns:
        SBOMGenerationResult with path to generated SBOM file

    Raises:
        SBOMGenerationError: If SBOM generation fails
    """
    if output_format not in ("cyclonedx", "spdx"):
        msg = f"Unsupported format '{output_format}'. Use 'cyclonedx' or 'spdx'."
        raise SBOMGenerationError(
            msg
        )

    # Create a private temporary directory (0o700) and place the SBOM file inside it
    temp_dir = tempfile.mkdtemp(prefix="sbom_")
    os.chmod(temp_dir, 0o700)
    output_path = Path(temp_dir) / "sbom.json"

    try:
        if check_syft_installed():
            _generate_sbom_with_local_syft(
                image, output_format, output_path, verbose
            )
            method = "syft"
        elif check_docker_installed():
            # Fall back to Docker-based Syft
            _generate_sbom_with_docker(
                image, output_format, output_path, verbose
            )
            method = "docker"
        else:
            msg = (
                "Neither Syft nor Docker is installed. "
                "Please install Syft (https://github.com/anchore/syft#installation) "
                "or Docker to generate SBOMs from images."
            )
            raise SBOMGenerationError(
                msg
            )

        if not output_path.exists() or output_path.stat().st_size == 0:
            msg = f"SBOM generation produced no output for image '{image}'"
            raise SBOMGenerationError(
                msg
            )

        component_count = _count_components(output_path)

        return SBOMGenerationResult(
            file_path=output_path,
            component_count=component_count,
            format_type=output_format,
            generation_method=method,
        )

    except SBOMGenerationError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        msg = f"Unexpected error generating SBOM: {e}"
        raise SBOMGenerationError(msg) from e
