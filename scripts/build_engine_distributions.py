"""Build platform wheels from one promoted CRA Evidence engine payload.

The engine directory must be the ``/engine`` payload extracted from the pinned
engine image. No engine is rebuilt here. Linux manylinux and musllinux wheels
are packaged separately from the same promoted static binary bytes.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SOURCE_DATE_EPOCH = "946684800"
ENGINE_PACKAGE_PATH = Path("cra_evidence_cli/_engine")
ENGINE_BINARY_PATH = ENGINE_PACKAGE_PATH / "grype"


@dataclass(frozen=True)
class WheelTarget:
    engine_name: str
    platform_tag: str
    retag_platforms: tuple[str, ...] = ()


WHEEL_TARGETS = (
    WheelTarget(
        "grype-linux-amd64",
        "manylinux_2_17_x86_64",
        ("musllinux_1_2_x86_64",),
    ),
    WheelTarget(
        "grype-linux-arm64",
        "manylinux_2_17_aarch64",
        ("musllinux_1_2_aarch64",),
    ),
    WheelTarget("grype-darwin-amd64", "macosx_12_0_x86_64"),
    WheelTarget("grype-darwin-arm64", "macosx_12_0_arm64"),
)


class DistributionBuildError(Exception):
    """The promoted payload or a built distribution failed verification."""


@contextmanager
def _release_umask():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def expected_wheel_filenames(version: str) -> tuple[str, ...]:
    tags = [
        tag
        for target in WHEEL_TARGETS
        for tag in (target.platform_tag, *target.retag_platforms)
    ]
    return tuple(f"craevidence-{version}-py3-none-{tag}.whl" for tag in tags)


def expected_distribution_filenames(version: str) -> tuple[str, ...]:
    return (*expected_wheel_filenames(version), f"craevidence-{version}.tar.gz")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_hashes(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) != 2 or len(fields[0]) != 64:
            msg = f"invalid SHA256SUMS line: {line!r}"
            raise DistributionBuildError(msg)
        name = Path(fields[1].lstrip("*")).name
        result[name] = fields[0]
    return result


def _validate_static_elf(path: Path, expected_machine: int) -> None:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2:
        msg = f"{path.name} is not a 64-bit ELF executable"
        raise DistributionBuildError(msg)
    if data[5] == 1:
        byteorder = "little"
    elif data[5] == 2:
        byteorder = "big"
    else:
        msg = f"{path.name} has an invalid ELF byte order"
        raise DistributionBuildError(msg)
    machine = int.from_bytes(data[18:20], byteorder)
    if machine != expected_machine:
        msg = f"{path.name} has ELF machine {machine}, expected {expected_machine}"
        raise DistributionBuildError(msg)
    program_offset = int.from_bytes(data[32:40], byteorder)
    entry_size = int.from_bytes(data[54:56], byteorder)
    entry_count = int.from_bytes(data[56:58], byteorder)
    table_end = program_offset + entry_size * entry_count
    if table_end > len(data):
        msg = f"{path.name} has a truncated ELF program table"
        raise DistributionBuildError(msg)
    for index in range(entry_count):
        offset = program_offset + entry_size * index
        if entry_size < 4:
            msg = f"{path.name} has an invalid ELF program-header size"
            raise DistributionBuildError(msg)
        program_type = int.from_bytes(data[offset : offset + 4], byteorder)
        if program_type == 3:
            msg = (
                f"{path.name} is dynamically linked and cannot back both "
                "manylinux and musllinux wheels"
            )
            raise DistributionBuildError(msg)


def _validate_macho(path: Path, expected_cpu: int) -> None:
    header = path.read_bytes()[:8]
    if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
        msg = f"{path.name} is not a 64-bit Mach-O executable"
        raise DistributionBuildError(msg)
    cpu = int.from_bytes(header[4:8], "little")
    if cpu != expected_cpu:
        msg = f"{path.name} has Mach-O CPU {cpu}, expected {expected_cpu}"
        raise DistributionBuildError(msg)


def _validate_binary_shape(target: WheelTarget, path: Path) -> None:
    expected = {
        "grype-linux-amd64": ("elf", 62),
        "grype-linux-arm64": ("elf", 183),
        "grype-darwin-amd64": ("macho", 0x01000007),
        "grype-darwin-arm64": ("macho", 0x0100000C),
    }[target.engine_name]
    if expected[0] == "elf":
        _validate_static_elf(path, expected[1])
    else:
        _validate_macho(path, expected[1])


def validate_engine_payload(engine_dir: Path) -> None:
    required_text = {
        "LICENSE": "Apache License",
        "NOTICE": "modified build of Anchore Grype",
    }
    for name, marker in required_text.items():
        path = engine_dir / name
        if not path.is_file() or marker not in path.read_text(encoding="utf-8"):
            msg = f"engine payload {name} is missing or does not contain {marker!r}"
            raise DistributionBuildError(msg)

    manifest_path = engine_dir / "SHA256SUMS"
    if not manifest_path.is_file():
        msg = "engine payload is missing SHA256SUMS"
        raise DistributionBuildError(msg)
    manifest = _manifest_hashes(manifest_path)

    for target in WHEEL_TARGETS:
        binary = engine_dir / target.engine_name
        if not binary.is_file() or binary.is_symlink():
            msg = f"engine payload is missing regular file {target.engine_name}"
            raise DistributionBuildError(msg)
        suffix = target.engine_name.removeprefix("grype-")
        matching = [value for name, value in manifest.items() if name.endswith(suffix)]
        if len(matching) != 1:
            msg = f"SHA256SUMS has {len(matching)} entries for {target.engine_name}"
            raise DistributionBuildError(msg)
        actual = _sha256_file(binary)
        if actual != matching[0]:
            msg = f"SHA-256 mismatch for {target.engine_name}: {actual} != {matching[0]}"
            raise DistributionBuildError(msg)
        _validate_binary_shape(target, binary)


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(command, env=env, check=False)  # noqa: S603
    if result.returncode != 0:
        msg = f"command failed with exit {result.returncode}: {' '.join(command)}"
        raise DistributionBuildError(msg)


def _copy_release_source(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git",
        ".venv",
        "build",
        "dist",
        "*.egg-info",
        "__pycache__",
        "*.pyc",
    )
    shutil.copytree(source, destination, ignore=ignored)


def _validate_engine_free_source(release_src: Path) -> None:
    engine_binary = release_src / ENGINE_BINARY_PATH
    if engine_binary.exists() or engine_binary.is_symlink():
        msg = (
            "source distribution input contains the bundled engine executable: "
            f"{engine_binary}"
        )
        raise DistributionBuildError(msg)


def _build_platform_wheel(
    release_src: Path,
    engine_dir: Path,
    target: WheelTarget,
    output_dir: Path,
) -> Path:
    with tempfile.TemporaryDirectory() as temporary:
        staged_source = Path(temporary) / "source"
        build_output = Path(temporary) / "dist"
        _copy_release_source(release_src, staged_source)
        package_dir = staged_source / ENGINE_PACKAGE_PATH
        package_dir.mkdir(parents=True, exist_ok=True)
        binary = package_dir / "grype"
        shutil.copy2(engine_dir / target.engine_name, binary)
        binary.chmod(0o755)
        shutil.copy2(engine_dir / "LICENSE", package_dir / "LICENSE")
        shutil.copy2(engine_dir / "NOTICE", package_dir / "NOTICE")

        env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--outdir",
                str(build_output),
                (
                    "--config-setting=--build-option="
                    f"--plat-name={target.platform_tag}"
                ),
                str(staged_source),
            ],
            env=env,
        )
        wheels = list(build_output.glob("*.whl"))
        if len(wheels) != 1:
            msg = f"expected one {target.platform_tag} wheel, found {wheels}"
            raise DistributionBuildError(msg)
        built = output_dir / wheels[0].name
        shutil.copy2(wheels[0], built)
        return built


def _engine_hash_in_wheel(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith("/_engine/grype")]
        if len(names) != 1:
            msg = f"{wheel.name} contains {len(names)} bundled engine files"
            raise DistributionBuildError(msg)
        return hashlib.sha256(archive.read(names[0])).hexdigest()


def _normalize_sdist(source: Path, destination: Path) -> None:
    epoch = int(SOURCE_DATE_EPOCH)
    with tarfile.open(source, "r:gz") as input_archive:
        members = sorted(input_archive.getmembers(), key=lambda item: item.name)
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                msg = f"unsafe path in built source distribution: {member.name}"
                raise DistributionBuildError(msg)

        with destination.open("wb") as output_file:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=output_file,
                mtime=epoch,
            ) as gzip_file:
                with tarfile.open(
                    fileobj=gzip_file,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as output_archive:
                    for original in members:
                        normalized = copy.copy(original)
                        normalized.mtime = epoch
                        normalized.uid = 0
                        normalized.gid = 0
                        normalized.uname = ""
                        normalized.gname = ""
                        normalized.pax_headers = {}
                        if original.isfile():
                            content = input_archive.extractfile(original)
                            if content is None:
                                msg = f"could not read {original.name} from source distribution"
                                raise DistributionBuildError(msg)
                            with content:
                                output_archive.addfile(normalized, content)
                        else:
                            output_archive.addfile(normalized)


def _build_sdist(release_src: Path, output_dir: Path, env: dict[str, str]) -> Path:
    with tempfile.TemporaryDirectory() as temporary:
        raw_output = Path(temporary)
        _run(
            [
                sys.executable,
                "-m",
                "build",
                "--sdist",
                "--outdir",
                str(raw_output),
                str(release_src),
            ],
            env=env,
        )
        sdists = list(raw_output.glob("*.tar.gz"))
        if len(sdists) != 1:
            msg = f"expected one source distribution, found {sdists}"
            raise DistributionBuildError(msg)
        normalized = output_dir / sdists[0].name
        _normalize_sdist(sdists[0], normalized)
        return normalized


def build_distributions(
    version: str,
    release_src: Path,
    engine_dir: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    with _release_umask():
        return _build_distributions(version, release_src, engine_dir, output_dir)


def _build_distributions(
    version: str,
    release_src: Path,
    engine_dir: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    validate_engine_payload(engine_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    produced: list[Path] = []

    sdist = build_source_distribution(version, release_src, output_dir)

    for target in WHEEL_TARGETS:
        original_engine_hash = _sha256_file(engine_dir / target.engine_name)
        for platform_tag in (target.platform_tag, *target.retag_platforms):
            build_target = WheelTarget(target.engine_name, platform_tag)
            wheel = _build_platform_wheel(
                release_src,
                engine_dir,
                build_target,
                output_dir,
            )
            if _engine_hash_in_wheel(wheel) != original_engine_hash:
                msg = f"{wheel.name} does not contain the promoted engine bytes"
                raise DistributionBuildError(msg)
            produced.append(wheel)

    expected_sdist = output_dir / f"craevidence-{version}.tar.gz"
    if sdist != expected_sdist or not sdist.is_file():
        msg = f"build output is missing {sdist.name}"
        raise DistributionBuildError(msg)
    produced.append(sdist)

    expected = set(expected_distribution_filenames(version))
    actual = {path.name for path in produced}
    if actual != expected:
        msg = f"distribution set mismatch: expected {sorted(expected)}, got {sorted(actual)}"
        raise DistributionBuildError(msg)
    return tuple(produced)


def build_source_distribution(version: str, release_src: Path, output_dir: Path) -> Path:
    with _release_umask():
        return _build_source_distribution(version, release_src, output_dir)


def _build_source_distribution(
    version: str,
    release_src: Path,
    output_dir: Path,
) -> Path:
    _validate_engine_free_source(release_src)
    output_dir.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
    sdist = _build_sdist(release_src, output_dir, env)
    expected = output_dir / f"craevidence-{version}.tar.gz"
    if sdist != expected:
        msg = f"source distribution mismatch: expected {expected.name}, got {sdist.name}"
        raise DistributionBuildError(msg)
    return sdist


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build CRA Evidence platform wheels from a promoted engine payload.",
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-src", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--sdist-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.sdist_only:
            build_source_distribution(args.version, args.release_src, args.out_dir)
        else:
            if args.engine_dir is None:
                msg = "--engine-dir is required for platform wheels"
                raise DistributionBuildError(msg)
            build_distributions(
                args.version,
                args.release_src,
                args.engine_dir,
                args.out_dir,
            )
    except DistributionBuildError as error:
        sys.stderr.write(f"engine distribution build failed: {error}\n")
        return 1
    names = (
        (f"craevidence-{args.version}.tar.gz",)
        if args.sdist_only
        else expected_distribution_filenames(args.version)
    )
    for name in names:
        sys.stdout.write(f"built {name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
