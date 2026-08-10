"""Fetch and verify the pinned official Opengrep release payload."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    sha256: str


LOCK_PATH = (
    Path(__file__).resolve().parent.parent
    / "cra_evidence_cli"
    / "_engine"
    / "opengrep-release.json"
)
LOCK = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
VERSION = str(LOCK["version"])
TAG = str(LOCK["tag"])
COMMIT = str(LOCK["commit"])
RELEASE_BASE = f"https://github.com/opengrep/opengrep/releases/download/{TAG}"
SOURCE_REPOSITORY = "https://github.com/opengrep/opengrep.git"
LICENSE_URL = f"https://raw.githubusercontent.com/opengrep/opengrep/{COMMIT}/LICENSE"
COPYRIGHT_URL = f"https://raw.githubusercontent.com/opengrep/opengrep/{COMMIT}/COPYRIGHT"
CERTIFICATE_IDENTITY = str(LOCK["certificate_identity"])
CERTIFICATE_ISSUER = str(LOCK["certificate_issuer"])
ASSETS = tuple(
    ReleaseAsset(name, sha256) for name, sha256 in LOCK["assets"].items()
)
EXCLUDED_SOURCE_PREFIXES = ("tests/semgrep-rules/",)


class FetchError(Exception):
    """The pinned release payload could not be verified."""


_NATIVE_LIBRARY_RE = re.compile(
    rb"(?:lib[A-Za-z0-9_+.-]+\.(?:so(?:\.[0-9.]+)?|dylib))\x00"
)


def _native_dependencies(binary: Path) -> list[str]:
    return sorted(
        {
            match.group(0).removesuffix(b"\x00").decode("ascii")
            for match in _NATIVE_LIBRARY_RE.finditer(binary.read_bytes())
        }
    )


def _run_git(
    git: str,
    arguments: list[str],
    *,
    cwd: Path | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(  # noqa: S603
        [git, *arguments],
        cwd=cwd,
        capture_output=True,
        text=text,
        timeout=1200,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr if text else result.stderr.decode(errors="replace")
        msg = f"git {' '.join(arguments[:2])} failed: {stderr.strip()[:600]}"
        raise FetchError(msg)
    return result


def _source_submodules(git: str, checkout: Path) -> list[dict[str, str]]:
    result = _run_git(git, ["submodule", "status", "--recursive"], cwd=checkout)
    submodules = []
    for raw_line in result.stdout.splitlines():
        if not raw_line or raw_line[0] != " ":
            msg = f"Opengrep source submodule is not at its pinned commit: {raw_line}"
            raise FetchError(msg)
        fields = raw_line[1:].split()
        if len(fields) < 2 or not re.fullmatch(r"[0-9a-f]{40}", fields[0]):
            msg = f"invalid Opengrep submodule status: {raw_line}"
            raise FetchError(msg)
        submodules.append({"commit": fields[0], "path": fields[1]})
    if not submodules:
        msg = "Opengrep source checkout contains no initialized submodules"
        raise FetchError(msg)
    return submodules


def _source_paths(git: str, checkout: Path) -> list[Path]:
    result = _run_git(
        git,
        ["ls-files", "--recurse-submodules", "-z"],
        cwd=checkout,
        text=False,
    )
    paths = []
    for raw_path in result.stdout.split(b"\x00"):
        if not raw_path:
            continue
        value = raw_path.decode("utf-8")
        if any(value.startswith(prefix) for prefix in EXCLUDED_SOURCE_PREFIXES):
            continue
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            msg = f"unsafe path in Opengrep source checkout: {value}"
            raise FetchError(msg)
        paths.append(path)
    return sorted(paths, key=lambda path: path.as_posix())


def _add_source_file(
    archive: tarfile.TarFile, checkout: Path, path: Path, root_name: str
) -> None:
    source = checkout / path
    stat = source.lstat()
    info = tarfile.TarInfo(f"{root_name}/{path.as_posix()}")
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if source.is_symlink():
        info.type = tarfile.SYMTYPE
        info.mode = 0o777
        info.linkname = os.readlink(source)
        archive.addfile(info)
        return
    if not source.is_file():
        msg = f"unsupported tracked source entry: {path}"
        raise FetchError(msg)
    info.mode = 0o755 if stat.st_mode & 0o111 else 0o644
    info.size = stat.st_size
    with source.open("rb") as content:
        archive.addfile(info, content)


def _archive_source_checkout(checkout: Path, destination: Path, git: str) -> dict:
    head = _run_git(git, ["rev-parse", "HEAD"], cwd=checkout).stdout.strip()
    if head != COMMIT:
        msg = f"Opengrep source checkout is {head}, expected {COMMIT}"
        raise FetchError(msg)
    submodules = _source_submodules(git, checkout)
    paths = _source_paths(git, checkout)
    source_manifest = {
        "project": "opengrep/opengrep",
        "commit": COMMIT,
        "tag": TAG,
        "submodules": submodules,
        "excluded_paths": [
            {
                "path": "tests/semgrep-rules",
                "reason": "non-build rule test corpus excluded from redistribution",
            }
        ],
    }
    manifest_bytes = (
        json.dumps(source_manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    root_name = f"opengrep-{COMMIT}"
    with destination.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as gz:
            with tarfile.open(
                fileobj=gz, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                root = tarfile.TarInfo(root_name)
                root.type = tarfile.DIRTYPE
                root.mode = 0o755
                root.mtime = 0
                archive.addfile(root)
                for path in paths:
                    _add_source_file(archive, checkout, path, root_name)
                info = tarfile.TarInfo(f"{root_name}/SOURCE-COMMITS.json")
                info.mode = 0o644
                info.mtime = 0
                info.size = len(manifest_bytes)
                archive.addfile(info, io.BytesIO(manifest_bytes))
    return {
        "submodule_count": len(submodules),
        "tracked_file_count": len(paths),
        "excluded_paths": source_manifest["excluded_paths"],
    }


def _build_source_archive(destination: Path, git: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="cra-opengrep-source-") as temporary:
        checkout = Path(temporary) / "checkout"
        _run_git(
            git,
            [
                "clone",
                "--quiet",
                "--recurse-submodules",
                "--shallow-submodules",
                "--branch",
                TAG,
                "--depth",
                "1",
                SOURCE_REPOSITORY,
                str(checkout),
            ],
        )
        return _archive_source_checkout(checkout, destination, git)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "github.com",
        "raw.githubusercontent.com",
    }:
        msg = f"refusing untrusted download URL: {url}"
        raise FetchError(msg)
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "craevidence-release"}
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        if response.status != 200:
            msg = f"download returned HTTP {response.status}: {url}"
            raise FetchError(msg)
        with destination.open("wb") as output:
            shutil.copyfileobj(response, output)


def _verify_signature(cosign: str, binary: Path, certificate: Path, signature: Path) -> None:
    command = [
        cosign,
        "verify-blob",
        "--certificate",
        str(certificate),
        "--signature",
        str(signature),
        "--certificate-identity",
        CERTIFICATE_IDENTITY,
        "--certificate-oidc-issuer",
        CERTIFICATE_ISSUER,
        str(binary),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        msg = f"signature verification failed for {binary.name}: {detail}"
        raise FetchError(msg)


def fetch_release(out_dir: Path, cosign: str, git: str = "git") -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        msg = f"output directory is not empty: {out_dir}"
        raise FetchError(msg)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest_assets = []
    for asset in ASSETS:
        binary = out_dir / asset.name
        certificate = out_dir / f"{asset.name}.cert"
        signature = out_dir / f"{asset.name}.sig"
        _download(f"{RELEASE_BASE}/{asset.name}", binary)
        _download(f"{RELEASE_BASE}/{asset.name}.cert", certificate)
        _download(f"{RELEASE_BASE}/{asset.name}.sig", signature)
        actual = _sha256(binary)
        if actual != asset.sha256:
            msg = f"SHA-256 mismatch for {asset.name}: {actual} != {asset.sha256}"
            raise FetchError(msg)
        _verify_signature(cosign, binary, certificate, signature)
        binary.chmod(0o755)
        manifest_assets.append(
            {
                **asdict(asset),
                "signature_verified": True,
                "native_dependencies": _native_dependencies(binary),
            }
        )

    license_path = out_dir / "LICENSE"
    copyright_path = out_dir / "COPYRIGHT"
    source_path = out_dir / f"opengrep-{VERSION}-source.tar.gz"
    _download(LICENSE_URL, license_path)
    _download(COPYRIGHT_URL, copyright_path)
    source_details = _build_source_archive(source_path, git)
    (out_dir / "NOTICE").write_text(
        "This product includes Opengrep, licensed under the GNU Lesser General "
        f"Public License version 2.1. Source commit: {COMMIT}. The upstream "
        "repository is https://github.com/opengrep/opengrep. The matching CRA "
        f"Evidence CLI GitHub release includes opengrep-{VERSION}-source.tar.gz. "
        "Upstream copyright notices and the native dependency inventory accompany "
        "this notice.\n",
        encoding="utf-8",
    )
    native_dependencies = {
        asset["name"]: asset["native_dependencies"] for asset in manifest_assets
    }
    (out_dir / "NATIVE-DEPENDENCIES.json").write_text(
        json.dumps(native_dependencies, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "SHA256SUMS").write_text(
        "".join(f"{asset.sha256}  {asset.name}\n" for asset in ASSETS),
        encoding="utf-8",
    )
    manifest = {
        "project": "opengrep/opengrep",
        "version": VERSION,
        "tag": TAG,
        "commit": COMMIT,
        "release_url": f"https://github.com/opengrep/opengrep/releases/tag/{TAG}",
        "certificate_identity": CERTIFICATE_IDENTITY,
        "certificate_issuer": CERTIFICATE_ISSUER,
        "source_archive": {
            "name": source_path.name,
            "repository": SOURCE_REPOSITORY,
            "sha256": _sha256(source_path),
            "commit": COMMIT,
            "signature_verified": False,
            "verification": "exact-commit-recursive-submodules-deterministic-archive",
            **source_details,
        },
        "assets": manifest_assets,
    }
    (out_dir / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--cosign", default=shutil.which("cosign"))
    parser.add_argument("--git", default=shutil.which("git"))
    args = parser.parse_args()
    if not args.cosign:
        parser.error("cosign is required to verify the official release signatures")
    if not args.git:
        parser.error("git is required to collect the pinned source submodules")
    try:
        fetch_release(args.out_dir, args.cosign, args.git)
    except (FetchError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
