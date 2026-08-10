#!/usr/bin/env python3
"""Fetch exact, manifest-pinned rule-pack evidence corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_PROJECTS = REPO_ROOT / "tests" / "rulepack_real_projects.json"
BENCHMARKS = REPO_ROOT / "tests" / "rulepack_benchmarks.json"
DOWNLOAD_USER_AGENT = (
    "CRA-Evidence-CLI-rulepack-evidence/1.0 "
    "(+https://github.com/craevidence/cli)"
)


class CorpusFetchError(RuntimeError):
    pass


def _entries(real_projects: Path, benchmarks: Path) -> list[dict]:
    real = json.loads(real_projects.read_text(encoding="utf-8"))["projects"]
    benchmark = json.loads(benchmarks.read_text(encoding="utf-8"))["benchmarks"]
    entries = [*real, *benchmark]
    directories = [str(entry["directory"]) for entry in entries]
    if len(set(directories)) != len(directories):
        message = "corpus directory names must be unique"
        raise CorpusFetchError(message)
    return entries


def _run(command: list[str]) -> None:
    result = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:600]
        message = f"command failed: {command[0]}: {detail}"
        raise CorpusFetchError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, target: Path) -> None:
    if urllib.parse.urlsplit(url).scheme != "https":
        message = f"download URL must use HTTPS: {url}"
        raise CorpusFetchError(message)
    request = urllib.request.Request(  # noqa: S310 - HTTPS is required above
        url,
        headers={"User-Agent": DOWNLOAD_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            with target.open("wb") as handle:
                shutil.copyfileobj(response, handle)
    except OSError as exc:
        message = f"download failed: {url}: {exc}"
        raise CorpusFetchError(message) from exc


def _verify_file(path: Path, *, size: int, sha256: str) -> None:
    actual_size = path.stat().st_size
    if actual_size != size:
        message = f"unexpected size for {path.name}: {actual_size}, expected {size}"
        raise CorpusFetchError(message)
    actual_hash = _sha256(path)
    if actual_hash != sha256:
        message = f"unexpected SHA-256 for {path.name}: {actual_hash}"
        raise CorpusFetchError(message)


def _validate_zip(archive: Path, *, expected_entries: int) -> None:
    with ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) != expected_entries:
            message = (
                f"unexpected ZIP entry count for {archive.name}: "
                f"{len(entries)}, expected {expected_entries}"
            )
            raise CorpusFetchError(message)
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if (
                not name
                or "\\" in name
                or path.is_absolute()
                or ".." in path.parts
                or (path.parts and ":" in path.parts[0])
                or stat.S_ISLNK(mode)
            ):
                message = f"unsafe ZIP entry in {archive.name}: {name!r}"
                raise CorpusFetchError(message)


def _repair_manifest(entry: dict, target: Path) -> None:
    repair = entry["manifest_repair"]
    source = target / str(repair["source"])
    if _sha256(source) != repair["source_sha256"]:
        message = f"source manifest SHA-256 mismatch: {source}"
        raise CorpusFetchError(message)
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    remove_lines = set(repair["remove_lines"])
    if len(remove_lines) != len(repair["remove_lines"]):
        message = "manifest repair lines must be unique"
        raise CorpusFetchError(message)
    for line_number in remove_lines:
        if line_number < 1 or line_number > len(lines):
            message = f"manifest repair line is out of range: {line_number}"
            raise CorpusFetchError(message)
        if lines[line_number - 1].strip() != "</testcase>":
            message = f"manifest repair line {line_number} is not </testcase>"
            raise CorpusFetchError(message)
    repaired = "".join(
        line for number, line in enumerate(lines, start=1) if number not in remove_lines
    )
    if "<!DOCTYPE" in repaired or "<!ENTITY" in repaired:
        message = "manifest contains a forbidden XML declaration"
        raise CorpusFetchError(message)
    try:
        root = ET.fromstring(repaired)  # noqa: S314 - declarations rejected above
    except ET.ParseError as exc:
        message = "repaired manifest is not valid XML"
        raise CorpusFetchError(message) from exc
    testcase_count = len(root.findall("testcase"))
    if testcase_count != repair["expected_testcases"]:
        message = (
            f"repaired manifest has {testcase_count} testcases, "
            f"expected {repair['expected_testcases']}"
        )
        raise CorpusFetchError(message)
    destination = target / str(repair["destination"])
    destination.write_text(repaired, encoding="utf-8", newline="")
    if _sha256(destination) != repair["destination_sha256"]:
        message = f"repaired manifest SHA-256 mismatch: {destination}"
        raise CorpusFetchError(message)


def _fetch_git(entry: dict, output: Path) -> None:
    target = output / str(entry["directory"])
    if target.exists():
        message = f"refusing to reuse existing corpus path: {target}"
        raise CorpusFetchError(message)
    repository = str(entry["repository"])
    commit = str(entry["commit"])
    _run(
        [
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            repository,
            str(target),
        ]
    )
    _run(["git", "-C", str(target), "fetch", "--depth=1", "origin", commit])
    _run(["git", "-C", str(target), "checkout", "--detach", commit])


def _fetch_archive(entry: dict, output: Path) -> None:
    target = output / str(entry["directory"])
    if target.exists():
        message = f"refusing to reuse existing corpus path: {target}"
        raise CorpusFetchError(message)
    target.mkdir()
    archive = target / str(entry["archive_file"])
    _download(str(entry["archive_url"]), archive)
    _verify_file(
        archive,
        size=int(entry["archive_bytes"]),
        sha256=str(entry["archive_sha256"]),
    )
    _validate_zip(archive, expected_entries=int(entry["archive_entries"]))
    with ZipFile(archive) as bundle:
        bundle.extractall(target)
    license_path = target / str(entry["license_file"])
    _download(str(entry["license_url"]), license_path)
    _verify_file(
        license_path,
        size=int(entry["license_bytes"]),
        sha256=str(entry["license_sha256"]),
    )
    _repair_manifest(entry, target)


def _fetch(entry: dict, output: Path) -> None:
    source_type = entry.get("source_type", "git")
    if source_type == "git":
        _fetch_git(entry, output)
    elif source_type == "archive":
        _fetch_archive(entry, output)
    else:
        message = f"unsupported corpus source type: {source_type}"
        raise CorpusFetchError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--real-projects", type=Path, default=REAL_PROJECTS)
    parser.add_argument("--benchmarks", type=Path, default=BENCHMARKS)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=False)
    entries = _entries(args.real_projects, args.benchmarks)
    for entry in entries:
        _fetch(entry, args.output)
        identity = entry.get("commit") or entry.get("archive_sha256")
        print(f"fetched {entry['name']} at {identity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
