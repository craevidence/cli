"""Shared engine identity check for rule-pack evidence commands."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from cra_evidence_cli.local.rules_pack import TESTED_OPENGREP_VERSION


class EngineIdentityError(RuntimeError):
    pass


LOCK_PATH = (
    Path(__file__).resolve().parents[1]
    / "cra_evidence_cli"
    / "_engine"
    / "opengrep-release.json"
)


def _verified_asset(binary: Path) -> str:
    try:
        resolved = binary.resolve(strict=True)
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        assets = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["assets"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        message = f"cannot verify Opengrep bytes: {binary}"
        raise EngineIdentityError(message) from exc
    matches = [name for name, expected in assets.items() if expected == digest]
    if len(matches) != 1:
        message = (
            f"Opengrep SHA-256 is not present in the pinned release lock: "
            f"{resolved} ({digest})"
        )
        raise EngineIdentityError(message)
    return matches[0]


def resolve_engine(binary: Path) -> Path:
    candidate = binary
    if not binary.is_absolute() and binary.parent == Path("."):
        path_binary = shutil.which(str(binary))
        if path_binary is not None:
            candidate = Path(path_binary)
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        message = f"cannot resolve Opengrep executable: {binary}"
        raise EngineIdentityError(message) from exc


def verify_engine(binary: Path) -> str:
    resolved = resolve_engine(binary)
    _verified_asset(resolved)
    try:
        result = subprocess.run(  # noqa: S603
            [str(resolved), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"cannot execute Opengrep: {resolved}"
        raise EngineIdentityError(message) from exc
    output = (result.stdout or result.stderr or "").strip()
    actual = output.splitlines()[0].strip() if output else ""
    if result.returncode != 0 or actual != TESTED_OPENGREP_VERSION:
        message = (
            f"expected Opengrep {TESTED_OPENGREP_VERSION}, got "
            f"{actual or 'no version output'} from {resolved}"
        )
        raise EngineIdentityError(message)
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    print(verify_engine(args.binary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
