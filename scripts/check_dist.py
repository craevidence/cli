"""Distribution content guard.

Builds the sdist and wheel and verifies:
  - All 15 rule YAML files are present in each artifact.
  - No .py or fixture files appear under local/rules/ in either artifact.
  - No rule_fixtures path appears in either artifact.

Run: python scripts/check_dist.py

Invoked by CI after the rulepack structural and engine gates pass. Implemented
as a standalone script (not a pytest test) to keep multi-second build time out
of the normal test suite.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RULES_ROOT = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"

EXPECTED_RULE_COUNT = 15


def _build_dist(dist_dir: Path) -> tuple[Path, Path]:
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "build", "--outdir", str(dist_dir), str(REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        msg = f"build failed (exit {result.returncode})"
        raise SystemExit(msg)

    wheels = list(dist_dir.glob("*.whl"))
    sdists = list(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1:
        msg = f"expected 1 wheel, found {len(wheels)}: {wheels}"
        raise SystemExit(msg)
    if len(sdists) != 1:
        msg = f"expected 1 sdist, found {len(sdists)}: {sdists}"
        raise SystemExit(msg)
    return wheels[0], sdists[0]


def _names_from_wheel(whl: Path) -> list[str]:
    with zipfile.ZipFile(whl) as z:
        return z.namelist()


def _names_from_sdist(sdist: Path) -> list[str]:
    with tarfile.open(sdist, "r:gz") as t:
        return t.getnames()


def _check(artifact_label: str, names: list[str]) -> list[str]:
    errors: list[str] = []

    rule_yamls = sorted(RULES_ROOT.rglob("*.yaml"))
    if len(rule_yamls) != EXPECTED_RULE_COUNT:
        errors.append(
            f"{artifact_label}: expected {EXPECTED_RULE_COUNT} rule files on disk, "
            f"found {len(rule_yamls)}"
        )

    for rule_path in rule_yamls:
        rel = rule_path.relative_to(REPO_ROOT)
        suffix = str(rel).replace("\\", "/")
        matching = [n for n in names if n.endswith(suffix)]
        if not matching:
            errors.append(
                f"{artifact_label}: rule file missing from artifact: {suffix}"
            )

    py_in_rules = [
        n for n in names
        if "local/rules/" in n and n.endswith(".py")
    ]
    if py_in_rules:
        errors.append(
            f"{artifact_label}: .py files found under local/rules/ -- "
            f"fixtures must not ship: {py_in_rules}"
        )

    fixture_entries = [n for n in names if "rule_fixtures" in n]
    if fixture_entries:
        errors.append(
            f"{artifact_label}: rule_fixtures paths found in artifact -- "
            f"deliberately-vulnerable fixtures must not ship: {fixture_entries[:5]}"
        )

    return errors


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        dist_dir = Path(tmp)
        print("Building sdist and wheel...")
        wheel, sdist = _build_dist(dist_dir)
        print(f"  wheel : {wheel.name}")
        print(f"  sdist : {sdist.name}")

        all_errors: list[str] = []
        all_errors.extend(_check(f"wheel ({wheel.name})", _names_from_wheel(wheel)))
        all_errors.extend(_check(f"sdist ({sdist.name})", _names_from_sdist(sdist)))

    if all_errors:
        print("\nDist content check FAILED:")
        for err in all_errors:
            print(f"  {err}")
        raise SystemExit(1)

    print(
        f"\nDist content check passed: "
        f"{EXPECTED_RULE_COUNT} rules in wheel and sdist, no fixtures."
    )


if __name__ == "__main__":
    main()
