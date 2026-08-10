"""Execute the Go downcast fixture and check its annotations against behavior.

The per-rule and batch gates prove that a rule matches its fixture. They cannot
prove the fixture is right: a case annotated `ok:` that is in fact vulnerable
makes both gates pass while the rule silently misses a real defect.

Integer truncation is decidable by running the code, so this module compiles the
fixture and calls every case with boundary inputs. A case named `ok...` or
`reported...` must never produce a wraparound; a case named `bad...` must produce
one for at least one input.

Requires a Go toolchain. Skipped when `go` is not on PATH.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

TESTS_ROOT = Path(__file__).parent
FIXTURE = TESTS_ROOT / "rule_fixtures" / "go" / "integer" / "cra-go-parseint-downcast.go"
HARNESS = TESTS_ROOT / "semantic" / "go_downcast_harness.go"
PROBE_RE = re.compile(
    r"^func ((?:ok|bad|reported)[A-Za-z0-9]+)\(s string\) (int32|uint32)",
    re.MULTILINE,
)
MAIN_TEST = """package integer

import "testing"

func TestSemantics(t *testing.T) {
	if n := Run(); n > 0 {
		t.Fatalf("%d fixture annotations contradict runtime behavior", n)
	}
}
"""


def _probe_table(fixture_source: str) -> tuple[str, int]:
    entries = []
    for name, target in PROBE_RE.findall(fixture_source):
        slot = f"{name}, nil" if target == "int32" else f"nil, {name}"
        entries.append(f'\t{{"{name}", {slot}}},')
    body = "\n".join(entries)
    return f"package integer\n\nvar probes = []probe{{\n{body}\n}}\n", len(entries)


def _run_go_test(workdir: Path) -> subprocess.CompletedProcess[str]:
    go = shutil.which("go")
    assert go is not None
    subprocess.run(  # noqa: S603
        [go, "mod", "init", "fixturesemantics"],
        cwd=workdir,
        capture_output=True,
        text=True,
        check=True,
    )
    return subprocess.run(  # noqa: S603
        [go, "test", "./..."],
        cwd=workdir,
        capture_output=True,
        text=True,
    )


def _prepare(workdir: Path, fixture_source: str) -> int:
    (workdir / "fixture.go").write_text(fixture_source, encoding="utf-8")
    (workdir / "harness.go").write_text(
        HARNESS.read_text(encoding="utf-8"), encoding="utf-8"
    )
    table, count = _probe_table(fixture_source)
    (workdir / "probes.go").write_text(table, encoding="utf-8")
    (workdir / "main_test.go").write_text(MAIN_TEST, encoding="utf-8")
    return count


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not available")
def test_go_downcast_fixture_annotations_match_runtime_behavior(tmp_path) -> None:
    source = FIXTURE.read_text(encoding="utf-8")
    count = _prepare(tmp_path, source)
    assert count >= 20, f"expected the fixture to expose many cases, found {count}"

    result = _run_go_test(tmp_path)

    assert result.returncode == 0, (
        "fixture annotations contradict runtime behavior:\n"
        f"{result.stdout}\n{result.stderr}"
    )


@pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not available")
def test_semantic_check_rejects_a_vulnerable_case_annotated_safe(tmp_path) -> None:
    """The check above is only worth running if it fails on a bad annotation.

    Renaming a case that truncates so it reads as a safe case must be caught.
    """
    source = FIXTURE.read_text(encoding="utf-8")
    mutated = source.replace(
        "func badReversedOperandsUpperOnly(", "func okMutatedReversedOperands("
    )
    assert mutated != source, "the case this mutation relies on is no longer present"
    _prepare(tmp_path, mutated)

    result = _run_go_test(tmp_path)

    assert result.returncode != 0, "the semantic check passed a vulnerable safe case"
    assert "okMutatedReversedOperands" in result.stdout
    assert "annotated safe but wraps" in result.stdout
