"""Execute language fixtures and check their annotations against behavior.

The per-rule and batch gates prove that a rule matches its fixture. They cannot
prove the fixture is right: a case annotated `ok:` that is in fact vulnerable
makes both gates pass while the rule silently misses a real defect.

Integer truncation is decidable by running the code, so this module compiles the
fixture and calls every case with boundary inputs. A case named `ok...` or
`reported...` must never produce a wraparound; a case named `bad...` must produce
one for at least one input.

Requires a Go toolchain and PHP runtime. The PHP gate uses a locally cached,
digest-pinned image without pulling only when a host PHP runtime is unavailable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_ROOT = Path(__file__).parent
FIXTURE = TESTS_ROOT / "rule_fixtures" / "go" / "integer" / "cra-go-parseint-downcast.go"
HARNESS = TESTS_ROOT / "semantic" / "go_downcast_harness.go"
TLS_FIXTURES = TESTS_ROOT / "rule_fixtures" / "go" / "tls"
TLS_SEMANTIC_PACKAGES = TESTS_ROOT / "semantic" / "go_tls_import_binding"
PHP_FIXTURE = (
    TESTS_ROOT
    / "rule_fixtures"
    / "php"
    / "deserialization"
    / "cra-php-global-unserialize-superglobal.php"
)
PHP_BINDING = TESTS_ROOT / "semantic" / "php_global_unserialize_binding.php"
PHP_REDECLARE = TESTS_ROOT / "semantic" / "php_global_unserialize_redeclare.php"
JAVASCRIPT_PRECISION_FIXTURES = tuple(
    TESTS_ROOT
    / "rule_fixtures"
    / "javascript"
    / "integer"
    / f"cra-javascript-odd-unsafe-integer-literal.{suffix}"
    for suffix in ("js", "ts")
)
PHP_RUNTIME_IMAGE = (
    "php@sha256:f78661b492226388a7057679cc731c3e43bc92ba66cd49a8cfe12374a56bee9f"
)
RUST_RUNTIME_IMAGE = (
    "rust@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89"
)
RUST_ABSOLUTE = (
    TESTS_ROOT / "semantic" / "rust_reqwest_absolute_binding" / "src" / "lib.rs"
)
RUST_SELF_ALIAS = TESTS_ROOT / "semantic" / "rust_reqwest_self_alias" / "src" / "lib.rs"
RUST_DUMMY = TESTS_ROOT / "semantic" / "rust_reqwest_dummy.rs"
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


def _run_php(script: Path, *, lint: bool = False) -> subprocess.CompletedProcess[str]:
    php = shutil.which("php")
    arguments = ["-l"] if lint else []
    if php is not None:
        return subprocess.run(  # noqa: S603
            [php, *arguments, str(script)],
            capture_output=True,
            text=True,
        )

    docker = shutil.which("docker")
    assert docker is not None, (
        "PHP is not on PATH and Docker is unavailable; the PHP semantic "
        "evidence gate cannot run"
    )
    relative = script.relative_to(TESTS_ROOT).as_posix()
    return subprocess.run(  # noqa: S603
        [
            docker,
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "-v",
            f"{TESTS_ROOT}:/tests:ro",
            PHP_RUNTIME_IMAGE,
            "php",
            *arguments,
            f"/tests/{relative}",
        ],
        capture_output=True,
        text=True,
    )


def _rust_image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = subprocess.run(  # noqa: S603
        [docker, "image", "inspect", RUST_RUNTIME_IMAGE],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _run_rustc(workdir: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker is not None
    return subprocess.run(  # noqa: S603
        [
            docker,
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/rustc-tmp:rw,noexec,nosuid,size=32m",
            "--env",
            "TMPDIR=/rustc-tmp",
            "-v",
            f"{TESTS_ROOT}:/tests:ro",
            "-v",
            f"{workdir}:/work:rw",
            RUST_RUNTIME_IMAGE,
            "rustc",
            *arguments,
        ],
        capture_output=True,
        text=True,
    )


def _prepare(workdir: Path, fixture_source: str) -> int:
    instrumented = re.sub(r"\bint32\(", "traceI32(", fixture_source)
    instrumented = re.sub(r"\buint32\(", "traceU32(", instrumented)
    (workdir / "fixture.go").write_text(instrumented, encoding="utf-8")
    (workdir / "harness.go").write_text(
        HARNESS.read_text(encoding="utf-8"), encoding="utf-8"
    )
    table, count = _probe_table(fixture_source)
    (workdir / "probes.go").write_text(table, encoding="utf-8")
    (workdir / "main_test.go").write_text(MAIN_TEST, encoding="utf-8")
    return count


def test_go_downcast_fixture_annotations_match_runtime_behavior(tmp_path) -> None:
    source = FIXTURE.read_text(encoding="utf-8")
    count = _prepare(tmp_path, source)
    assert count >= 20, f"expected the fixture to expose many cases, found {count}"

    result = _run_go_test(tmp_path)

    assert result.returncode == 0, (
        "fixture annotations contradict runtime behavior:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_go_tls_import_homonym_fixtures_are_valid_compiling_code(tmp_path) -> None:
    for name in (
        "cra-go-tls-direct-dial-insecure-homonym.go",
        "cra-go-tls-direct-dial-insecure-suffix-import.go",
    ):
        shutil.copy2(TLS_FIXTURES / name, tmp_path / name)
    shutil.copytree(
        TLS_SEMANTIC_PACKAGES / "applicationtls",
        tmp_path / "applicationtls",
    )
    shutil.copytree(
        TLS_SEMANTIC_PACKAGES / "crypto",
        tmp_path / "crypto",
    )

    result = _run_go_test(tmp_path)

    assert result.returncode == 0, (
        "Go TLS homonym fixtures are not valid compiling code:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_php_global_unserialize_binding_and_fixture_are_executable() -> None:
    for script in (PHP_BINDING, PHP_FIXTURE):
        lint = _run_php(script, lint=True)
        assert lint.returncode == 0, (
            f"PHP fixture does not parse: {script}\n{lint.stdout}\n{lint.stderr}"
        )

    binding = _run_php(PHP_BINDING)
    assert binding.returncode == 0, binding.stderr
    assert binding.stdout.splitlines() == ["application:value", "global"]

    redeclare = _run_php(PHP_REDECLARE, lint=True)
    assert redeclare.returncode != 0, (
        "PHP allowed an application to redeclare the global unserialize function"
    )
    output = f"{redeclare.stdout}\n{redeclare.stderr}".lower()
    # PHP builds word this differently: "Cannot redeclare function
    # unserialize()" (8.4 docker image) versus "Cannot redeclare
    # unserialize()" (distribution builds). Assert the semantics, not one
    # build's exact phrase.
    assert "cannot redeclare" in output
    assert "unserialize" in output


def test_javascript_unsafe_integer_fixture_matches_binary64_runtime_values() -> None:
    assert sys.float_info.radix == 2
    assert sys.float_info.mant_dig == 53

    marker = re.compile(
        r"^// (?P<label>ruleid|ok): cra-javascript-odd-unsafe-integer-literal$"
    )
    assignment = re.compile(
        r"^const \w+(?:: (?:number|bigint|string))? = (?P<literal>[^;]+);$"
    )

    for fixture in JAVASCRIPT_PRECISION_FIXTURES:
        lines = fixture.read_text(encoding="utf-8").splitlines()
        unsafe = 0
        safe_numbers = 0
        safe_non_numbers = 0

        for index, line in enumerate(lines[:-1]):
            annotation = marker.fullmatch(line)
            if annotation is None:
                continue
            matched_assignment = assignment.fullmatch(lines[index + 1])
            assert matched_assignment is not None
            literal = matched_assignment.group("literal")
            label = annotation.group("label")

            if literal.endswith("n") or literal.startswith(('"', "'")):
                assert label == "ok"
                safe_non_numbers += 1
                continue

            normalized = literal.replace("_", "")
            sign = -1 if normalized.startswith("-") else 1
            magnitude = normalized.removeprefix("-")
            base = 16 if magnitude.lower().startswith("0x") else 10
            if magnitude.lower().startswith("0b"):
                base = 2
            elif magnitude.lower().startswith("0o"):
                base = 8
            exact = sign * int(magnitude, base)
            runtime = int(float(exact))

            if label == "ruleid":
                assert abs(exact) > 2**53 - 1
                assert abs(exact) % 2 == 1
                assert runtime != exact
                unsafe += 1
            else:
                assert runtime == exact
                safe_numbers += 1

        assert unsafe == 6, fixture
        assert safe_numbers == 4, fixture
        assert safe_non_numbers == 2, fixture


@pytest.mark.skipif(not _rust_image_available(), reason="pinned Rust image is unavailable")
def test_rust_absolute_and_current_crate_alias_fixtures_compile(tmp_path) -> None:
    dummy = _run_rustc(
        tmp_path,
        [
            "--edition=2021",
            "--crate-name=reqwest",
            "--crate-type=lib",
            "/tests/semantic/rust_reqwest_dummy.rs",
            "-o",
            "/work/libreqwest.rlib",
        ],
    )
    assert dummy.returncode == 0, dummy.stderr

    for source, output in (
        (RUST_ABSOLUTE, "absolute.rlib"),
        (RUST_SELF_ALIAS, "self-alias.rlib"),
    ):
        relative = source.relative_to(TESTS_ROOT).as_posix()
        result = _run_rustc(
            tmp_path,
            [
                "--edition=2021",
                "--crate-type=lib",
                f"/tests/{relative}",
                "--extern",
                "reqwest=/work/libreqwest.rlib",
                "-o",
                f"/work/{output}",
            ],
        )
        assert result.returncode == 0, result.stderr


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


def test_semantic_check_rejects_a_zero_valued_wrap_annotated_safe(tmp_path) -> None:
    source = FIXTURE.read_text(encoding="utf-8")
    source += """

func okMutatedZeroWrap(s string) uint32 {
	v, _ := strconv.ParseUint(s, 10, 64)
	if v != 4294967296 {
		return 0
	}
	return uint32(v)
}
"""
    _prepare(tmp_path, source)

    result = _run_go_test(tmp_path)

    assert result.returncode != 0, "the semantic check passed a zero-valued wrap"
    assert "okMutatedZeroWrap" in result.stdout
    assert "annotated safe but wraps" in result.stdout
