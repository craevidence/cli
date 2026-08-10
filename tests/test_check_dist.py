"""Tests for release distribution content checks."""

from __future__ import annotations

import ast
import importlib.util
import sys
import tarfile
import zipfile
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_dist.py"
_spec = importlib.util.spec_from_file_location("check_dist", _MODULE_PATH)
check_dist = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = check_dist
_spec.loader.exec_module(check_dist)

# check_dist compares the shipped Opengrep NOTICE with the generated attribution
# text for the pinned commit, so the synthetic payload carries that exact text.
_OPENGREP_NOTICE = check_dist._expected_opengrep_notice().encode("utf-8")
_PINNED_COMMIT = check_dist._opengrep_release_lock()["commit"]
_OTHER_COMMIT = "0" * 40
_WRONG_COMMIT_NOTICE = _OPENGREP_NOTICE.replace(
    _PINNED_COMMIT.encode("utf-8"), _OTHER_COMMIT.encode("utf-8")
)
_LICENCE_CONTRADICTING_NOTICE = (
    b"Opengrep is NOT licensed under the GNU Lesser General Public License "
    b"version 2.1.\nSource commit: unknown. This is unrelated text containing\n"
    b"https://github.com/opengrep/opengrep.\n"
)


def _write_release_set(
    dist_dir: Path,
    engine_dir: Path,
    opengrep_dir: Path,
    opengrep_notice: bytes = _OPENGREP_NOTICE,
) -> None:
    version = check_dist._project_version()
    engine_dir.mkdir()
    (engine_dir / "LICENSE").write_bytes(b"license bytes\n")
    (engine_dir / "NOTICE").write_bytes(b"notice bytes\n")
    for engine_name in {names[0] for names in check_dist.WHEEL_ENGINES.values()}:
        (engine_dir / engine_name).write_bytes(f"binary:{engine_name}".encode())
    opengrep_dir.mkdir()
    (opengrep_dir / "LICENSE").write_bytes(b"opengrep license\n")
    (opengrep_dir / "NOTICE").write_bytes(opengrep_notice)
    (opengrep_dir / "COPYRIGHT").write_bytes(b"opengrep copyright\n")
    (opengrep_dir / "NATIVE-DEPENDENCIES.json").write_bytes(b"{}\n")
    for opengrep_name in {names[1] for names in check_dist.WHEEL_ENGINES.values()}:
        (opengrep_dir / opengrep_name).write_bytes(
            f"binary:{opengrep_name}".encode()
        )

    for platform, (engine_name, opengrep_name) in check_dist.WHEEL_ENGINES.items():
        wheel = dist_dir / f"craevidence-{version}-py3-none-{platform}.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
            info.external_attr = 0o100755 << 16
            archive.writestr(info, (engine_dir / engine_name).read_bytes())
            archive.writestr(
                "cra_evidence_cli/_engine/LICENSE",
                (engine_dir / "LICENSE").read_bytes(),
            )
            archive.writestr(
                "cra_evidence_cli/_engine/NOTICE",
                (engine_dir / "NOTICE").read_bytes(),
            )
            opengrep_info = zipfile.ZipInfo("cra_evidence_cli/_engine/opengrep")
            opengrep_info.external_attr = 0o100755 << 16
            archive.writestr(
                opengrep_info, (opengrep_dir / opengrep_name).read_bytes()
            )
            archive.writestr(
                "cra_evidence_cli/_engine/opengrep-LICENSE",
                (opengrep_dir / "LICENSE").read_bytes(),
            )
            archive.writestr(
                "cra_evidence_cli/_engine/opengrep-NOTICE",
                (opengrep_dir / "NOTICE").read_bytes(),
            )
            archive.writestr(
                "cra_evidence_cli/_engine/opengrep-COPYRIGHT",
                (opengrep_dir / "COPYRIGHT").read_bytes(),
            )
            archive.writestr(
                "cra_evidence_cli/_engine/opengrep-NATIVE-DEPENDENCIES.json",
                (opengrep_dir / "NATIVE-DEPENDENCIES.json").read_bytes(),
            )
    with tarfile.open(dist_dir / f"craevidence-{version}.tar.gz", "w:gz"):
        pass


def test_engine_free_sdist_check_accepts_package_metadata_only():
    errors = check_dist._check_engine_free_sdist(
        [
            "craevidence-4.2.0/cra_evidence_cli/_engine/__init__.py",
            "craevidence-4.2.0/cra_evidence_cli/engine.py",
        ]
    )

    assert errors == []


def test_engine_free_sdist_check_rejects_bundled_engine():
    engine_path = "craevidence-4.2.0/cra_evidence_cli/_engine/grype"

    errors = check_dist._check_engine_free_sdist([engine_path])

    assert len(errors) == 1
    assert engine_path in errors[0]


def test_wheel_size_release_limit_is_enforced(tmp_path):
    wheel = tmp_path / "large.whl"
    with wheel.open("wb") as handle:
        handle.truncate(check_dist.MAX_WHEEL_SIZE + 1)

    errors = check_dist._check_wheel_size(wheel)

    assert errors == ["large.whl: 80.0 MiB exceeds the 80 MiB release limit"]


def test_pypi_file_size_limit_is_explicitly_enforced(tmp_path):
    wheel = tmp_path / "too-large.whl"
    with wheel.open("wb") as handle:
        handle.truncate(check_dist.PYPI_FILE_SIZE_LIMIT + 1)

    errors = check_dist._check_wheel_size(wheel)

    assert len(errors) == 2
    assert errors[1] == (
        "too-large.whl: 100.0 MiB exceeds PyPI's 100 MiB file limit"
    )


def test_dist_directory_applies_engine_free_check_to_sdist(tmp_path, monkeypatch):
    wheel = tmp_path / "craevidence-4.2.0-py3-none-any.whl"
    sdist = tmp_path / "craevidence-4.2.0.tar.gz"
    wheel.touch()
    sdist.touch()
    engine_path = "craevidence-4.2.0/cra_evidence_cli/_engine/grype"

    monkeypatch.setattr(check_dist, "_names_from_wheel", lambda path: [])
    monkeypatch.setattr(
        check_dist,
        "_names_from_sdist",
        lambda path: [engine_path],
    )
    monkeypatch.setattr(check_dist, "_check", lambda label, names: [])

    errors = check_dist._check_dist_dir(tmp_path)

    assert len(errors) == 1
    assert engine_path in errors[0]


def test_release_set_matches_promoted_payload(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir, opengrep_dir)

    assert check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir) == []


def test_release_set_rejects_tampered_engine_bytes(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir, opengrep_dir)
    (engine_dir / "grype-linux-amd64").write_bytes(b"different promoted bytes")

    errors = check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir)

    assert len(errors) == 2
    assert all("does not match promoted payload" in error for error in errors)


def test_release_set_rejects_notice_contradicting_the_opengrep_licence(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    # Both copies carry the same text, so only a content check catches this.
    _write_release_set(
        dist_dir, engine_dir, opengrep_dir, _LICENCE_CONTRADICTING_NOTICE
    )

    errors = check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir)

    assert len(errors) == len(check_dist.WHEEL_ENGINES)
    assert all("Opengrep NOTICE states source commit none" in e for e in errors)
    assert all(_PINNED_COMMIT in e for e in errors)


def test_release_set_rejects_notice_pinning_another_commit(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir, opengrep_dir, _WRONG_COMMIT_NOTICE)

    errors = check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir)

    assert len(errors) == len(check_dist.WHEEL_ENGINES)
    assert all(
        error.endswith(
            f"Opengrep NOTICE states source commit {_OTHER_COMMIT}, "
            f"release lock pins {_PINNED_COMMIT}"
        )
        for error in errors
    )


def test_release_set_rejects_notice_with_an_altered_clause(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    altered = _OPENGREP_NOTICE.replace(
        b"GNU Lesser General Public License version 2.1", b"MIT License"
    )
    _write_release_set(dist_dir, engine_dir, opengrep_dir, altered)

    errors = check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir)

    assert len(errors) == len(check_dist.WHEEL_ENGINES)
    assert all(
        error.endswith(
            "Opengrep NOTICE does not match the generated LGPL attribution "
            f"text for commit {_PINNED_COMMIT}"
        )
        for error in errors
    )


def test_release_set_rejects_unexpected_distribution_name(tmp_path):
    dist_dir = tmp_path / "dist"
    engine_dir = tmp_path / "engine"
    opengrep_dir = tmp_path / "opengrep"
    dist_dir.mkdir()
    _write_release_set(dist_dir, engine_dir, opengrep_dir)
    (dist_dir / "craevidence-4.2.0-py3-none-any.whl").touch()

    errors = check_dist._check_release_set(dist_dir, engine_dir, opengrep_dir)

    assert len(errors) == 1
    assert "release distribution set mismatch" in errors[0]


def test_release_wheel_rejects_non_executable_engine(tmp_path):
    engine_dir = tmp_path / "engine"
    engine_dir.mkdir()
    engine = engine_dir / "grype-linux-amd64"
    engine.write_bytes(b"engine bytes")
    (engine_dir / "LICENSE").write_bytes(b"license bytes")
    (engine_dir / "NOTICE").write_bytes(b"notice bytes")
    opengrep_dir = tmp_path / "opengrep"
    opengrep_dir.mkdir()
    opengrep = opengrep_dir / "opengrep_manylinux_x86"
    opengrep.write_bytes(b"opengrep bytes")
    (opengrep_dir / "LICENSE").write_bytes(b"opengrep license")
    (opengrep_dir / "NOTICE").write_bytes(_OPENGREP_NOTICE)
    (opengrep_dir / "COPYRIGHT").write_bytes(b"opengrep copyright")
    (opengrep_dir / "NATIVE-DEPENDENCIES.json").write_bytes(b"{}")
    wheel = tmp_path / "wheel.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
        info.external_attr = 0o100644 << 16
        archive.writestr(info, engine.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/LICENSE", b"license bytes")
        archive.writestr("cra_evidence_cli/_engine/NOTICE", b"notice bytes")
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/opengrep")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, opengrep.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/opengrep-LICENSE", b"opengrep license")
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-NOTICE", _OPENGREP_NOTICE
        )
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-COPYRIGHT", b"opengrep copyright"
        )
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-NATIVE-DEPENDENCIES.json", b"{}"
        )

    errors = check_dist._check_release_wheel(
        wheel, engine, engine_dir, opengrep, opengrep_dir
    )

    assert errors == ["wheel.whl: bundled engine is not executable"]


def test_release_wheel_rejects_notice_mismatch(tmp_path):
    engine_dir = tmp_path / "engine"
    engine_dir.mkdir()
    engine = engine_dir / "grype-linux-amd64"
    engine.write_bytes(b"engine bytes")
    (engine_dir / "LICENSE").write_bytes(b"license bytes")
    (engine_dir / "NOTICE").write_bytes(b"promoted notice")
    opengrep_dir = tmp_path / "opengrep"
    opengrep_dir.mkdir()
    opengrep = opengrep_dir / "opengrep_manylinux_x86"
    opengrep.write_bytes(b"opengrep bytes")
    (opengrep_dir / "LICENSE").write_bytes(b"opengrep license")
    (opengrep_dir / "NOTICE").write_bytes(_OPENGREP_NOTICE)
    (opengrep_dir / "COPYRIGHT").write_bytes(b"opengrep copyright")
    (opengrep_dir / "NATIVE-DEPENDENCIES.json").write_bytes(b"{}")
    wheel = tmp_path / "wheel.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/grype")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, engine.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/LICENSE", b"license bytes")
        archive.writestr("cra_evidence_cli/_engine/NOTICE", b"different notice")
        info = zipfile.ZipInfo("cra_evidence_cli/_engine/opengrep")
        info.external_attr = 0o100755 << 16
        archive.writestr(info, opengrep.read_bytes())
        archive.writestr("cra_evidence_cli/_engine/opengrep-LICENSE", b"opengrep license")
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-NOTICE", _OPENGREP_NOTICE
        )
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-COPYRIGHT", b"opengrep copyright"
        )
        archive.writestr(
            "cra_evidence_cli/_engine/opengrep-NATIVE-DEPENDENCIES.json", b"{}"
        )

    errors = check_dist._check_release_wheel(
        wheel, engine, engine_dir, opengrep, opengrep_dir
    )

    assert errors == ["wheel.whl: engine NOTICE differs from the promoted payload"]


def _generator_notice_template() -> str:
    """Recover the NOTICE text the release fetcher writes, without running it.

    check_dist restates the template on purpose so the guard does not accept
    whatever the generator happens to emit. That duplication is only safe while
    the two copies agree, so the text is read back out of the generator's source
    and compared here.
    """
    source = (
        Path(__file__).resolve().parent.parent
        / "scripts"
        / "fetch_opengrep_release.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "write_text":
            continue
        target = func.value
        if not isinstance(target, ast.BinOp) or not isinstance(target.op, ast.Div):
            continue
        if not isinstance(target.right, ast.Constant) or target.right.value != "NOTICE":
            continue
        if not node.args:
            continue
        return _render_joined_string(node.args[0])
    msg = "could not locate the NOTICE write in fetch_opengrep_release.py"
    raise AssertionError(msg)


def _render_joined_string(node: ast.AST) -> str:
    """Render a concatenation of literals and f-strings with named placeholders."""
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.JoinedStr):
        out = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                out.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                expr = value.value
                name = expr.id if isinstance(expr, ast.Name) else ast.dump(expr)
                out.append("{" + name.lower() + "}")
            else:  # pragma: no cover - defensive
                msg = f"unexpected f-string part: {ast.dump(value)}"
                raise AssertionError(msg)
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _render_joined_string(node.left) + _render_joined_string(node.right)
    msg = f"unexpected NOTICE expression: {ast.dump(node)}"
    raise AssertionError(msg)


def test_notice_template_matches_the_release_fetcher():
    assert _generator_notice_template() == check_dist.OPENGREP_NOTICE_TEMPLATE
