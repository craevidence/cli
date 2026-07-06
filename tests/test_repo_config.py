"""Tests for cra_evidence_cli.repo_config."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cra_evidence_cli.exceptions import ConfigurationError, CRAEvidenceError
from cra_evidence_cli.repo_config import (
    RepoConfig,
    find_repo_config,
    load_repo_config,
    resolve_identity,
    resolve_upload_identity,
    resolve_version,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _evidence_yaml(tmp_path: Path, content: str) -> Path:
    return _write(tmp_path / ".cra" / "evidence.yaml", content)


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def test_find_config_in_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: myapp\n")
    monkeypatch.chdir(tmp_path)
    result = find_repo_config()
    assert result is not None
    assert result == tmp_path / ".cra" / "evidence.yaml"


def test_find_config_via_git_root_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_root = tmp_path / "repo"
    subdir = git_root / "service"
    subdir.mkdir(parents=True)
    _write(git_root / ".cra" / "evidence.yaml", "schema_version: 1\nproduct: root-app\n")

    monkeypatch.chdir(subdir)

    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        return_value=type("R", (), {"stdout": str(git_root) + "\n", "returncode": 0})(),
    ):
        result = find_repo_config()

    assert result == git_root / ".cra" / "evidence.yaml"


def test_find_config_returns_none_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    import subprocess as _sp

    def _raise(*args, **kwargs):  # noqa: ANN001, ANN202
        raise _sp.CalledProcessError(128, "git")

    with patch("cra_evidence_cli.repo_config.subprocess.run", side_effect=_raise):
        result = find_repo_config()

    assert result is None


def test_find_config_not_git_repo_no_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        side_effect=FileNotFoundError("git not found"),
    ):
        result = find_repo_config()

    assert result is None


# ---------------------------------------------------------------------------
# load_repo_config - schema_version
# ---------------------------------------------------------------------------


def test_schema_version_missing_raises(tmp_path: Path) -> None:
    path = _evidence_yaml(tmp_path, "product: foo\n")
    with pytest.raises(ConfigurationError, match="missing required key 'schema_version'"):
        load_repo_config(path)


def test_schema_version_wrong_value_raises(tmp_path: Path) -> None:
    path = _evidence_yaml(tmp_path, "schema_version: 3\nproduct: foo\n")
    with pytest.raises(ConfigurationError, match="unsupported schema_version"):
        load_repo_config(path)


def test_unknown_key_raises(tmp_path: Path) -> None:
    path = _evidence_yaml(tmp_path, "schema_version: 1\ntypoo: foo\n")
    with pytest.raises(ConfigurationError, match="Unknown key"):
        load_repo_config(path)


def test_valid_config_parses(tmp_path: Path) -> None:
    path = _evidence_yaml(
        tmp_path,
        "schema_version: 1\nproduct: myapp\ncomponent: api\ncomponent_kind: service\n"
        "version_from: pyproject\n",
    )
    cfg = load_repo_config(path)
    assert isinstance(cfg, RepoConfig)
    assert cfg.product == "myapp"
    assert cfg.component == "api"
    assert cfg.component_kind == "service"
    assert cfg.version_from == "pyproject"


def test_schema_v2_parses_component_version_from(tmp_path: Path) -> None:
    path = _evidence_yaml(
        tmp_path,
        "schema_version: 2\nproduct: myapp\ncomponent: api\n"
        "product_version_from: env:PRODUCT_VER\n"
        "component_version_from: env:COMPONENT_VER\n",
    )
    cfg = load_repo_config(path)
    assert cfg.product_version_from == "env:PRODUCT_VER"
    assert cfg.component_version_from == "env:COMPONENT_VER"


def test_empty_file_parses_with_all_none(tmp_path: Path) -> None:
    path = _evidence_yaml(tmp_path, "schema_version: 1\n")
    cfg = load_repo_config(path)
    assert cfg.product is None
    assert cfg.component is None
    assert cfg.component_kind is None
    assert cfg.version_from is None


# ---------------------------------------------------------------------------
# load_repo_config - component_kind validation
# ---------------------------------------------------------------------------


def test_invalid_component_kind_raises(tmp_path: Path) -> None:
    path = _evidence_yaml(
        tmp_path, "schema_version: 1\nproduct: x\ncomponent_kind: database\n"
    )
    with pytest.raises(ConfigurationError, match="component_kind"):
        load_repo_config(path)


@pytest.mark.parametrize(
    "kind",
    ["frontend", "service", "datastore", "firmware", "library", "other"],
)
def test_valid_component_kinds(tmp_path: Path, kind: str) -> None:
    path = _evidence_yaml(tmp_path, f"schema_version: 1\ncomponent_kind: {kind}\n")
    cfg = load_repo_config(path)
    assert cfg.component_kind == kind


# ---------------------------------------------------------------------------
# resolve_version
# ---------------------------------------------------------------------------


def test_resolve_version_git_tag_via_describe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        return_value=type("R", (), {"stdout": "v1.2.3\n", "returncode": 0})(),
    ):
        assert resolve_version("git-tag") == "v1.2.3"


def test_resolve_version_git_tag_falls_back_to_github_ref(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    monkeypatch.setenv("GITHUB_REF_NAME", "v2.0.0")

    import subprocess as _sp

    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        side_effect=_sp.CalledProcessError(128, "git"),
    ):
        assert resolve_version("git-tag") == "v2.0.0"


def test_resolve_version_git_tag_failure_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_REF_TYPE", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)

    import subprocess as _sp

    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        side_effect=_sp.CalledProcessError(128, "git"),
    ):
        with pytest.raises(CRAEvidenceError, match="no tag at HEAD"):
            resolve_version("git-tag")


def test_resolve_version_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    version_file = tmp_path / "VERSION"
    version_file.write_text("\n1.0.0\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert resolve_version(f"file:{version_file}") == "1.0.0"


def test_resolve_version_file_missing_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CRAEvidenceError, match="file:"):
        resolve_version("file:nonexistent.txt")


def test_resolve_version_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "3.1.4"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert resolve_version("pyproject") == "3.1.4"


def test_resolve_version_pyproject_poetry_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nversion = "0.9.0"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert resolve_version("pyproject") == "0.9.0"


def test_resolve_version_pyproject_missing_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CRAEvidenceError, match="pyproject"):
        resolve_version("pyproject")


def test_resolve_version_package_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "my-lib", "version": "5.0.1"}), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert resolve_version("package.json") == "5.0.1"


def test_resolve_version_package_json_missing_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CRAEvidenceError, match="package.json"):
        resolve_version("package.json")


def test_resolve_version_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_APP_VERSION", "7.8.9")
    assert resolve_version("env:MY_APP_VERSION") == "7.8.9"


def test_resolve_version_env_unset_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MY_APP_VERSION", raising=False)
    with pytest.raises(CRAEvidenceError, match="MY_APP_VERSION"):
        resolve_version("env:MY_APP_VERSION")


# ---------------------------------------------------------------------------
# resolve_identity - precedence
# ---------------------------------------------------------------------------


def test_flag_beats_env_beats_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: file-product\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRA_EVIDENCE_PRODUCT", "env-product")

    product, version, _ = resolve_identity("flag-product", "1.0", None)

    assert product == "flag-product"


def test_env_beats_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: file-product\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRA_EVIDENCE_PRODUCT", "env-product")

    product, version, _ = resolve_identity(None, "1.0", None)

    assert product == "env-product"


def test_file_used_when_no_flag_or_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: file-product\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_PRODUCT", raising=False)

    product, version, _ = resolve_identity(None, "1.0", None)

    assert product == "file-product"


def test_version_env_beats_file_version_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(
        tmp_path, "schema_version: 1\nproduct: p\nversion_from: env:MY_VER\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRA_EVIDENCE_VERSION", "env-version")

    _, version, _ = resolve_identity(None, None, None)

    assert version == "env-version"


def test_component_flag_beats_env_beats_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: p\ncomponent: file-comp\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRA_EVIDENCE_COMPONENT", "env-comp")

    _, _, component = resolve_identity(None, "1.0", "flag-comp")

    assert component == "flag-comp"


def test_component_env_beats_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: p\ncomponent: file-comp\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CRA_EVIDENCE_COMPONENT", "env-comp")

    _, _, component = resolve_identity(None, "1.0", None)

    assert component == "env-comp"


def test_component_file_used_when_absent_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: p\ncomponent: file-comp\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_COMPONENT", raising=False)

    _, _, component = resolve_identity(None, "1.0", None)

    assert component == "file-comp"


def test_missing_product_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_PRODUCT", raising=False)

    with patch(
        "cra_evidence_cli.repo_config.subprocess.run",
        side_effect=FileNotFoundError(),
    ):
        with pytest.raises(CRAEvidenceError, match="Product is required"):
            resolve_identity(None, "1.0", None)


def test_missing_version_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_VERSION", raising=False)
    _evidence_yaml(tmp_path, "schema_version: 1\nproduct: p\n")

    with pytest.raises(CRAEvidenceError, match="Version is required"):
        resolve_identity(None, None, None)


def test_version_from_resolved_when_version_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(
        tmp_path, "schema_version: 1\nproduct: p\nversion_from: env:RELEASE_VER\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_VERSION", raising=False)
    monkeypatch.setenv("RELEASE_VER", "4.2.0")

    _, version, _ = resolve_identity(None, None, None)

    assert version == "4.2.0"


def test_upload_identity_resolves_component_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _evidence_yaml(
        tmp_path,
        "schema_version: 2\nproduct: p\n"
        "product_version_from: env:PRODUCT_VER\n"
        "component_version_from: env:COMPONENT_VER\n",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CRA_EVIDENCE_VERSION", raising=False)
    monkeypatch.delenv("CRA_EVIDENCE_COMPONENT_VERSION", raising=False)
    monkeypatch.setenv("PRODUCT_VER", "1.0.0")
    monkeypatch.setenv("COMPONENT_VER", "2.4.0")

    product, version, component, component_version = resolve_upload_identity(
        None, None, None, None
    )

    assert product == "p"
    assert version == "1.0.0"
    assert component is None
    assert component_version == "2.4.0"
