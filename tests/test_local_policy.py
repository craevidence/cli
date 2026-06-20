"""Tests for the committed-policy-file loader (cra_evidence_cli.local.policy)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cra_evidence_cli.exceptions import ConfigurationError
from cra_evidence_cli.local.policy import (
    DEFAULT_POLICY_PATH,
    Policy,
    ignored_set,
    load_policy,
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_explicit_path_loads_all_fields(tmp_path: Path) -> None:
    policy_file = _write(
        tmp_path / "check.yaml",
        """
        fail_on: high
        fail_on_new: any
        deny_license:
          - AGPL-3.0-only
          - GPL-3.0-only
        vex: security/openvex.json
        sbom_quality: true
        fail_on_score: 70
        ignore:
          - cve-2023-0002
          - CVE-2023-0001
          - CVE-2023-0001
        """,
    )

    policy = load_policy(policy_file)

    assert isinstance(policy, Policy)
    assert policy.fail_on == "high"
    assert policy.fail_on_new == "any"
    assert policy.deny_license == ["AGPL-3.0-only", "GPL-3.0-only"]
    assert policy.vex == "security/openvex.json"
    assert policy.sbom_quality is True
    assert policy.fail_on_score == 70
    # uppercased, de-duped, sorted
    assert policy.ignore == ["CVE-2023-0001", "CVE-2023-0002"]
    assert policy.source_path == policy_file
    assert ignored_set(policy) == {"CVE-2023-0001", "CVE-2023-0002"}


def test_explicit_path_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError) as exc:
        load_policy(tmp_path / "does-not-exist.yaml")
    assert "not found" in str(exc.value)
    assert exc.value.exit_code == 6


def test_autodiscovery_finds_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / DEFAULT_POLICY_PATH, "fail_on: critical\n")
    monkeypatch.chdir(tmp_path)

    policy = load_policy(None)

    assert policy is not None
    assert policy.fail_on == "critical"
    assert policy.source_path == DEFAULT_POLICY_PATH


def test_autodiscovery_missing_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_policy(None) is None


def test_unknown_key_raises_mentioning_key(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "fail_onn: high\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(policy_file)
    assert "fail_onn" in str(exc.value)
    assert exc.value.exit_code == 6


def test_invalid_fail_on_value_raises(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "fail_on: catastrophic\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(policy_file)
    assert "fail_on" in str(exc.value)


def test_fail_on_score_out_of_range_raises(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "fail_on_score: 150\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(policy_file)
    assert "fail_on_score" in str(exc.value)


def test_deny_license_bare_string_coerced(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "deny_license: AGPL-3.0-only\n")
    policy = load_policy(policy_file)
    assert policy is not None
    assert policy.deny_license == ["AGPL-3.0-only"]


def test_ignore_uppercased_deduped_sorted(tmp_path: Path) -> None:
    policy_file = _write(
        tmp_path / "check.yaml",
        """
        ignore:
          - cve-2024-9999
          - CVE-2024-0001
          - cve-2024-0001
        """,
    )
    policy = load_policy(policy_file)
    assert policy is not None
    assert policy.ignore == ["CVE-2024-0001", "CVE-2024-9999"]


def test_ignore_bare_string_coerced(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "ignore: cve-2024-0001\n")
    policy = load_policy(policy_file)
    assert policy is not None
    assert policy.ignore == ["CVE-2024-0001"]


def test_empty_file_yields_defaults_with_source_path(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "")
    policy = load_policy(policy_file)

    assert policy is not None
    assert policy.fail_on is None
    assert policy.fail_on_new is None
    assert policy.deny_license == []
    assert policy.vex is None
    assert policy.sbom_quality is None
    assert policy.fail_on_score is None
    assert policy.ignore == []
    assert policy.source_path == policy_file


def test_non_mapping_root_raises(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "- just\n- a\n- list\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(policy_file)
    assert "mapping" in str(exc.value)


def test_sbom_quality_non_bool_raises(tmp_path: Path) -> None:
    policy_file = _write(tmp_path / "check.yaml", "sbom_quality: maybe\n")
    with pytest.raises(ConfigurationError) as exc:
        load_policy(policy_file)
    assert "sbom_quality" in str(exc.value)


def test_ignored_set_none_returns_empty() -> None:
    assert ignored_set(None) == set()
