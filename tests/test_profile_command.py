"""Tests for product CRA profile commands."""

from __future__ import annotations

from io import StringIO
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import profile as profile_module

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


def test_setup_profile_help_has_no_retired_ce_marking_option() -> None:
    result = CliRunner().invoke(cli, ["setup-profile", "--help"])

    assert result.exit_code == 0
    assert "--ce-marking" not in result.output
    assert "--support-communicated" in result.output


def test_setup_profile_sends_only_supported_product_defaults() -> None:
    response = {
        "cra_profile": {
            "default_conformity_assessment_type": "self_assessment",
            "default_support_period_years": 5,
            "support_period_communicated": True,
            "secure_by_default_confirmed": True,
        }
    }
    with patch.object(profile_module, "CRAEvidenceClient") as client_class:
        client = client_class.return_value
        client.update_cra_profile = AsyncMock(return_value=response)

        result = CliRunner().invoke(
            cli,
            [
                "setup-profile",
                "--product",
                "test-product",
                "--conformity-type",
                "self_assessment",
                "--support-years",
                "5",
                "--support-communicated",
                "--secure-by-default",
            ],
            env=BASE_ENV,
        )

    assert result.exit_code == 0, result.output
    client.update_cra_profile.assert_awaited_once_with(
        product="test-product",
        profile={
            "default_conformity_assessment_type": "self_assessment",
            "default_support_period_years": 5,
            "support_period_communicated": True,
            "secure_by_default_confirmed": True,
        },
    )


def test_from_version_does_not_copy_ce_marking_into_product_profile() -> None:
    with patch.object(profile_module, "CRAEvidenceClient") as client_class:
        client = client_class.return_value
        client.get_version_cra_settings = AsyncMock(
            return_value={
                "conformity_assessment_type": "self_assessment",
                "ce_marking_applied": True,
                "support_period_communicated": True,
                "secure_by_default_confirmed": False,
            }
        )
        client.update_cra_profile = AsyncMock(
            return_value={"cra_profile": {"default_conformity_assessment_type": "self_assessment"}}
        )

        result = CliRunner().invoke(
            cli,
            [
                "setup-profile",
                "--product",
                "test-product",
                "--from-version",
                "1.0.0",
            ],
            env=BASE_ENV,
        )

    assert result.exit_code == 0, result.output
    payload = client.update_cra_profile.await_args.kwargs["profile"]
    assert payload == {
        "default_conformity_assessment_type": "self_assessment",
        "support_period_communicated": True,
        "secure_by_default_confirmed": False,
    }


def test_profile_text_does_not_display_retired_ce_marking_default(monkeypatch) -> None:
    output = StringIO()
    monkeypatch.setattr(
        profile_module,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )

    profile_module.format_profile_output(
        "test-product",
        {
            "default_conformity_assessment_type": "self_assessment",
            "ce_marking_standard": True,
        },
        "text",
    )

    assert "CE Marking" not in output.getvalue()
