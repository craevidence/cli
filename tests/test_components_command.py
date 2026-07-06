"""
Tests for `craevidence components list`.

Mocks the async _fetch_components helper so the test stays at the click
boundary without touching real HTTP.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.exceptions import APIError, AuthenticationError, CRAEvidenceError


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def base_env():
    return {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }


@pytest.fixture
def components_payload():
    return [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "slug": "firmware",
            "name": "Firmware",
            "vcs_uri": "github.com/acme/firmware",
            "repo_path": "",
            "auto_created": True,
            "archived_at": None,
            "sbom_count_latest_version": 2,
            "owner": {"email": "alice@acme.com"},
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "slug": "edge-agent",
            "name": "Edge Agent",
            "vcs_uri": "github.com/acme/edge",
            "repo_path": "",
            "auto_created": False,
            "archived_at": None,
            "sbom_count_latest_version": 0,
            "owner": {},
        },
    ]


class TestComponentsList:
    def test_text_output_renders_table_with_data(
        self, runner, base_env, components_payload, monkeypatch
    ):
        # Rich tables truncate to terminal width; force a wide console so
        # column values are not cut off in the test output capture.
        from rich.console import Console

        from cra_evidence_cli.commands import components as components_module
        monkeypatch.setattr(
            components_module,
            "console",
            Console(force_terminal=False, width=220, color_system=None),
        )

        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _async_payload(**_kwargs):
                return components_payload
            mock_fetch.side_effect = _async_payload

            result = runner.invoke(
                cli,
                ["components", "list", "--product", "security-camera"],
                env=base_env,
            )

        assert result.exit_code == 0, result.output
        assert "firmware" in result.output
        assert "edge-agent" in result.output
        # auto-attribution + alice's email show as status / owner.
        assert "auto" in result.output
        assert "alice@acme.com" in result.output

    def test_json_output_returns_payload(
        self, runner, base_env, components_payload
    ):
        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _async_payload(**_kwargs):
                return components_payload
            mock_fetch.side_effect = _async_payload

            result = runner.invoke(
                cli,
                ["--output", "json", "components", "list", "--product", "security-camera"],
                env=base_env,
            )

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert [c["slug"] for c in parsed] == ["firmware", "edge-agent"]
        assert parsed[0]["sbom_count_latest_version"] == 2

    def test_include_archived_flag_forwarded(
        self, runner, base_env, components_payload
    ):
        captured: dict[str, object] = {}

        async def _capture(**kwargs):
            captured.update(kwargs)
            return components_payload

        with patch(
            "cra_evidence_cli.commands.components._fetch_components",
            side_effect=_capture,
        ):
            result = runner.invoke(
                cli,
                [
                    "components", "list", "--product", "security-camera",
                    "--include-archived",
                ],
                env=base_env,
            )

        assert result.exit_code == 0, result.output
        assert captured["include_archived"] is True
        assert captured["product"] == "security-camera"

    def test_empty_payload_shows_friendly_message(self, runner, base_env):
        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _empty(**_kwargs):
                return []
            mock_fetch.side_effect = _empty

            result = runner.invoke(
                cli,
                ["components", "list", "--product", "security-camera"],
                env=base_env,
            )

        assert result.exit_code == 0, result.output
        assert "No components" in result.output

    def test_api_error_propagates_exit_code(self, runner, base_env):
        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _boom(**_kwargs):
                msg = "Product 'nope' not found"
                raise CRAEvidenceError(msg, exit_code=2)
            mock_fetch.side_effect = _boom

            result = runner.invoke(
                cli,
                ["components", "list", "--product", "nope"],
                env=base_env,
            )

        assert result.exit_code == 2
        assert "not found" in result.output

    def test_authentication_error_exits_2(self, runner, base_env):
        """AuthenticationError (exit 2) from _fetch_components is propagated."""
        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _auth_fail(**_kwargs):
                msg = "Authentication failed (401). Check your API key or OIDC token."
                raise AuthenticationError(msg)
            mock_fetch.side_effect = _auth_fail

            result = runner.invoke(
                cli,
                ["components", "list", "--product", "security-camera"],
                env=base_env,
            )

        assert result.exit_code == 2
        assert "Authentication" in result.output or "401" in result.output

    def test_product_not_found_exits_3(self, runner, base_env):
        """APIError with status 404 (exit 3) is raised for product-not-found."""
        with patch(
            "cra_evidence_cli.commands.components._fetch_components"
        ) as mock_fetch:
            async def _not_found(**_kwargs):
                msg = "Product 'ghost' not found"
                raise APIError(msg, status_code=404)
            mock_fetch.side_effect = _not_found

            result = runner.invoke(
                cli,
                ["components", "list", "--product", "ghost"],
                env=base_env,
            )

        assert result.exit_code == 3
        assert "not found" in result.output
