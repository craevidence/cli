"""Tests for standalone draft product-version creation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import APIError, AuthenticationError
from cra_evidence_cli.local.sast_scanner import SASTReport
from tests.test_plain_language_guard import _line_violations

REPO_ROOT = Path(__file__).resolve().parent.parent

PRODUCT_ID = "11111111-1111-4111-8111-111111111111"
VERSION_ID = "22222222-2222-4222-8222-222222222222"
SOURCE_VERSION_ID = "33333333-3333-4333-8333-333333333333"

PRODUCTS_URL = "https://api.test.craevidence.com/api/v1/products"
VERSIONS_URL = f"{PRODUCTS_URL}/{PRODUCT_ID}/versions"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def base_env() -> dict[str, str]:
    return {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "https://api.test.craevidence.com",
    }


def _created_result() -> dict:
    return {
        "id": VERSION_ID,
        "product_id": PRODUCT_ID,
        "version_number": "2.4.0",
        "release_state": "draft",
        "created": True,
    }


def test_command_is_registered(runner: CliRunner, base_env: dict[str, str]) -> None:
    result = runner.invoke(cli, ["--help"], env=base_env)

    assert result.exit_code == 0
    assert "create-version" in result.output


def test_minimal_create_has_no_evidence_side_effects(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(return_value=_created_result())
    client.upload_sbom = AsyncMock()
    client.scan = AsyncMock()
    client.set_release_state = AsyncMock()

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
            ],
            env=base_env,
        )

    assert result.exit_code == 0, result.output
    assert "Product version created" in result.output
    assert "State: draft" in result.output
    assert "New evidence: none uploaded" in result.output
    assert "Product-level documents may be linked automatically" in result.output
    assert "Nothing was scanned, released, or approved." in result.output
    client.create_product_version.assert_awaited_once_with(
        product="security-camera",
        version="2.4.0",
        release_type=None,
        environment=None,
        release_notes=None,
        release_date=None,
        end_of_support_date=None,
        external_url=None,
        inherit_from=None,
        reuse_existing=False,
    )
    client.upload_sbom.assert_not_awaited()
    client.scan.assert_not_awaited()
    client.set_release_state.assert_not_awaited()


def test_all_optional_fields_are_forwarded(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(return_value=_created_result())

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
                "--release-type",
                "security_patch",
                "--environment",
                "qa-eu",
                "--release-notes",
                "Security update",
                "--release-date",
                "2026-07-31",
                "--end-of-support-date",
                "2031-07-31",
                "--external-url",
                "https://example.com/releases/2.4.0",
                "--inherit-from",
                "2.3.0",
                "--reuse-existing",
            ],
            env=base_env,
        )

    assert result.exit_code == 0, result.output
    client.create_product_version.assert_awaited_once_with(
        product="security-camera",
        version="2.4.0",
        release_type="security_patch",
        environment="qa-eu",
        release_notes="Security update",
        release_date="2026-07-31",
        end_of_support_date="2031-07-31",
        external_url="https://example.com/releases/2.4.0",
        inherit_from="2.3.0",
        reuse_existing=True,
    )


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--release-date", "31-07-2026"),
        ("--release-date", "2026-7-31"),
        ("--end-of-support-date", "2026-02-30"),
    ],
)
def test_dates_require_iso_calendar_dates(
    runner: CliRunner,
    base_env: dict[str, str],
    flag: str,
    value: str,
) -> None:
    result = runner.invoke(
        cli,
        [
            "create-version",
            "--product",
            "security-camera",
            "--version",
            "2.4.0",
            flag,
            value,
        ],
        env=base_env,
    )

    assert result.exit_code == 4
    assert "YYYY-MM-DD" in result.output


def test_json_output_has_stable_created_boolean(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(return_value=_created_result())

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "--output",
                "json",
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
            ],
            env=base_env,
        )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["created"] is True


def test_reused_output_does_not_claim_no_existing_evidence(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    existing = {**_created_result(), "created": False}
    client = MagicMock()
    client.create_product_version = AsyncMock(return_value=existing)

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
                "--reuse-existing",
            ],
            env=base_env,
        )

    assert result.exit_code == 0
    assert "Product version reused" in result.output
    assert "Evidence: not changed by this command" in result.output
    assert "New evidence: none uploaded" not in result.output


def test_json_error_keeps_stdout_empty_and_preserves_request_id(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(
        side_effect=APIError(
            "Version already exists",
            status_code=400,
            request_id="req-create-123",
        )
    )

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "--output",
                "json",
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
            ],
            env=base_env,
        )

    assert result.exit_code == 3
    assert result.stdout == ""
    assert "Version already exists" in result.stderr
    assert "req-create-123" in result.stderr


@pytest.mark.asyncio
async def test_client_posts_json_to_existing_product(monkeypatch) -> None:
    config = CRAEvidenceConfig(
        api_key="test_key_123",
        url="https://api.test.craevidence.com",
    )
    client = CRAEvidenceClient(config)
    monkeypatch.setattr(
        client,
        "_resolve_product_id",
        AsyncMock(return_value=PRODUCT_ID),
    )
    monkeypatch.setattr(
        client,
        "_resolve_version_id",
        AsyncMock(return_value=SOURCE_VERSION_ID),
    )
    captured: dict = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return httpx.Response(
                status_code=201,
                json={
                    "id": VERSION_ID,
                    "product_id": PRODUCT_ID,
                    "version_number": "2.4.0",
                    "release_state": "draft",
                },
            )

    monkeypatch.setattr(
        "cra_evidence_cli.client.httpx.AsyncClient",
        FakeAsyncClient,
    )

    result = await client.create_product_version(
        product="security-camera",
        version="2.4.0",
        release_type="security_patch",
        environment="qa-eu",
        release_notes="Security update",
        release_date="2026-07-31",
        end_of_support_date="2031-07-31",
        external_url="https://example.com/releases/2.4.0",
        inherit_from="2.3.0",
    )

    assert captured["url"] == (
        f"https://api.test.craevidence.com/api/v1/products/{PRODUCT_ID}/versions"
    )
    assert captured["json"] == {
        "version_number": "2.4.0",
        "release_type": "security_patch",
        "environment_override": "qa-eu",
        "release_notes": "Security update",
        "release_date": "2026-07-31",
        "end_of_support_date": "2031-07-31",
        "external_url": "https://example.com/releases/2.4.0",
        "inherit_from_version_id": SOURCE_VERSION_ID,
    }
    assert result["created"] is True
    assert result["release_state"] == "draft"


@pytest.mark.asyncio
async def test_reuse_existing_never_posts(monkeypatch) -> None:
    config = CRAEvidenceConfig(
        api_key="test_key_123",
        url="https://api.test.craevidence.com",
    )
    client = CRAEvidenceClient(config)
    monkeypatch.setattr(
        client,
        "_resolve_product_id",
        AsyncMock(return_value=PRODUCT_ID),
    )
    monkeypatch.setattr(
        client,
        "_find_version_by_number",
        AsyncMock(
            return_value={
                "id": VERSION_ID,
                "version_number": "2.4.0",
                "release_state": "draft",
            }
        ),
    )

    class UnexpectedAsyncClient:
        def __init__(self, **_kwargs):
            message = "reuse-existing must not issue a POST"
            raise AssertionError(message)

    monkeypatch.setattr(
        "cra_evidence_cli.client.httpx.AsyncClient",
        UnexpectedAsyncClient,
    )

    result = await client.create_product_version(
        product="security-camera",
        version="2.4.0",
        reuse_existing=True,
    )

    assert result == {
        "id": VERSION_ID,
        "product_id": PRODUCT_ID,
        "version_number": "2.4.0",
        "release_state": "draft",
        "created": False,
    }


def test_created_version_can_receive_code_check_sarif_without_sbom(
    runner: CliRunner,
    base_env: dict[str, str],
    tmp_path: Path,
) -> None:
    create_client = MagicMock()
    create_client.create_product_version = AsyncMock(return_value=_created_result())

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=create_client,
    ):
        created = runner.invoke(
            cli,
            [
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
            ],
            env=base_env,
        )

    report = SASTReport(
        engine_version="1.25.0",
        rules_path="/rules",
        rule_count=8,
        findings=[],
        scan_failed=False,
        failure_reason=None,
        sarif_raw={"version": "2.1.0", "runs": []},
    )
    upload_client = MagicMock()
    upload_client.upload_sarif = AsyncMock(return_value={})

    with (
        patch(
            "cra_evidence_cli.commands.code_check.opengrep_path",
            return_value="/usr/bin/opengrep",
        ),
        patch(
            "cra_evidence_cli.commands.code_check.run_scan",
            return_value=report,
        ),
        patch(
            "cra_evidence_cli.client.CRAEvidenceClient",
            return_value=upload_client,
        ),
    ):
        uploaded = runner.invoke(
            cli,
            [
                "code-check",
                str(tmp_path),
                "--upload",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
            ],
            env=base_env,
        )

    assert created.exit_code == 0, created.output
    assert uploaded.exit_code == 0, uploaded.output
    upload_client.upload_sarif.assert_awaited_once()
    assert upload_client.upload_sarif.await_args.kwargs["product"] == "security-camera"
    assert upload_client.upload_sarif.await_args.kwargs["version"] == "2.4.0"




def test_help_states_no_evidence_and_opt_in_inheritance(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["create-version", "--help"])
    # Click rewraps help paragraphs, so compare on normalized whitespace.
    text = " ".join(result.output.split())

    assert result.exit_code == 0
    assert "--reuse-existing" in text
    assert "--inherit-from" in text
    assert "without uploading new evidence" in text
    assert "links reusable product-level documents and templates" in text
    assert "only when --inherit-from is passed" in text


def test_command_needs_an_api_key(monkeypatch) -> None:
    """An account command, so it must not be treated as a no-key local command."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    # Ignore any config file on the machine running the tests.
    monkeypatch.setattr("cra_evidence_cli.config.load_config_file", dict)
    cli_runner = CliRunner()

    with cli_runner.isolated_filesystem():
        result = cli_runner.invoke(
            cli,
            ["create-version", "--product", "security-camera", "--version", "2.4.0"],
        )

    assert result.exit_code == 6
    assert "API key is required" in (result.output + (result.stderr or ""))


def test_duplicate_version_fails_by_default(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(
        side_effect=APIError(
            "Version '2.4.0' already exists for this product",
            status_code=400,
        )
    )

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            ["create-version", "--product", "security-camera", "--version", "2.4.0"],
            env=base_env,
        )

    assert result.exit_code == 3
    assert "already exists" in result.output
    assert client.create_product_version.await_args.kwargs["reuse_existing"] is False


def test_authentication_failure_exits_2(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(
        side_effect=AuthenticationError("API key is missing required scope: version:write")
    )

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            ["create-version", "--product", "security-camera", "--version", "2.4.0"],
            env=base_env,
        )

    assert result.exit_code == 2
    assert "version:write" in result.output


def test_unknown_release_type_is_rejected(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(return_value=_created_result())

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            [
                "create-version",
                "--product",
                "security-camera",
                "--version",
                "2.4.0",
                "--release-type",
                "hotfix",
            ],
            env=base_env,
        )

    assert result.exit_code != 0
    client.create_product_version.assert_not_awaited()


def test_missing_product_is_reported_and_nothing_is_created(
    runner: CliRunner,
    base_env: dict[str, str],
) -> None:
    client = MagicMock()
    client.create_product_version = AsyncMock(
        side_effect=APIError("Product 'ghost' not found.", status_code=404)
    )

    with patch(
        "cra_evidence_cli.commands.create_version.CRAEvidenceClient",
        return_value=client,
    ):
        result = runner.invoke(
            cli,
            ["create-version", "--product", "ghost", "--version", "2.4.0"],
            env=base_env,
        )

    assert result.exit_code == 3
    assert "not found" in result.output
    # No product-creation or evidence path is reached on a missing product.
    assert client.create_product.call_count == 0
    assert client.upload_sbom.call_count == 0




def _client() -> CRAEvidenceClient:
    return CRAEvidenceClient(
        CRAEvidenceConfig(api_key="test_key_123", url="https://api.test.craevidence.com")
    )


class _FakeAsyncClient:
    """Stub for httpx.AsyncClient that records every POST."""

    posts: list[dict] = []
    status_code = 201
    body: dict | None = None

    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers, json):
        type(self).posts.append({"url": url, "json": json})
        return httpx.Response(
            status_code=type(self).status_code,
            json=type(self).body
            if type(self).body is not None
            else {
                "id": VERSION_ID,
                "product_id": PRODUCT_ID,
                "version_number": "2.4.0",
                "release_state": "draft",
            },
        )


def _recorder(**overrides):
    """A fresh stub class per test, so recorded posts never leak between tests."""
    return type("_Recorder", (_FakeAsyncClient,), {"posts": [], **overrides})


def _products_response() -> httpx.Response:
    return httpx.Response(
        status_code=200,
        json=[{"id": PRODUCT_ID, "slug": "security-camera", "name": "Security Camera"}],
    )


@pytest.mark.asyncio
async def test_product_slug_resolves_before_the_create(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(return_value=_products_response())
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    await client.create_product_version(product="security-camera", version="2.4.0")

    client._request_with_retry.assert_awaited_once_with("GET", PRODUCTS_URL)
    assert recorder.posts[0]["url"] == VERSIONS_URL
    assert recorder.posts[0]["json"] == {"version_number": "2.4.0"}


@pytest.mark.asyncio
async def test_product_uuid_skips_the_lookup(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock()
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    await client.create_product_version(product=PRODUCT_ID, version="2.4.0")

    client._request_with_retry.assert_not_awaited()
    assert recorder.posts[0]["url"] == VERSIONS_URL


@pytest.mark.asyncio
async def test_no_inheritance_key_without_the_flag(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(return_value=_products_response())
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    await client.create_product_version(product="security-camera", version="2.4.0")

    assert "inherit_from_version_id" not in recorder.posts[0]["json"]


@pytest.mark.asyncio
async def test_uuid_shaped_version_number_resolves_from_product_versions() -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        return_value=httpx.Response(
            status_code=200,
            json=[
                {
                    "id": SOURCE_VERSION_ID,
                    "version_number": VERSION_ID,
                }
            ],
        )
    )

    resolved = await client._resolve_version_id(
        PRODUCT_ID,
        VERSION_ID,
        "security-camera",
    )

    assert resolved == SOURCE_VERSION_ID
    client._request_with_retry.assert_awaited_once_with("GET", VERSIONS_URL)


@pytest.mark.asyncio
async def test_version_uuid_must_belong_to_the_selected_product() -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        return_value=httpx.Response(
            status_code=200,
            json=[{"id": SOURCE_VERSION_ID, "version_number": "1.0.0"}],
        )
    )

    with pytest.raises(APIError) as exc_info:
        await client._resolve_version_id(
            PRODUCT_ID,
            VERSION_ID,
            "security-camera",
        )

    assert exc_info.value.status_code == 404
    assert VERSION_ID in str(exc_info.value)


@pytest.mark.asyncio
async def test_version_reference_rejects_id_number_ambiguity() -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        return_value=httpx.Response(
            status_code=200,
            json=[
                {"id": VERSION_ID, "version_number": "1.0.0"},
                {"id": SOURCE_VERSION_ID, "version_number": VERSION_ID},
            ],
        )
    )

    with pytest.raises(APIError) as exc_info:
        await client._resolve_version_id(
            PRODUCT_ID,
            VERSION_ID,
            "security-camera",
        )

    assert exc_info.value.status_code == 409
    assert "ambiguous" in str(exc_info.value)


@pytest.mark.asyncio
async def test_reuse_existing_creates_when_the_version_is_absent(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        side_effect=[
            _products_response(),
            httpx.Response(status_code=200, json=[{"id": "other", "version_number": "1.0.0"}]),
        ]
    )
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    result = await client.create_product_version(
        product="security-camera",
        version="2.4.0",
        reuse_existing=True,
    )

    assert recorder.posts[0]["json"] == {"version_number": "2.4.0"}
    assert result["created"] is True


@pytest.mark.asyncio
async def test_reuse_existing_reports_the_state_the_server_returned(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        side_effect=[
            _products_response(),
            httpx.Response(
                status_code=200,
                json=[
                    {"id": "other", "version_number": "1.0.0", "release_state": "released"},
                    {"id": VERSION_ID, "version_number": "2.4.0", "release_state": "approved"},
                ],
            ),
        ]
    )
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    result = await client.create_product_version(
        product="security-camera",
        version="2.4.0",
        reuse_existing=True,
    )

    assert recorder.posts == []
    assert result["release_state"] == "approved"
    assert result["created"] is False


@pytest.mark.asyncio
async def test_unknown_product_never_posts(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(return_value=httpx.Response(status_code=200, json=[]))
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    with pytest.raises(APIError) as exc_info:
        await client.create_product_version(product="ghost", version="2.4.0")

    assert exc_info.value.status_code == 404
    assert recorder.posts == []


@pytest.mark.asyncio
async def test_duplicate_response_surfaces_as_an_api_error(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(return_value=_products_response())
    recorder = _recorder(
        status_code=409,
        body={
            "error": {
                "code": "RESOURCE_ALREADY_EXISTS",
                "message": "Version '2.4.0' already exists for this product",
            }
        },
    )
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    with pytest.raises(APIError) as exc_info:
        await client.create_product_version(product="security-camera", version="2.4.0")

    assert exc_info.value.status_code == 409
    assert exc_info.value.error_code == "RESOURCE_ALREADY_EXISTS"
    assert exc_info.value.exit_code == 3


@pytest.mark.asyncio
async def test_reuse_existing_recovers_from_duplicate_create_race(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        side_effect=[
            _products_response(),
            httpx.Response(status_code=200, json=[]),
            httpx.Response(
                status_code=200,
                json=[
                    {
                        "id": VERSION_ID,
                        "version_number": "2.4.0",
                        "release_state": "draft",
                    }
                ],
            ),
        ]
    )
    recorder = _recorder(
        status_code=409,
        body={
            "error": {
                "code": "RESOURCE_ALREADY_EXISTS",
                "message": "Version '2.4.0' already exists for this product",
            }
        },
    )
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    result = await client.create_product_version(
        product="security-camera",
        version="2.4.0",
        reuse_existing=True,
    )

    assert len(recorder.posts) == 1
    assert client._request_with_retry.await_count == 3
    assert result == {
        "id": VERSION_ID,
        "product_id": PRODUCT_ID,
        "version_number": "2.4.0",
        "release_state": "draft",
        "created": False,
    }


@pytest.mark.asyncio
async def test_reuse_existing_does_not_recover_unrelated_conflict(monkeypatch) -> None:
    client = _client()
    client._request_with_retry = AsyncMock(
        side_effect=[
            _products_response(),
            httpx.Response(status_code=200, json=[]),
        ]
    )
    recorder = _recorder(
        status_code=409,
        body={
            "error": {
                "code": "CONFLICT",
                "message": "Another conflict",
            }
        },
    )
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    with pytest.raises(APIError) as exc_info:
        await client.create_product_version(
            product="security-camera",
            version="2.4.0",
            reuse_existing=True,
        )

    assert exc_info.value.error_code == "CONFLICT"
    assert client._request_with_retry.await_count == 2


@pytest.mark.asyncio
async def test_only_product_and_version_endpoints_are_contacted(monkeypatch) -> None:
    """No upload, scan, release, risk-assessment, or due-diligence endpoint."""
    client = _client()
    client._request_with_retry = AsyncMock(return_value=_products_response())
    recorder = _recorder()
    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", recorder)

    await client.create_product_version(product="security-camera", version="2.4.0")

    urls = [call.args[1] for call in client._request_with_retry.await_args_list]
    urls += [post["url"] for post in recorder.posts]
    assert urls == [PRODUCTS_URL, VERSIONS_URL]
    for fragment in ("/sarif", "/scan", "release-state", "risk-assessment", "distributor"):
        assert not any(fragment in url for url in urls)



_NEW_OR_CHANGED_FILES = [
    "cra_evidence_cli/commands/create_version.py",
    "cra_evidence_cli/client.py",
    "cra_evidence_cli/cli.py",
    "docs/account-commands.md",
    "README.md",
    "CHANGELOG.md",
    "tests/test_create_version_command.py",
]


def test_plain_language_guard_self_check_new_files() -> None:
    """Direct self-check independent of git tracking (see test_plain_language_guard.py
    for the repo-wide sweep, which only covers files once they are git-tracked)."""
    offenders: dict[str, list[str]] = {}
    for rel in _NEW_OR_CHANGED_FILES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        bad = []
        for line in text.splitlines():
            bad.extend(_line_violations(rel, line))
        if bad:
            offenders[rel] = bad
    assert offenders == {}, offenders


def test_no_em_dashes_in_new_files() -> None:
    # Built from a Unicode escape, not a literal character, so this very
    # assertion string cannot trip the check against its own source file.
    em_dash = "\u2014"
    for rel in _NEW_OR_CHANGED_FILES:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert em_dash not in text, f"em dash found in {rel}"


def test_command_module_makes_no_compliance_claim() -> None:
    text = (REPO_ROOT / "cra_evidence_cli/commands/create_version.py").read_text(
        encoding="utf-8"
    )
    lowered = text.lower()
    assert "compliant" not in lowered
    assert "proves" not in lowered
