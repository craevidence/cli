"""CLI contract for registering a Cosign attestation trust key."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from click.testing import CliRunner

from cra_evidence_cli.cli import cli
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import ValidationError

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


async def _resolved_product_id(_product):
    return "product-123"


def test_help_states_public_key_and_admin_requirement():
    result = CliRunner().invoke(cli, ["trust-attestation-key", "--help"])

    assert result.exit_code == 0, result.output
    assert "Cosign public key" in result.output
    assert "organisation admin" in result.output
    assert "PEM" in result.output
    assert "rejected before the key is sent to" in result.output


def test_command_forwards_name_and_public_key_path():
    runner = CliRunner()
    with patch(
        "cra_evidence_cli.commands.trust.CRAEvidenceClient"
    ) as mock_client_cls, patch(
        "cra_evidence_cli.commands.trust.asyncio.run"
    ) as mock_run:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_run.return_value = {
            "id": "key-123",
            "name": "Gitea release",
            "key_algorithm": "ECDSA",
            "key_fingerprint": "ab" * 32,
        }

        with runner.isolated_filesystem():
            Path("cosign.pub").write_text("PUBLIC KEY", encoding="utf-8")
            result = runner.invoke(
                cli,
                [
                    "trust-attestation-key",
                    "--name",
                    "Gitea release",
                    "--public-key",
                    "cosign.pub",
                ],
                env=BASE_ENV,
            )

    assert result.exit_code == 0, result.output
    mock_client.trust_attestation_key.assert_called_once_with(
        name="Gitea release",
        public_key_path=Path("cosign.pub"),
    )
    assert "Attestation trust key registered" in result.output
    assert "Gitea release" in result.output


def test_verify_help_prefers_product_slug_and_version():
    result = CliRunner().invoke(cli, ["verify-attestation", "--help"])

    assert result.exit_code == 0, result.output
    assert "Product slug or ID" in result.output
    assert "Existing version number" in result.output
    assert "attestation ID is not required" in result.output


def test_verify_command_resolves_normal_identity_without_attestation_id():
    runner = CliRunner()
    with patch(
        "cra_evidence_cli.commands.trust.CRAEvidenceClient"
    ) as mock_client_cls, patch(
        "cra_evidence_cli.commands.trust.asyncio.run"
    ) as mock_run:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_run.return_value = {
            "attestation_id": "att-123",
            "product": "my-product",
            "version": "1.0.0",
            "status": "valid",
            "trust_policy": "signing-key:key-123",
        }

        result = runner.invoke(
            cli,
            [
                "verify-attestation",
                "--product",
                "my-product",
                "--version",
                "1.0.0",
            ],
            env=BASE_ENV,
        )

    assert result.exit_code == 0, result.output
    mock_client.verify_attestation.assert_called_once_with(
        product="my-product",
        version="1.0.0",
        attestation_id=None,
    )
    assert "Build Provenance verification" in result.output
    assert "valid" in result.output


@pytest.mark.parametrize("status", ["pending", "untrusted", "invalid", "error"])
def test_verify_command_exits_22_unless_result_is_valid(status):
    runner = CliRunner()
    with patch(
        "cra_evidence_cli.commands.trust.CRAEvidenceClient"
    ), patch(
        "cra_evidence_cli.commands.trust.asyncio.run",
        return_value={
            "attestation_id": "att-123",
            "product": "my-product",
            "version": "1.0.0",
            "status": status,
            "trust_policy": None,
        },
    ):
        result = runner.invoke(
            cli,
            [
                "verify-attestation",
                "--product",
                "my-product",
                "--version",
                "1.0.0",
            ],
            env=BASE_ENV,
        )

    assert result.exit_code == 22, result.output
    assert status in result.output


def test_verify_command_json_failure_is_valid_json_and_exits_22():
    runner = CliRunner()
    with patch(
        "cra_evidence_cli.commands.trust.CRAEvidenceClient"
    ), patch(
        "cra_evidence_cli.commands.trust.asyncio.run",
        return_value={
            "attestation_id": "att-123",
            "product": "my-product",
            "version": "1.0.0",
            "status": "pending",
            "trust_policy": None,
        },
    ):
        result = runner.invoke(
            cli,
            [
                "--output",
                "json",
                "verify-attestation",
                "--product",
                "my-product",
                "--version",
                "1.0.0",
            ],
            env=BASE_ENV,
        )

    assert result.exit_code == 22, result.output
    assert json.loads(result.output)["status"] == "pending"


@pytest.mark.asyncio
async def test_client_posts_only_public_key_material(monkeypatch, tmp_path):
    posts = []

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers=None, json=None):
            posts.append({"url": url, "headers": headers, "json": json})
            return httpx.Response(
                201,
                json={
                    "id": "key-123",
                    "name": "Gitea release",
                    "key_algorithm": "ECDSA",
                    "key_fingerprint": "ab" * 32,
                },
            )

    monkeypatch.setattr(
        "cra_evidence_cli.client.httpx.AsyncClient",
        FakeAsyncClient,
    )
    public_key_path = tmp_path / "cosign.pub"
    public_key_path.write_text("PUBLIC KEY PEM\n", encoding="utf-8")
    client = CRAEvidenceClient(
        CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://api.test.craevidence.com",
        )
    )

    result = await client.trust_attestation_key(
        name="Gitea release",
        public_key_path=public_key_path,
    )

    assert result["id"] == "key-123"
    assert len(posts) == 1
    assert posts[0]["url"].endswith(
        "/api/v1/signing/attestation-trust-keys"
    )
    assert posts[0]["json"] == {
        "name": "Gitea release",
        "public_key_pem": "PUBLIC KEY PEM\n",
    }
    assert "private_key_pem" not in posts[0]["json"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pem_header",
    [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "ENCRYPTED COSIGN PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ],
)
async def test_client_rejects_private_key_before_network(
    monkeypatch,
    tmp_path,
    pem_header,
):
    class NetworkMustNotBeOpened:
        def __init__(self, *args, **kwargs):
            message = "network client was opened"
            raise AssertionError(message)

    monkeypatch.setattr(
        "cra_evidence_cli.client.httpx.AsyncClient",
        NetworkMustNotBeOpened,
    )
    private_key_path = tmp_path / "cosign.key"
    private_key_path.write_text(
        f"-----BEGIN {pem_header}-----\nredacted\n"
        f"-----END {pem_header}-----\n",
        encoding="utf-8",
    )
    client = CRAEvidenceClient(
        CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://api.test.craevidence.com",
        )
    )

    with pytest.raises(ValidationError, match="Pass cosign.pub"):
        await client.trust_attestation_key(
            name="Gitea release",
            public_key_path=private_key_path,
        )


@pytest.mark.asyncio
async def test_client_verifies_latest_attestation_by_product_and_version(
    monkeypatch,
):
    client = CRAEvidenceClient(
        CRAEvidenceConfig(
            api_key="test_key_123",
            url="https://api.test.craevidence.com",
        )
    )
    monkeypatch.setattr(client, "_resolve_product_id", _resolved_product_id)

    responses = [
        httpx.Response(
            200,
            json=[{"id": "version-123", "version_number": "1.0.0"}],
        ),
        httpx.Response(
            200,
            json=[
                {"id": "latest-attestation", "verification_status": "pending"},
                {"id": "older-attestation", "verification_status": "pending"},
            ],
        ),
        httpx.Response(
            200,
            json={
                "attestation_id": "latest-attestation",
                "status": "valid",
                "trust_policy": "signing-key:key-123",
            },
        ),
    ]
    requests = []

    async def fake_request(method, url, **kwargs):
        requests.append((method, url, kwargs))
        return responses.pop(0)

    monkeypatch.setattr(client, "_request_with_retry", fake_request)

    result = await client.verify_attestation(
        product="my-product",
        version="1.0.0",
    )

    assert result["status"] == "valid"
    assert result["product"] == "my-product"
    assert result["version"] == "1.0.0"
    assert requests == [
        (
            "GET",
            "https://api.test.craevidence.com/api/v1/products/product-123/versions",
            {},
        ),
        (
            "GET",
            "https://api.test.craevidence.com/api/v1/attestations/version/version-123",
            {},
        ),
        (
            "POST",
            "https://api.test.craevidence.com/api/v1/attestations/latest-attestation/verify",
            {"json": {}},
        ),
    ]


def test_json_mode_errors_go_to_stderr_not_stdout(tmp_path, monkeypatch):
    """In --output json mode stdout must stay valid JSON or empty, so error
    chrome belongs on stderr. Regression guard: both trust commands used to
    print errors to stdout, which corrupted machine-readable output."""
    from click.testing import CliRunner

    from cra_evidence_cli.cli import cli

    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    key = tmp_path / "cosign.pub"
    key.write_text(
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--output",
            "json",
            "trust-attestation-key",
            "--name",
            "release-signer",
            "--public-key",
            str(key),
        ],
        env={"CRA_EVIDENCE_API_KEY": ""},
        catch_exceptions=False,
    )

    assert result.exit_code != 0
    stdout = result.stdout.strip()
    assert stdout == "" or stdout.startswith(("{", "[")), (
        f"stdout must be empty or JSON in --output json mode, got: {stdout[:120]!r}"
    )
    assert "Error:" not in result.stdout
