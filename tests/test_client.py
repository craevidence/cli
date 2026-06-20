"""Tests for CRAEvidenceClient: headers, response handling, and upload contracts."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from httpx import Response

from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.exceptions import APIError, AuthenticationError


def test_client_initialization(test_config):
    """base_url and api_key are set from config on construction."""
    client = CRAEvidenceClient(test_config)

    assert client.base_url == "https://api.test.craevidence.com"
    assert client.config.api_key == "test_key_12345"


def test_client_headers(test_config):
    """Authorization and User-Agent headers are set correctly."""
    client = CRAEvidenceClient(test_config)
    headers = client._get_headers()

    assert headers["Authorization"] == "Bearer test_key_12345"
    assert "craevidence-cli" in headers["User-Agent"]


def test_handle_response_success(test_config, mock_api_response):
    """200 response is parsed and returned as a dict."""
    client = CRAEvidenceClient(test_config)

    response = Response(
        status_code=200,
        json=mock_api_response,
    )

    result = client._handle_response(response)
    assert result == mock_api_response


def test_handle_response_auth_error(test_config):
    """401 response raises AuthenticationError containing the API detail."""
    client = CRAEvidenceClient(test_config)

    response = Response(
        status_code=401,
        json={"detail": "Invalid API key"},
    )

    with pytest.raises(AuthenticationError) as exc_info:
        client._handle_response(response)

    assert "Invalid API key" in str(exc_info.value)


def test_handle_response_forbidden_without_detail_is_actionable(test_config):
    """403 responses without an API detail should not claim the key is invalid."""
    client = CRAEvidenceClient(test_config)

    response = Response(status_code=403, json={})

    with pytest.raises(AuthenticationError) as exc_info:
        client._handle_response(response)

    message = str(exc_info.value)
    assert "Request forbidden" in message
    assert "does not have access" in message
    assert "Invalid or expired API key" not in message


def test_handle_response_api_error(test_config):
    """400 response raises APIError with status_code and request_id populated."""
    client = CRAEvidenceClient(test_config)

    response = Response(
        status_code=400,
        json={"detail": "Invalid request"},
        headers={"X-Request-ID": "req-123"},
    )

    with pytest.raises(APIError) as exc_info:
        client._handle_response(response)

    error = exc_info.value
    assert error.status_code == 400
    assert error.request_id == "req-123"
    assert "Invalid request" in str(error)


@pytest.mark.asyncio
async def test_upload_attestation_posts_version_id_form(test_config, tmp_path, monkeypatch):
    """Attestation upload uses the /attestations/upload form contract."""
    attestation_file = tmp_path / "provenance.json"
    attestation_file.write_text('{"payload": "abc"}')

    client = CRAEvidenceClient(test_config)
    client._resolve_product_id = AsyncMock(return_value="prod-123")
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            json=[{"id": "ver-456", "version_number": "1.0"}],
        )
    )

    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, files, data):
            captured["url"] = url
            captured["headers"] = headers
            captured["file_name"] = files["file"][0]
            captured["data"] = data
            return Response(
                status_code=201,
                json={
                    "id": "att-123",
                    "version_id": "ver-456",
                    "verification_status": "pending",
                },
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    result = await client.upload_attestation(
        product="test",
        version="1.0",
        file_path=Path(attestation_file),
    )

    assert result["id"] == "att-123"
    assert captured["url"] == "https://api.test.craevidence.com/api/v1/attestations/upload"
    assert captured["file_name"] == "provenance.json"
    assert captured["data"] == {"version_id": "ver-456"}


@pytest.mark.asyncio
async def test_upload_sbom_posts_target_markets(test_config, tmp_path, monkeypatch):
    """SBOM uploads forward target_markets to the CI upload form."""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text('{"components": []}')

    client = CRAEvidenceClient(test_config)
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, files, data):
            captured["url"] = url
            captured["file_name"] = files["file"][0]
            captured["data"] = data
            return Response(
                status_code=201,
                json={"artifact_id": "sbom-123"},
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    result = await client.upload_sbom(
        product="security-camera",
        version="0.1.0",
        file_path=sbom_file,
        create_product=True,
        create_version=True,
        target_markets="DE,ES",
    )

    assert result["artifact_id"] == "sbom-123"
    assert captured["url"] == "https://api.test.craevidence.com/api/v1/ci/upload"
    assert captured["file_name"] == "sbom.json"
    assert captured["data"]["target_markets"] == "DE,ES"


@pytest.mark.asyncio
async def test_verify_sbom_signature_posts_bundle_and_policy(test_config, tmp_path, monkeypatch):
    """SBOM signature verification sends only the bundle and signer policy."""
    bundle_file = tmp_path / "sbom.sigstore.json"
    bundle_file.write_text('{"mediaType": "application/vnd.dev.sigstore.bundle+json"}')

    client = CRAEvidenceClient(test_config)
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, files, data):
            captured["url"] = url
            captured["headers"] = headers
            captured["file_name"] = files["signature_bundle"][0]
            captured["data"] = data
            return Response(
                status_code=201,
                json={
                    "sbom_id": "sbom-123",
                    "verification": {
                        "status": "valid",
                        "policy_enforced": True,
                    },
                },
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    result = await client.verify_sbom_signature(
        sbom_id="sbom-123",
        bundle_path=bundle_file,
        expected_identity="https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
        expected_issuer="https://token.actions.githubusercontent.com",
    )

    assert result["verification"]["status"] == "valid"
    assert captured["url"] == "https://api.test.craevidence.com/api/v1/signatures/sboms/sbom-123/verify"
    assert captured["file_name"] == "sbom.sigstore.json"
    assert captured["data"] == {
        "expected_identity": "https://github.com/acme/device/.github/workflows/release.yml@refs/heads/main",
        "expected_issuer": "https://token.actions.githubusercontent.com",
    }


@pytest.mark.asyncio
async def test_download_gemara_source_writes_yaml(test_config, tmp_path):
    """Gemara source download uses the document-scoped provenance endpoint."""
    client = CRAEvidenceClient(test_config)
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            content=b"metadata:\n  type: RiskCatalog\n",
        )
    )
    output_path = tmp_path / "source.yaml"

    result = await client.download_gemara_source(
        document_id="doc-123",
        output_path=output_path,
    )

    assert output_path.read_bytes() == b"metadata:\n  type: RiskCatalog\n"
    assert result == {
        "status": "success",
        "document_id": "doc-123",
        "file_path": str(output_path),
        "size_bytes": 30,
        "provenance_only": True,
    }
    client._request_with_retry.assert_awaited_once()
    assert client._request_with_retry.call_args.args == (
        "GET",
        "https://api.test.craevidence.com/api/v1/documents/doc-123/gemara-source/download",
    )


@pytest.mark.asyncio
async def test_list_hboms_uses_hbom_read_endpoint(test_config):
    client = CRAEvidenceClient(test_config)
    client._resolve_product_id = AsyncMock(return_value="prod-123")
    client._resolve_version_id = AsyncMock(return_value="ver-456")
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            json=[{"id": "hbom-1", "filename": "hardware.json"}],
        )
    )

    result = await client.list_hboms("product", "1.0.0")

    assert result == [{"id": "hbom-1", "filename": "hardware.json"}]
    client._request_with_retry.assert_awaited_once()
    assert client._request_with_retry.call_args.args == (
        "GET",
        "https://api.test.craevidence.com/api/v1/products/prod-123/versions/ver-456/hboms",
    )


@pytest.mark.asyncio
async def test_list_vex_documents_uses_vex_read_endpoint(test_config):
    client = CRAEvidenceClient(test_config)
    client._resolve_product_id = AsyncMock(return_value="prod-123")
    client._resolve_version_id = AsyncMock(return_value="ver-456")
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            json=[{"id": "vex-1", "filename": "vex.json"}],
        )
    )

    result = await client.list_vex_documents("product", "1.0.0")

    assert result == [{"id": "vex-1", "filename": "vex.json"}]
    client._request_with_retry.assert_awaited_once()
    assert client._request_with_retry.call_args.args == (
        "GET",
        "https://api.test.craevidence.com/api/v1/products/prod-123/versions/ver-456/vex",
    )


@pytest.mark.asyncio
async def test_list_static_analysis_results_forwards_supported_filters(test_config):
    client = CRAEvidenceClient(test_config)
    client._resolve_product_id = AsyncMock(return_value="prod-123")
    client._resolve_version_id = AsyncMock(return_value="ver-456")
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            json=[{"id": "finding-1", "rule_id": "rule"}],
        )
    )

    result = await client.list_static_analysis_results(
        "product",
        "1.0.0",
        limit=25,
        offset=5,
        tool_name="CodeQL",
        severity="error",
        suppressed=False,
        min_severity_rank=3,
    )

    assert result == [{"id": "finding-1", "rule_id": "rule"}]
    client._request_with_retry.assert_awaited_once()
    assert client._request_with_retry.call_args.args == (
        "GET",
        "https://api.test.craevidence.com/api/v1/versions/ver-456/static-analysis",
    )
    assert client._request_with_retry.call_args.kwargs["params"] == {
        "limit": 25,
        "offset": 5,
        "tool_name": "CodeQL",
        "severity": "error",
        "suppressed": False,
        "min_severity_rank": 3,
    }


@pytest.mark.asyncio
async def test_get_static_analysis_summary_uses_summary_endpoint(test_config):
    client = CRAEvidenceClient(test_config)
    client._resolve_product_id = AsyncMock(return_value="prod-123")
    client._resolve_version_id = AsyncMock(return_value="ver-456")
    client._request_with_retry = AsyncMock(
        return_value=Response(
            status_code=200,
            json={"total_results": 0},
        )
    )

    result = await client.get_static_analysis_summary("product", "1.0.0")

    assert result == {"total_results": 0}
    client._request_with_retry.assert_awaited_once()
    assert client._request_with_retry.call_args.args == (
        "GET",
        "https://api.test.craevidence.com/api/v1/versions/ver-456/static-analysis/summary",
    )
