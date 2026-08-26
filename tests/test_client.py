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


def test_handle_response_preserves_structured_error_payload(test_config):
    """error.code / error.details from the RFC 7807 body land on the raised
    APIError so callers can tell apart error shapes that share a status
    code (for example, which kind of resource a 404 was actually about)."""
    client = CRAEvidenceClient(test_config)

    response = Response(
        status_code=404,
        json={
            "error": {
                "code": "RESOURCE_NOT_FOUND",
                "detail": "No structured risk assessment exists for this version.",
                "details": {
                    "resource_type": "Risk assessment",
                    "product_level_assessment_exists": False,
                },
            }
        },
    )

    with pytest.raises(APIError) as exc_info:
        client._handle_response(response)

    error = exc_info.value
    assert error.status_code == 404
    assert error.error_code == "RESOURCE_NOT_FOUND"
    assert error.error_details == {
        "resource_type": "Risk assessment",
        "product_level_assessment_exists": False,
    }


def test_handle_response_error_code_and_details_default_to_none(test_config):
    """A body without the RFC 7807 envelope (or a non-JSON body) leaves
    error_code/error_details unset rather than raising."""
    client = CRAEvidenceClient(test_config)

    response = Response(status_code=400, json={"detail": "Invalid request"})

    with pytest.raises(APIError) as exc_info:
        client._handle_response(response)

    error = exc_info.value
    assert error.error_code is None
    assert error.error_details is None


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
            captured["content_type"] = files["file"][2]
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
        component_version="2.4.0",
    )

    assert result["artifact_id"] == "sbom-123"
    assert captured["url"] == "https://api.test.craevidence.com/api/v1/ci/upload"
    assert captured["file_name"] == "sbom.json"
    assert captured["content_type"] == "application/json"
    assert captured["data"]["target_markets"] == "DE,ES"
    assert captured["data"]["component_version"] == "2.4.0"


@pytest.mark.asyncio
async def test_upload_sbom_uses_xml_multipart_media_type(test_config, tmp_path, monkeypatch):
    sbom_file = tmp_path / "sbom.xml"
    sbom_file.write_text("<bom/>")
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, files, data):
            captured["content_type"] = files["file"][2]
            return Response(status_code=201, json={"artifact_id": "sbom-xml"})

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    await CRAEvidenceClient(test_config).upload_sbom(
        product="security-camera",
        version="0.1.0",
        file_path=sbom_file,
    )

    assert captured["content_type"] == "application/xml"


@pytest.mark.asyncio
async def test_upload_sbom_rejects_unknown_filename_extension(test_config, tmp_path):
    sbom_file = tmp_path / "sbom.txt"
    sbom_file.write_text("not an SBOM")

    with pytest.raises(APIError, match=r"\.json or \.xml") as raised:
        await CRAEvidenceClient(test_config).upload_sbom(
            product="security-camera",
            version="0.1.0",
            file_path=sbom_file,
        )

    assert raised.value.status_code == 422


@pytest.mark.asyncio
async def test_validate_sbom_uses_xml_multipart_media_type(test_config, tmp_path, monkeypatch):
    sbom_file = tmp_path / "sbom.xml"
    sbom_file.write_text("<bom/>")
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers, files):
            captured["content_type"] = files["file"][2]
            return Response(status_code=200, json={"valid": True})

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    await CRAEvidenceClient(test_config).validate_sbom(sbom_file)

    assert captured["content_type"] == "application/xml"


@pytest.mark.asyncio
async def test_validate_sbom_rejects_unknown_filename_extension(test_config, tmp_path):
    sbom_file = tmp_path / "sbom.txt"
    sbom_file.write_text("not an SBOM")

    with pytest.raises(APIError, match=r"\.json or \.xml") as raised:
        await CRAEvidenceClient(test_config).validate_sbom(sbom_file)

    assert raised.value.status_code == 422


@pytest.mark.asyncio
async def test_upload_sbom_create_product_defaults_to_false_in_form(
    test_config, tmp_path, monkeypatch
):
    """Product creation is opt-in: the literal form field is "false" unless
    the caller explicitly asks for create_product=True."""
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
            captured["data"] = data
            return Response(
                status_code=201,
                json={"artifact_id": "sbom-123"},
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    await client.upload_sbom(
        product="security-camera",
        version="0.1.0",
        file_path=sbom_file,
    )

    assert captured["data"]["create_product"] == "false"


@pytest.mark.asyncio
async def test_upload_sbom_create_product_true_posts_true_in_form(
    test_config, tmp_path, monkeypatch
):
    """Passing create_product=True sends the literal form field "true"."""
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
            captured["data"] = data
            return Response(
                status_code=201,
                json={"artifact_id": "sbom-123"},
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    await client.upload_sbom(
        product="security-camera",
        version="0.1.0",
        file_path=sbom_file,
        create_product=True,
        target_markets="DE,ES",
    )

    assert captured["data"]["create_product"] == "true"


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


@pytest.mark.asyncio
async def test_oidc_get_exchanges_token_before_request(monkeypatch):
    """In OIDC mode with no cached token, a GET first exchanges the OIDC
    token, then sends the request with the exchanged bearer token."""
    from cra_evidence_cli.config import CRAEvidenceConfig

    config = CRAEvidenceConfig(
        url="https://api.test.craevidence.com",
        oidc_mode=True,
        oidc_token="github-oidc-token",  # noqa: S106
    )
    client = CRAEvidenceClient(config)

    calls = []

    class FakeAsyncClient:
        def __init__(self, timeout=None):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, headers=None):
            calls.append(("POST", url, headers, json))
            return Response(status_code=200, json={"access_token": "exchanged-token"})

        async def request(self, method, url, headers=None, **kwargs):
            calls.append((method, url, headers))
            return Response(status_code=200, json={"cra_status": "ready"})

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    result = await client.get_version_status(product="p", version="1.0")

    assert result == {"cra_status": "ready"}
    assert len(calls) == 2
    exchange = calls[0]
    assert exchange[0] == "POST"
    assert exchange[1] == "https://api.test.craevidence.com/api/v1/oidc/token"
    assert exchange[3] == {"github_token": "github-oidc-token"}
    get_call = calls[1]
    assert get_call[0] == "GET"
    assert get_call[1].endswith("/api/v1/ci/status")
    assert get_call[2]["Authorization"] == "Bearer exchanged-token"


@pytest.mark.asyncio
async def test_upload_vex_posts_ci_upload_form(test_config, tmp_path, monkeypatch):
    """VEX uploads go to /api/v1/ci/upload as multipart form data and
    transmit the classification, version, and CI metadata options."""
    vex_file = tmp_path / "vex.json"
    vex_file.write_text('{"vulnerabilities": []}')

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
                json={
                    "artifact_id": "vex-123",
                    "artifact_type": "vex",
                    "vulnerability_count": 3,
                },
            )

    monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeAsyncClient)

    result = await client.upload_vex(
        product="my-product",
        version="1.0.0",
        file_path=vex_file,
        no_inherit=True,
        category="important_class_i",
        subcategory="vpn",
        product_type="software",
        cra_role="manufacturer",
        product_group="iot",
        environment="production",
        tags="ci,nightly",
        commit_sha="abc123",
        branch="main",
        pipeline_id="42",
        repository="https://github.com/acme/device",
        repo_path="firmware",
    )

    assert result["artifact_id"] == "vex-123"
    assert result["vulnerability_count"] == 3
    assert captured["url"] == "https://api.test.craevidence.com/api/v1/ci/upload"
    assert captured["file_name"] == "vex.json"
    assert captured["data"] == {
        "product": "my-product",
        "version": "1.0.0",
        "artifact_type": "vex",
        "create_product": "false",
        "create_version": "false",
        "no_inherit": "true",
        "category": "important_class_i",
        "subcategory": "vpn",
        "product_type": "software",
        "cra_role": "manufacturer",
        "product_group": "iot",
        "environment": "production",
        "tags": "ci,nightly",
        "commit_sha": "abc123",
        "branch": "main",
        "pipeline_id": "42",
        "repository": "https://github.com/acme/device",
        "repo_path": "firmware",
    }
