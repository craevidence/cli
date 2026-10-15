"""Tests for the no-key offline path of `compliance-as-code template`."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml
from click.testing import CliRunner

from cra_evidence_cli.commands.gemara import _fetch_product, _write_gemara_template, gemara
from cra_evidence_cli.config import CRAEvidenceConfig
from cra_evidence_cli.exceptions import APIError


def _obj_without_key() -> dict:
    # No api_key set: the offline path must not require one.
    return {
        "config": CRAEvidenceConfig(url="https://api.craevidence.com", output_format="text"),
        "verbose": False,
    }


def test_offline_policy_template_needs_no_key(tmp_path: Path) -> None:
    out = tmp_path / "cvd-policy.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "policy",
            "--product",
            "my-iot-device",
            "--org",
            "Acme Ltd",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    doc = yaml.safe_load(out.read_text())
    assert doc["metadata"]["type"] == "Policy"
    # Placeholder identity comes straight from --product / --org.
    assert "my-iot-device" in doc["title"]
    assert doc["metadata"]["author"]["name"] == "Acme Ltd"


def test_template_writer_refuses_racing_existing_file_without_force(tmp_path: Path) -> None:
    import click

    out = tmp_path / "existing.yaml"
    out.write_text("keep existing contents", encoding="utf-8")

    with pytest.raises(click.UsageError, match="Use --force to overwrite"):
        _write_gemara_template(out, {"metadata": {"type": "Policy"}})

    assert out.read_text(encoding="utf-8") == "keep existing contents"


@pytest.mark.parametrize("offline", [True, False])
def test_template_force_overwrites_existing_output(monkeypatch, tmp_path: Path, offline):
    out = tmp_path / "existing.yaml"
    out.write_text("old contents", encoding="utf-8")
    if not offline:
        monkeypatch.setattr(
            "cra_evidence_cli.commands.gemara.validate_config", lambda _config: None
        )

        async def fetch_product(_client, _product):
            return {"id": "product-id", "name": "Product"}

        monkeypatch.setattr(
            "cra_evidence_cli.commands.gemara._fetch_product",
            fetch_product,
        )

    args = [
        "template",
        "--type",
        "policy",
        "--product",
        "product",
        "--output",
        str(out),
        "--force",
    ]
    if offline:
        args.append("--offline")
    result = CliRunner().invoke(gemara, args, obj=_obj_without_key())

    assert result.exit_code == 0, result.output
    assert yaml.safe_load(out.read_text(encoding="utf-8"))["metadata"]["type"] == "Policy"


def test_offline_risk_catalog_template_renders_without_components(tmp_path: Path) -> None:
    out = tmp_path / "risk-catalog.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "risk-catalog",
            "--product",
            "my-iot-device",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text())
    assert doc["metadata"]["type"] == "RiskCatalog"
    assert "Install cue to validate locally" in result.output


def test_offline_risk_catalog_can_seed_from_local_sbom(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "urllib3", "version": "2.0.0"},
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "risk-catalog.yaml"

    result = CliRunner().invoke(
        gemara,
        [
            "template",
            "--type",
            "risk-catalog",
            "--product",
            "my-iot-device",
            "--output",
            str(out),
            "--offline",
            "--sbom",
            str(sbom),
        ],
        obj=_obj_without_key(),
    )

    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(out.read_text())
    titles = [risk["title"] for risk in doc["risks"]]
    assert "Risk related to urllib3" in titles


def test_capability_catalog_not_in_type_map() -> None:
    """CapabilityCatalog is not in GEMARA_TYPE_MAP: the backend renderer rejects it."""
    from cra_evidence_cli.commands.gemara import GEMARA_TYPE_MAP

    assert "CapabilityCatalog" not in GEMARA_TYPE_MAP


def test_offline_never_calls_the_api(monkeypatch, tmp_path: Path) -> None:
    # If the offline path touched the API, this stub would raise.
    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        msg = "offline template must not call the API"
        raise AssertionError(msg)

    monkeypatch.setattr("cra_evidence_cli.commands.gemara._fetch_product", _boom)
    monkeypatch.setattr("cra_evidence_cli.commands.gemara.validate_config", _boom)

    out = tmp_path / "control-catalog.yaml"
    runner = CliRunner()
    result = runner.invoke(
        gemara,
        [
            "template",
            "--type",
            "control-catalog",
            "--product",
            "p",
            "--output",
            str(out),
            "--offline",
        ],
        obj=_obj_without_key(),
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


@pytest.mark.asyncio
async def test_fetch_product_resolves_then_requests_product_detail():
    product_id = "12345678-1234-1234-1234-123456789abc"
    captured = {}

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, *, headers):
            captured["url"] = url
            captured["headers"] = headers
            return {"id": product_id, "name": "Resolved product"}

    client = type("Client", (), {})()
    client.base_url = "https://api.test.craevidence.com"
    client._resolve_product_id = AsyncMock(return_value=product_id)
    client._http_client = FakeHttpClient
    client._get_headers = lambda: {"Authorization": "Bearer test"}
    client._handle_response = lambda response: response

    result = await _fetch_product(client, "target-product")

    assert result == {"id": product_id, "name": "Resolved product"}
    client._resolve_product_id.assert_awaited_once_with("target-product")
    assert captured == {
        "url": f"https://api.test.craevidence.com/api/v1/products/{product_id}",
        "headers": {"Authorization": "Bearer test"},
    }


@pytest.mark.parametrize("product_response", [{}, [], {"id": "another-product"}])
@pytest.mark.asyncio
async def test_fetch_product_rejects_invalid_product_detail(product_response):
    product_id = "12345678-1234-1234-1234-123456789abc"

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, *, headers):
            return product_response

    client = type("Client", (), {})()
    client.base_url = "https://api.test.craevidence.com"
    client._resolve_product_id = AsyncMock(return_value=product_id)
    client._http_client = FakeHttpClient
    client._get_headers = lambda: {"Authorization": "Bearer test"}
    client._handle_response = lambda response: response

    with pytest.raises(APIError, match="invalid product response") as exc:
        await _fetch_product(client, "target-product")

    assert exc.value.status_code is None


@pytest.mark.parametrize("template_type", ["policy", "risk-catalog"])
def test_template_does_not_write_when_product_detail_is_invalid(
    monkeypatch, tmp_path: Path, template_type: str
) -> None:
    product_id = "12345678-1234-1234-1234-123456789abc"

    class FakeHttpClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, *, headers):
            return {}

    class FakeClient:
        def __init__(self, _config):
            self.base_url = "https://api.test.craevidence.com"
            self._http_client = FakeHttpClient
            self._get_headers = lambda: {"Authorization": "Bearer test"}
            self._handle_response = lambda response: response

        async def _resolve_product_id(self, _product):
            return product_id

    monkeypatch.setattr("cra_evidence_cli.commands.gemara.validate_config", lambda _config: None)
    monkeypatch.setattr("cra_evidence_cli.commands.gemara.CRAEvidenceClient", FakeClient)
    output = tmp_path / "product-template.yaml"
    result = CliRunner().invoke(
        gemara,
        [
            "template",
            "--type",
            template_type,
            "--product",
            "target-product",
            "--output",
            str(output),
        ],
        obj=_obj_without_key(),
    )

    assert result.exit_code == 3, result.output
    assert "API returned an invalid product response." in result.output
    assert not output.exists()
