"""Network behavior of `check` as documented in README.md.

`check` never contacts CRA Evidence, even with an API key and URL configured, and
it still requests CISA KEV and FIRST EPSS enrichment when Grype database updates
are turned off with GRYPE_DB_AUTO_UPDATE=false.
"""

import json

import httpx
from click.testing import CliRunner

from cra_evidence_cli import client as client_module
from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import check as check_module
from cra_evidence_cli.local.models import CoverageSource, Finding

CRA_EVIDENCE_URL = "https://cra-evidence.example.test"
_NETWORK_DISABLED = "network disabled in this test"


class _FakeScanner:
    def __init__(self, *args, **kwargs):
        pass

    def is_available(self):
        return True

    def scan_sbom(self, sbom_path):
        finding = Finding(
            id="CVE-2025-9999",
            package="acme",
            version="1.0.0",
            severity="high",
            purl="pkg:pypi/acme@1.0.0",
        )
        return [finding], CoverageSource("grype-db", "present", as_of="2026-06-10")


def _write_sbom(path):
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "acme",
                        "version": "1.0.0",
                        "purl": "pkg:pypi/acme@1.0.0",
                    }
                ],
            }
        )
    )


def _record_network(monkeypatch):
    requests = []
    clients = []

    def record_send(self, request, *args, **kwargs):
        requests.append(str(request.url))
        raise httpx.ConnectError(_NETWORK_DISABLED, request=request)

    async def record_async_send(self, request, *args, **kwargs):
        requests.append(str(request.url))
        raise httpx.ConnectError(_NETWORK_DISABLED, request=request)

    original_init = client_module.CRAEvidenceClient.__init__

    def record_client(self, *args, **kwargs):
        clients.append((args, kwargs))
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "send", record_send)
    monkeypatch.setattr(httpx.AsyncClient, "send", record_async_send)
    monkeypatch.setattr(client_module.CRAEvidenceClient, "__init__", record_client)
    return requests, clients


def _install_scanner_and_enrichment(monkeypatch):
    calls = {"kev": 0, "epss": 0}

    def fake_kev():
        calls["kev"] += 1
        return set(), CoverageSource("cisa-kev", "present", as_of="2026-06-10")

    def fake_epss(cves):
        calls["epss"] += 1
        return {}, CoverageSource("first-epss", "present", as_of="2026-06-10")

    monkeypatch.setattr(check_module, "GrypeLocalScanner", _FakeScanner)
    monkeypatch.setattr(check_module, "get_embedded_syft_version", lambda: None)
    monkeypatch.setattr(check_module, "fetch_kev_catalog", fake_kev)
    monkeypatch.setattr(check_module, "fetch_epss_scores", fake_epss)
    return calls


def _run_check(tmp_path):
    sbom = tmp_path / "sbom.json"
    _write_sbom(sbom)
    return CliRunner().invoke(cli, ["--output", "json", "check", "--sbom", str(sbom)])


def test_check_never_contacts_cra_evidence(monkeypatch, tmp_path):
    """Fails if `check` builds an API client or sends any request to the configured service."""
    monkeypatch.setenv("CRA_EVIDENCE_API_KEY", "cra_test_key")
    monkeypatch.setenv("CRA_EVIDENCE_URL", CRA_EVIDENCE_URL)
    _install_scanner_and_enrichment(monkeypatch)
    requests, clients = _record_network(monkeypatch)

    result = _run_check(tmp_path)

    assert json.loads(result.output)["schema_version"] == "craevidence.local_check.v1"
    assert clients == []
    assert not [url for url in requests if url.startswith(CRA_EVIDENCE_URL)]


def test_check_requests_kev_and_epss_with_grype_updates_off(monkeypatch, tmp_path):
    """Fails if turning off Grype database updates also skips KEV or EPSS enrichment."""
    monkeypatch.delenv("CRA_EVIDENCE_API_KEY", raising=False)
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    calls = _install_scanner_and_enrichment(monkeypatch)
    _record_network(monkeypatch)

    result = _run_check(tmp_path)

    assert json.loads(result.output)["schema_version"] == "craevidence.local_check.v1"
    assert calls == {"kev": 1, "epss": 1}
