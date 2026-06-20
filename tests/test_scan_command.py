"""Tests for scan command: threshold logic, exit codes, and output formatting."""

import pytest

from cra_evidence_cli.commands.scan import check_vulnerability_threshold, format_scan_output
from cra_evidence_cli.exceptions import VulnerabilityThresholdExceeded


@pytest.fixture
def scan_response_completed():
    """A completed scan with vulnerabilities."""
    return {
        "scan_id": "scan-123",
        "status": "completed",
        "vulnerabilities": {
            "critical": 1,
            "high": 3,
            "medium": 7,
            "low": 15,
        },
    }


@pytest.fixture
def scan_response_pending():
    """A pending scan (no results yet)."""
    return {
        "scan_id": "scan-456",
        "status": "pending",
        "vulnerabilities": None,
    }


@pytest.fixture
def scan_response_disabled():
    """Scan is disabled on the server."""
    return {
        "scan_id": None,
        "status": "disabled",
        "vulnerabilities": None,
    }


class TestScanThresholdChecking:
    """Tests for scan vulnerability threshold logic."""

    def test_no_fail_on(self, scan_response_completed):
        """No --fail-on → never raises."""
        check_vulnerability_threshold(scan_response_completed, None)

    def test_critical_fails(self, scan_response_completed):
        """--fail-on critical fails when critical > 0."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(scan_response_completed, "critical")
        assert exc_info.value.exit_code == 10

    def test_high_fails_on_critical(self, scan_response_completed):
        """--fail-on high also catches critical."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(scan_response_completed, "high")
        # Might fail on critical or high depending on implementation
        assert exc_info.value.exit_code in (10, 11)

    def test_no_vulns_key_passes(self, scan_response_pending):
        """Missing vulnerabilities key → passes."""
        check_vulnerability_threshold(scan_response_pending, "critical")

    def test_clean_scan_passes(self):
        """All zeroes passes any threshold."""
        data = {
            "vulnerabilities": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }
        check_vulnerability_threshold(data, "critical")
        check_vulnerability_threshold(data, "high")
        check_vulnerability_threshold(data, "medium")


class TestScanOutput:
    """Tests that scan output formatting doesn't crash."""

    def test_json_output(self, scan_response_completed):
        """JSON format renders without raising."""
        format_scan_output(scan_response_completed, "json")

    def test_text_output_completed(self, scan_response_completed):
        """Text format renders a completed scan without raising."""
        format_scan_output(scan_response_completed, "text")

    def test_text_output_pending(self, scan_response_pending):
        """Text format renders a pending scan without raising."""
        format_scan_output(scan_response_pending, "text")

    def test_text_output_disabled(self, scan_response_disabled):
        """Text format renders a disabled-scan response without raising."""
        format_scan_output(scan_response_disabled, "text")

    def test_text_output_minimal(self):
        """Minimal dict with only 'status' is handled without raising."""
        format_scan_output({"status": "unknown"}, "text")


class TestTriggerScanComponentForwarding:
    """The client must forward --component as form data when set, and
    must NOT send the field when omitted, so single-component products
    keep the existing server behavior."""

    @pytest.mark.asyncio
    async def test_component_included_when_set(self, monkeypatch):
        from cra_evidence_cli.client import CRAEvidenceClient
        from cra_evidence_cli.config import CRAEvidenceConfig

        captured: dict = {}

        class _Resp:
            status_code = 200
            text = "{}"
            headers = {"content-type": "application/json"}

            def json(self):
                return {"scan_id": "x", "status": "pending"}

        class _AsyncClient:
            def __init__(self, *_, **__):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            async def post(self, url, headers=None, data=None):
                captured["url"] = url
                captured["data"] = data
                return _Resp()

        import httpx

        monkeypatch.setattr(httpx, "AsyncClient", _AsyncClient)

        cfg = CRAEvidenceConfig(api_key="cra_test", base_url="http://localhost")
        client = CRAEvidenceClient(cfg)

        await client.trigger_scan(
            product="p", version="1.0", component="api"
        )

        assert captured["data"]["component"] == "api"
        assert captured["data"]["product"] == "p"
        assert captured["data"]["version"] == "1.0"

    @pytest.mark.asyncio
    async def test_component_omitted_when_none(self, monkeypatch):
        from cra_evidence_cli.client import CRAEvidenceClient
        from cra_evidence_cli.config import CRAEvidenceConfig

        captured: dict = {}

        class _Resp:
            status_code = 200
            text = "{}"
            headers = {"content-type": "application/json"}

            def json(self):
                return {"scan_id": "x", "status": "pending"}

        class _AsyncClient:
            def __init__(self, *_, **__):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            async def post(self, url, headers=None, data=None):
                captured["data"] = data
                return _Resp()

        import httpx

        monkeypatch.setattr(httpx, "AsyncClient", _AsyncClient)

        cfg = CRAEvidenceConfig(api_key="cra_test", base_url="http://localhost")
        client = CRAEvidenceClient(cfg)

        await client.trigger_scan(product="p", version="1.0")

        assert "component" not in captured["data"]
