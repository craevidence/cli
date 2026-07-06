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
        """--fail-on high also catches critical, and critical wins."""
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_vulnerability_threshold(scan_response_completed, "high")
        # Highest severity is checked first, so critical determines the exit code
        assert exc_info.value.exit_code == 10
        assert exc_info.value.severity == "critical"

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

        cfg = CRAEvidenceConfig(api_key="cra_test", url="http://localhost")
        client = CRAEvidenceClient(cfg)

        await client.trigger_scan(
            product="p", version="1.0", component="api"
        )

        assert captured["url"] == "http://localhost/api/v1/ci/scan"
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
                captured["url"] = url
                captured["data"] = data
                return _Resp()

        import httpx

        monkeypatch.setattr(httpx, "AsyncClient", _AsyncClient)

        cfg = CRAEvidenceConfig(api_key="cra_test", url="http://localhost")
        client = CRAEvidenceClient(cfg)

        await client.trigger_scan(product="p", version="1.0")

        assert captured["url"] == "http://localhost/api/v1/ci/scan"
        assert "component" not in captured["data"]


class TestScanFailOnGate:
    """scan --fail-on waits for the asynchronous scan, then gates on the
    completed counts from the status endpoint."""

    BASE_ENV = {
        "CRA_EVIDENCE_API_KEY": "test_key_123",
        "CRA_EVIDENCE_URL": "http://localhost:8000",
    }

    @staticmethod
    def _summary(critical=0, high=0, medium=0, low=0):
        total = critical + high + medium + low
        return {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": total,
        }

    def _invoke(self, responses, args, monotonic_values=None):
        from itertools import count
        from unittest.mock import MagicMock, patch

        from click.testing import CliRunner

        from cra_evidence_cli.cli import cli

        runner = CliRunner()
        with patch(
            "cra_evidence_cli.commands.scan.CRAEvidenceClient"
        ) as mock_client_cls, patch(
            "cra_evidence_cli.commands.scan.asyncio.run",
            side_effect=responses,
        ) as mock_run, patch(
            "cra_evidence_cli.commands.scan.time.sleep"
        ) as mock_sleep, patch(
            "cra_evidence_cli.commands.scan.time.monotonic",
            side_effect=monotonic_values or count(0.0, 1.0),
        ):
            mock_client_cls.return_value = MagicMock()
            result = runner.invoke(
                cli,
                ["scan", "--product", "p", "--version", "1.0", *args],
                env=self.BASE_ENV,
            )
        return result, mock_run, mock_sleep

    @pytest.mark.parametrize(
        ("fail_on", "summary_kwargs", "expected_exit"),
        [
            ("critical", {"critical": 2}, 10),
            ("high", {"high": 3}, 11),
            ("medium", {"medium": 4}, 12),
        ],
    )
    def test_gate_polls_until_completed_then_exits_on_threshold(
        self, fail_on, summary_kwargs, expected_exit
    ):
        responses = [
            {"scan_id": "s1", "status": "pending", "vulnerabilities": None},
            {"scan_state": "pending", "vulnerability_summary": self._summary()},
            {
                "scan_state": "completed",
                "vulnerability_summary": self._summary(**summary_kwargs),
            },
        ]

        result, mock_run, mock_sleep = self._invoke(
            responses, ["--fail-on", fail_on]
        )

        assert result.exit_code == expected_exit, result.output
        # trigger + two status polls prove the command waited for completion
        assert mock_run.call_count == 3
        mock_sleep.assert_called_once()

    def test_gate_passes_when_completed_scan_is_clean(self):
        responses = [
            {"scan_id": "s1", "status": "pending", "vulnerabilities": None},
            {
                "scan_state": "completed",
                "vulnerability_summary": self._summary(low=7),
            },
        ]

        result, mock_run, _ = self._invoke(responses, ["--fail-on", "medium"])

        assert result.exit_code == 0, result.output
        assert mock_run.call_count == 2

    def test_gate_timeout_exits_3_with_clear_message(self):
        responses = [
            {"scan_id": "s1", "status": "pending", "vulnerabilities": None},
            {"scan_state": "pending", "vulnerability_summary": self._summary()},
        ]

        result, mock_run, _ = self._invoke(
            responses,
            ["--fail-on", "high", "--scan-timeout", "300"],
            monotonic_values=[0.0, 301.0],
        )

        assert result.exit_code == 3, result.output
        assert "did not complete within 300 seconds" in result.output
        assert mock_run.call_count == 2

    def test_gate_scan_failed_exits_3(self):
        responses = [
            {"scan_id": "s1", "status": "pending", "vulnerabilities": None},
            {"scan_state": "failed", "vulnerability_summary": self._summary()},
        ]

        result, mock_run, _ = self._invoke(responses, ["--fail-on", "high"])

        assert result.exit_code == 3, result.output
        assert "scan failed" in result.output.lower()

    def test_gate_immediate_failed_trigger_exits_3_without_polling(self):
        responses = [{"scan_id": None, "status": "failed", "vulnerabilities": None}]

        result, mock_run, _ = self._invoke(responses, ["--fail-on", "high"])

        assert result.exit_code == 3, result.output
        assert mock_run.call_count == 1

    def test_no_fail_on_does_not_poll(self):
        responses = [{"scan_id": "s1", "status": "pending", "vulnerabilities": None}]

        result, mock_run, _ = self._invoke(responses, [])

        assert result.exit_code == 0, result.output
        assert mock_run.call_count == 1
