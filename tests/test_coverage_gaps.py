"""Coverage gaps from CRA Evidence: display, the opt-in gate and release anyway.

Each test docstring names the wrong implementation it catches.
"""

from __future__ import annotations

import json
from io import StringIO
from itertools import count
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from cra_evidence_cli.cli import cli
from cra_evidence_cli.commands import release as release_module
from cra_evidence_cli.commands import status as status_module
from cra_evidence_cli.commands import upload as upload_module
from cra_evidence_cli.commands.scan import (
    check_vulnerability_threshold as scan_threshold,
)
from cra_evidence_cli.commands.status import check_fail_on
from cra_evidence_cli.commands.upload import check_vulnerability_threshold
from cra_evidence_cli.coverage_gaps import coverage_gap_lines, read_coverage_gaps
from cra_evidence_cli.exceptions import (
    ApplicabilityInconclusive,
    AssessmentIncomplete,
    CoverageGapsFound,
    CRANonCompliantError,
    ReleasePolicyNotMetError,
    VulnerabilityThresholdExceeded,
)

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}

REMEDY_VERSION = (
    "Add the resolved version of each package (for example, generate the SBOM from "
    "the lock file or build output) and upload a new revision."
)
REMEDY_ECOSYSTEM = (
    "Give each package a typed purl (pkg:type/name@version) or a CPE and upload a "
    "new revision."
)
GAPS = {
    "state": "gaps",
    "total": 12,
    "counts_by_reason": {"unknown-package-version": 10, "no-package-ecosystem": 2},
    "remedy": [REMEDY_VERSION, REMEDY_ECOSYSTEM],
}
NO_GAPS = {"state": "none", "total": 0, "counts_by_reason": {}, "remedy": []}


def _summary(coverage_gaps=None, **counts):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0,
        "applicability_pending": False,
        "scan_incomplete": False,
    }
    summary.update(counts)
    if coverage_gaps is not None:
        summary["coverage_gaps"] = coverage_gaps
    return summary


def _status(summary, **extra):
    data = {
        "product": {"id": "p", "name": "My Product", "slug": "my-product"},
        "version": {"id": "v", "number": "1.0", "cra_status": "ready"},
        "cra_status": "ready",
        "release_state": "draft",
        "scan_state": "completed",
        "sbom": {"format": "cyclonedx", "component_count": 14},
        "vulnerability_summary": summary,
        "documents": {},
    }
    data.update(extra)
    return data


def _flat(text: str) -> str:
    return " ".join(text.split())


def _capture(monkeypatch, module):
    out = StringIO()
    monkeypatch.setattr(
        module, "console", Console(file=out, force_terminal=False, width=200, color_system=None)
    )
    return out


class TestReadCoverageGaps:
    def test_absent_object_renders_nothing(self):
        """Catches an older server (no coverage_gaps) being shown as 'no gaps'."""
        gaps = read_coverage_gaps(None)
        assert gaps.state == "absent"
        assert coverage_gap_lines(gaps) == []

    def test_none_state_is_distinct_from_absent(self):
        """Catches a reported 'none' collapsing into the absent case."""
        gaps = read_coverage_gaps(NO_GAPS)
        assert gaps.state == "none"
        assert coverage_gap_lines(gaps) == ["Coverage gaps: none reported."]

    @pytest.mark.parametrize(
        "value",
        [
            "gaps",
            [],
            {"state": "partial", "total": 1},
            {"state": "gaps", "total": True},
            {"state": "gaps", "total": -1},
            {"state": "gaps", "total": "12"},
            {"state": "gaps", "total": 0},
            {"state": "none", "total": 3},
            {"state": "gaps", "total": 2, "counts_by_reason": [2]},
            {"state": "gaps", "total": 2, "counts_by_reason": {"x": -1}},
            {"state": "gaps", "total": 2, "remedy": "fix it"},
            {"state": "gaps", "total": 2, "remedy": [3]},
        ],
    )
    def test_malformed_object_is_invalid(self, value):
        """Catches trusting a malformed server object as a valid gap count."""
        gaps = read_coverage_gaps(value)
        assert gaps.state == "invalid"
        assert coverage_gap_lines(gaps) == [
            "Coverage gaps: reported in a form this CLI cannot read."
        ]

    def test_gap_lines_group_reasons_with_meaning_and_remedies(self):
        """Catches reasons shown without plain-language meaning, or remedies dropped."""
        lines = coverage_gap_lines(read_coverage_gaps(GAPS))
        assert lines[0].startswith(
            "Coverage gaps: 12 package(s) not checked for vulnerabilities."
        )
        assert "  2 with no package type the scanner supports (no-package-ecosystem)" in lines
        assert "  10 with no version in the SBOM (unknown-package-version)" in lines
        assert f"  Next step: {REMEDY_VERSION}" in lines
        assert f"  Next step: {REMEDY_ECOSYSTEM}" in lines

    def test_unknown_reason_code_is_shown_verbatim(self):
        """Catches a reason this CLI has no label for being dropped from the list."""
        lines = coverage_gap_lines(
            read_coverage_gaps(
                {"state": "gaps", "total": 1, "counts_by_reason": {"future-code": 1}}
            )
        )
        assert "  1 with future-code" in lines


class TestStatusDisplay:
    def test_text_shows_gaps_and_remedies(self, monkeypatch):
        """Catches status text that omits the coverage gaps of a completed scan."""
        out = _capture(monkeypatch, status_module)
        status_module.format_status_output(_status(_summary(GAPS)), "text")
        rendered = out.getvalue()
        assert "Coverage gaps: 12 package(s) not checked for vulnerabilities." in rendered
        assert "10 with no version in the SBOM (unknown-package-version)" in rendered
        assert REMEDY_ECOSYSTEM in rendered

    def test_older_server_shows_no_gap_line(self, monkeypatch):
        """Catches an absent field rendered as 'none reported' for an older server."""
        out = _capture(monkeypatch, status_module)
        status_module.format_status_output(_status(_summary()), "text")
        assert "Coverage gaps" not in out.getvalue()

    def test_remedy_markup_is_printed_literally(self, monkeypatch):
        """Catches server text interpreted as Rich markup instead of printed as sent."""
        out = _capture(monkeypatch, status_module)
        gaps = {**GAPS, "remedy": ["Use [bold]pkg:npm/x@1[/bold]."]}
        status_module.format_status_output(_status(_summary(gaps)), "text")
        assert "Use [bold]pkg:npm/x@1[/bold]." in out.getvalue()

    def test_per_sbom_coverage_only_in_verbose(self, monkeypatch):
        """Catches per-SBOM rows missing in verbose output or cluttering default output."""
        scan_coverage = [
            {"sbom_id": "s1", "filename": "app.cdx.json", "state": "gaps", "total_gaps": 12},
            {"sbom_id": "s2", "filename": "os.cdx.json", "state": "not_established"},
        ]
        data = _status(_summary(GAPS), scan_coverage=scan_coverage)
        out = _capture(monkeypatch, status_module)
        status_module.format_status_output(data, "text", verbose=True)
        rendered = out.getvalue()
        assert "app.cdx.json: gaps (12 package(s) not checked)" in rendered
        assert "os.cdx.json: not_established" in rendered

        out = _capture(monkeypatch, status_module)
        status_module.format_status_output(data, "text", verbose=False)
        assert "app.cdx.json" not in out.getvalue()

    def test_json_passes_new_fields_through(self):
        """Catches the JSON output dropping or rewriting the server's new fields."""
        data = _status(_summary(GAPS), scan_coverage=[{"sbom_id": "s1", "state": "gaps"}])
        with patch.object(status_module, "CRAEvidenceClient") as client_class:
            client_class.return_value.get_version_status = AsyncMock(return_value=data)
            result = CliRunner().invoke(
                cli,
                ["--output", "json", "status", "--product", "p", "--version", "1.0"],
                env=BASE_ENV,
            )
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["vulnerability_summary"]["coverage_gaps"] == GAPS
        assert parsed["scan_coverage"] == [{"sbom_id": "s1", "state": "gaps"}]


def _status_cli(data, args):
    with patch.object(status_module, "CRAEvidenceClient") as client_class:
        client_class.return_value.get_version_status = AsyncMock(return_value=data)
        return CliRunner().invoke(
            cli, ["status", "--product", "p", "--version", "1.0", *args], env=BASE_ENV
        )


class TestStatusGate:
    def test_gaps_without_flag_keep_exit_zero(self):
        """Catches coverage gaps failing a default --fail-on gate."""
        result = _status_cli(_status(_summary(GAPS)), ["--fail-on", "critical"])
        assert result.exit_code == 0, result.output

    def test_gaps_with_flag_exit_30(self):
        """Catches --fail-on-coverage-gaps not failing on reported gaps."""
        result = _status_cli(
            _status(_summary(GAPS)), ["--fail-on", "critical", "--fail-on-coverage-gaps"]
        )
        assert result.exit_code == 30, result.output
        assert "12 package(s) could not be checked" in _flat(result.output)
        assert "10 unknown-package-version" in _flat(result.output)

    def test_flag_with_no_gaps_passes(self):
        """Catches the flag failing a run whose server reported no gaps."""
        result = _status_cli(
            _status(_summary(NO_GAPS)), ["--fail-on", "critical", "--fail-on-coverage-gaps"]
        )
        assert result.exit_code == 0, result.output

    def test_flag_with_older_server_fails_closed(self):
        """Catches an absent field read as 'no gaps' by the opt-in gate."""
        result = _status_cli(
            _status(_summary()), ["--fail-on", "critical", "--fail-on-coverage-gaps"]
        )
        assert result.exit_code == 30, result.output
        assert "did not report coverage gaps" in _flat(result.output)

    def test_flag_with_malformed_object_fails_closed(self):
        """Catches a malformed object passing the opt-in gate."""
        summary = _summary({"state": "none", "total": 4})
        with pytest.raises(CoverageGapsFound, match="cannot read") as exc_info:
            check_fail_on("high", summary, "ready", fail_on_coverage_gaps=True)
        assert exc_info.value.exit_code == 30

    def test_flag_requires_fail_on(self):
        """Catches a silent no-op flag when no --fail-on gate runs."""
        result = _status_cli(_status(_summary(GAPS)), ["--fail-on-coverage-gaps"])
        assert result.exit_code == 2
        assert "--fail-on-coverage-gaps requires --fail-on" in result.output

    @pytest.mark.parametrize("flag", [False, True])
    def test_real_failure_keeps_assessment_incomplete(self, flag):
        """Catches gaps hiding a real scan failure or changing its message."""
        summary = _summary(GAPS, scan_incomplete=True)
        with pytest.raises(AssessmentIncomplete):
            check_fail_on("critical", summary, "ready", fail_on_coverage_gaps=flag)

    def test_flag_keeps_severity_gate(self):
        """Catches the flag replacing the severity gate instead of adding to it."""
        summary = _summary(NO_GAPS, critical=1, total=1)
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on("high", summary, "ready", fail_on_coverage_gaps=True)
        assert exc_info.value.exit_code == 10

    def test_existing_severity_exit_wins_over_gaps(self):
        """Catches the opt-in gap check masking the severity exit (30 instead of 10)."""
        summary = _summary(GAPS, critical=1, total=1)
        with pytest.raises(VulnerabilityThresholdExceeded) as exc_info:
            check_fail_on("high", summary, "ready", fail_on_coverage_gaps=True)
        assert exc_info.value.exit_code == 10


# The opt-in gap check runs only when every existing --fail-on check passes:
# each existing exit keeps its code and message, whatever the gap field holds.
GAP_FIELDS = {
    "gaps": GAPS,
    "absent": None,
    "malformed": {"state": "none", "total": 4},
}
SEVERITY_EXITS = {
    10: {"critical": 1},
    11: {"high": 1},
    12: {"medium": 1},
    13: {"low": 1},
}


def _exit_of(call):
    try:
        call()
    except (
        ApplicabilityInconclusive,
        AssessmentIncomplete,
        CoverageGapsFound,
        CRANonCompliantError,
        ReleasePolicyNotMetError,
        VulnerabilityThresholdExceeded,
    ) as exc:
        return type(exc).__name__, exc.exit_code
    return None, 0


class TestGapGatePrecedence:
    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    @pytest.mark.parametrize("expected", list(SEVERITY_EXITS))
    def test_status_severity_exit_wins(self, field, expected):
        """Catches the gap check running before the severity thresholds (status)."""
        summary = _summary(GAP_FIELDS[field], total=1, **SEVERITY_EXITS[expected])
        assert _exit_of(
            lambda: check_fail_on("low", summary, "ready", fail_on_coverage_gaps=True)
        ) == ("VulnerabilityThresholdExceeded", expected)

    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    @pytest.mark.parametrize(
        ("statuses", "expected"),
        [
            ({"cra_floor_status": "incomplete", "release_policy_status": "ready"},
             ("CRANonCompliantError", 20)),
            ({"cra_floor_status": "ready", "release_policy_status": "incomplete"},
             ("ReleasePolicyNotMetError", 24)),
            ({"cra_status": "incomplete"}, ("CRANonCompliantError", 20)),
        ],
        ids=["floor-20", "policy-24", "legacy-status-20"],
    )
    def test_status_floor_and_policy_exits_win(self, field, statuses, expected):
        """Catches the gap check masking a failing CRA floor or release policy
        (exit 30 instead of 20/24) when there are no vulnerabilities."""
        summary = _summary(GAP_FIELDS[field])
        statuses = dict(statuses)
        cra_status = statuses.pop("cra_status", "ready")
        assert _exit_of(
            lambda: check_fail_on(
                "high", summary, cra_status, fail_on_coverage_gaps=True, **statuses
            )
        ) == expected

    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    @pytest.mark.parametrize(
        ("flag", "expected"),
        [
            ("applicability_pending", "ApplicabilityInconclusive"),
            ("scan_incomplete", "AssessmentIncomplete"),
        ],
    )
    @pytest.mark.parametrize("command", ["status", "scan", "upload"])
    def test_inconclusive_exceptions_keep_their_message(self, command, field, flag, expected):
        """Catches the gap message replacing the applicability or incomplete one."""
        summary = _summary(GAP_FIELDS[field], critical=1, total=1, **{flag: True})
        call = {
            "status": lambda: check_fail_on(
                "high", summary, "incomplete", fail_on_coverage_gaps=True
            ),
            "scan": lambda: scan_threshold(
                {"vulnerabilities": summary}, "high", fail_on_coverage_gaps=True
            ),
            "upload": lambda: check_vulnerability_threshold(
                summary, "high", fail_on_coverage_gaps=True
            ),
        }[command]
        assert _exit_of(call) == (expected, 30)

    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    @pytest.mark.parametrize("expected", [10, 11, 12])
    def test_scan_severity_exit_wins(self, field, expected):
        """Catches the gap check running before the severity thresholds (scan)."""
        summary = _summary(GAP_FIELDS[field], total=1, **SEVERITY_EXITS[expected])
        assert _exit_of(
            lambda: scan_threshold(
                {"vulnerabilities": summary}, "medium", fail_on_coverage_gaps=True
            )
        ) == ("VulnerabilityThresholdExceeded", expected)

    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    @pytest.mark.parametrize("expected", list(SEVERITY_EXITS))
    def test_upload_severity_exit_wins(self, field, expected):
        """Catches the gap check running before the severity thresholds (upload)."""
        summary = _summary(GAP_FIELDS[field], total=1, **SEVERITY_EXITS[expected])
        assert _exit_of(
            lambda: check_vulnerability_threshold(summary, "low", fail_on_coverage_gaps=True)
        ) == ("VulnerabilityThresholdExceeded", expected)

    @pytest.mark.parametrize("field", list(GAP_FIELDS))
    def test_gap_check_runs_when_every_existing_check_passes(self, field):
        """Catches the moved check never being reached on a passing run, on the
        status floor/policy branch and on each command."""
        summary = _summary(GAP_FIELDS[field])
        calls = [
            lambda: check_fail_on("high", summary, "ready", fail_on_coverage_gaps=True),
            lambda: check_fail_on(
                "high",
                summary,
                "ready",
                cra_floor_status="ready",
                release_policy_status="ready",
                fail_on_coverage_gaps=True,
            ),
            lambda: scan_threshold(
                {"vulnerabilities": summary}, "high", fail_on_coverage_gaps=True
            ),
            lambda: check_vulnerability_threshold(summary, "high", fail_on_coverage_gaps=True),
        ]
        for call in calls:
            assert _exit_of(call) == ("CoverageGapsFound", 30)

    def test_status_cli_severity_exit_wins(self):
        """Catches the command path (not only the helper) returning 30 over 10."""
        result = _status_cli(
            _status(_summary(GAPS, critical=1, total=1)),
            ["--fail-on", "high", "--fail-on-coverage-gaps"],
        )
        assert result.exit_code == 10, result.output

    def test_status_cli_floor_exit_wins(self):
        """Catches the command path returning 30 over a failing CRA floor (20)."""
        result = _status_cli(
            _status(
                _summary(GAPS),
                cra_status="incomplete",
                cra_floor_status="incomplete",
                release_policy_status="ready",
            ),
            ["--fail-on", "high", "--fail-on-coverage-gaps"],
        )
        assert result.exit_code == 20, result.output


class TestWaitReady:
    def _invoke(self, data):
        with patch.object(status_module, "CRAEvidenceClient") as client_class:
            client_class.return_value.get_version_status = AsyncMock(return_value=data)
            return CliRunner().invoke(
                cli, ["wait-ready", "--product", "p", "--version", "1.0"], env=BASE_ENV
            )

    def test_ready_with_gaps_reports_them_and_exits_zero(self):
        """Catches wait-ready hiding gaps at READY, or blocking readiness on them."""
        result = self._invoke(_status(_summary(GAPS)))
        assert result.exit_code == 0, result.output
        assert "CRA Status: READY" in result.output
        assert "Coverage gaps: 12 package(s) not checked" in result.output

    def test_ready_on_older_server_prints_no_gap_line(self):
        """Catches an absent field rendered as a gap state by wait-ready."""
        result = self._invoke(_status(_summary()))
        assert result.exit_code == 0, result.output
        assert "Coverage gaps" not in result.output


class TestScanGate:
    def _invoke(self, summary, args, output_format=None):
        responses = [
            {"scan_id": "s", "status": "pending"},
            {"scan_state": "completed", "vulnerability_summary": summary},
        ]
        with patch("cra_evidence_cli.commands.scan.CRAEvidenceClient") as client_class, patch(
            "cra_evidence_cli.commands.scan.asyncio.run", side_effect=responses
        ), patch("cra_evidence_cli.commands.scan.time.sleep"), patch(
            "cra_evidence_cli.commands.scan.time.monotonic", side_effect=count(0.0, 1.0)
        ):
            client_class.return_value = MagicMock()
            command = ["scan", "--product", "p", "--version", "1.0", *args]
            if output_format:
                command = ["--output", output_format, *command]
            return CliRunner().invoke(cli, command, env=BASE_ENV)

    def test_gap_only_exit_unchanged_without_flag(self):
        """Catches scan --fail-on newly failing on coverage gaps."""
        result = self._invoke(_summary(GAPS), ["--fail-on", "high"])
        assert result.exit_code == 0, result.output
        assert "Coverage gaps: 12 package(s) not checked" in result.output

    def test_gap_only_with_flag_exits_30(self):
        """Catches the scan gate ignoring --fail-on-coverage-gaps."""
        result = self._invoke(_summary(GAPS), ["--fail-on", "high", "--fail-on-coverage-gaps"])
        assert result.exit_code == 30, result.output

    def test_flag_with_empty_summary_fails_closed(self):
        """Catches the empty-summary early return skipping the opt-in gate."""
        result = self._invoke({}, ["--fail-on", "high", "--fail-on-coverage-gaps"])
        assert result.exit_code == 30, result.output
        assert "did not report coverage gaps" in _flat(result.output)

    def test_empty_summary_without_flag_passes(self):
        """Catches the restructured early return changing the default result."""
        result = self._invoke({}, ["--fail-on", "high"])
        assert result.exit_code == 0, result.output

    def test_json_mode_keeps_gap_lines_off_stdout(self):
        """Catches gap lines corrupting the JSON document on stdout."""
        result = self._invoke(_summary(GAPS), ["--fail-on", "high"], output_format="json")
        assert result.exit_code == 0, result.output
        assert "Coverage gaps" not in result.stdout
        assert "Coverage gaps: 12 package(s) not checked" in result.stderr
        json.loads(result.stdout)

    def test_flag_requires_fail_on(self):
        """Catches a silent no-op flag on scan."""
        result = CliRunner().invoke(
            cli,
            ["scan", "--product", "p", "--version", "1.0", "--fail-on-coverage-gaps"],
            env=BASE_ENV,
        )
        assert result.exit_code == 2
        assert "--fail-on-coverage-gaps requires --fail-on" in result.output


class TestUploadGate:
    def test_gap_only_exit_unchanged_without_flag(self):
        """Catches upload --fail-on newly failing on coverage gaps."""
        check_vulnerability_threshold(_summary(GAPS), "high")

    def test_gap_only_with_flag_raises_exit_30(self):
        """Catches the upload gate ignoring --fail-on-coverage-gaps."""
        with pytest.raises(CoverageGapsFound) as exc_info:
            check_vulnerability_threshold(_summary(GAPS), "high", fail_on_coverage_gaps=True)
        assert exc_info.value.exit_code == 30

    def test_real_failure_keeps_assessment_incomplete(self):
        """Catches the gap check running before, and masking, a real scan failure."""
        with pytest.raises(AssessmentIncomplete):
            check_vulnerability_threshold(
                _summary(GAPS, scan_incomplete=True), "high", fail_on_coverage_gaps=True
            )

    def _invoke(self, summary, args):
        upload_response = {
            "artifact_id": "sbom-123",
            "artifact_type": "sbom",
            "product": {"name": "test", "created": False},
            "version": {"number": "1.0", "created": False},
            "scan_results": {"status": "pending", "vulnerabilities": None},
        }
        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as client_class, patch(
            "cra_evidence_cli.commands.upload.asyncio.run",
            side_effect=[
                upload_response,
                {"scan_state": "completed", "vulnerability_summary": summary},
            ],
        ), patch("cra_evidence_cli.commands.scan.time.sleep"), patch(
            "cra_evidence_cli.commands.scan.time.monotonic", side_effect=count(0.0, 1.0)
        ):
            client_class.return_value = MagicMock()
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                return runner.invoke(
                    cli,
                    [
                        "upload-sbom", "--product", "test", "--version", "1.0",
                        "--file", "sbom.json", "--no-ci-detect", *args,
                    ],
                    env=BASE_ENV,
                )

    def test_cli_flag_exits_30_and_reports_gaps(self):
        """Catches the upload command not passing the flag to its gate."""
        result = self._invoke(
            _summary(GAPS), ["--scan", "--fail-on", "high", "--fail-on-coverage-gaps"]
        )
        assert result.exit_code == 30, result.output
        assert "Coverage gaps: 12 package(s) not checked" in result.output

    def test_cli_without_flag_exits_zero(self):
        """Catches upload-sbom --scan --fail-on newly failing on gaps."""
        result = self._invoke(_summary(GAPS), ["--scan", "--fail-on", "high"])
        assert result.exit_code == 0, result.output

    def test_flag_requires_fail_on(self):
        """Catches a silent no-op flag on upload-sbom."""
        runner = CliRunner()
        with patch("cra_evidence_cli.commands.upload.CRAEvidenceClient") as client_class:
            with runner.isolated_filesystem():
                Path("sbom.json").write_text('{"components": []}')
                result = runner.invoke(
                    cli,
                    [
                        "upload-sbom", "--product", "test", "--version", "1.0",
                        "--file", "sbom.json", "--scan", "--fail-on-coverage-gaps",
                    ],
                    env=BASE_ENV,
                )
        assert result.exit_code == 2
        assert "--fail-on-coverage-gaps requires --fail-on" in result.output
        client_class.assert_not_called()

    def test_release_coverage_gaps_are_shown(self, monkeypatch):
        """Catches the gaps recorded with an upload release being dropped from text."""
        out = _capture(monkeypatch, upload_module)
        upload_module.format_output(
            {"artifact_id": "a", "release_coverage_gaps": GAPS}, "text"
        )
        rendered = out.getvalue()
        assert "Recorded with the release:" in rendered
        assert "Coverage gaps: 12 package(s) not checked" in rendered

    def test_null_release_coverage_gaps_show_nothing(self, monkeypatch):
        """Catches a null field rendered as a gap state."""
        out = _capture(monkeypatch, upload_module)
        upload_module.format_output({"artifact_id": "a", "release_coverage_gaps": None}, "text")
        assert "Coverage gaps" not in out.getvalue()
        assert "Recorded with the release" not in out.getvalue()


def _release_cli(args, response=None):
    response = response or {
        "product": "p",
        "version": "1.0",
        "previous_state": "approved",
        "new_state": "released",
    }
    with patch.object(release_module, "CRAEvidenceClient") as client_class:
        client = client_class.return_value
        client.set_release_state = AsyncMock(return_value=response)
        result = CliRunner().invoke(
            cli,
            ["release", "--product", "p", "--version", "1.0", "--state", "released", *args],
            env=BASE_ENV,
        )
    return result, client.set_release_state


class TestReleaseAnyway:
    @pytest.mark.parametrize(
        "reason",
        ["123456789", "  123456789  ", "x" * 2001, "   "],
        ids=["9-chars", "9-chars-after-trim", "2001-chars", "blank"],
    )
    def test_reason_outside_bounds_is_usage_error(self, reason):
        """Catches an off-by-one bound, or counting untrimmed spaces as reason text."""
        result, call = _release_cli(["--release-anyway", "--reason", reason])
        assert result.exit_code == 2
        assert "10 to 2000 characters" in _flat(result.output)
        call.assert_not_called()

    @pytest.mark.parametrize(
        "reason",
        ["1234567890", " 1234567890 ", "y" * 2000],
        ids=["10-chars", "10-chars-padded", "2000-chars"],
    )
    def test_reason_within_bounds_is_sent(self, reason):
        """Catches a valid reason being rejected or not sent."""
        result, call = _release_cli(["--release-anyway", "--reason", reason])
        assert result.exit_code == 0, result.output
        assert call.call_args.kwargs["release_anyway_reason"] == reason

    def test_release_anyway_without_reason_is_usage_error(self):
        """Catches a release-anyway request sent without a reason."""
        result, call = _release_cli(["--release-anyway"])
        assert result.exit_code == 2
        call.assert_not_called()

    def test_reason_without_release_anyway_is_usage_error(self):
        """Catches a reason silently ignored without --release-anyway."""
        result, call = _release_cli(["--reason", "a long enough reason"])
        assert result.exit_code == 2
        assert "--reason is only valid with --release-anyway" in result.output
        call.assert_not_called()

    def test_release_anyway_needs_released_state(self):
        """Catches release anyway sent with a state that is not a release."""
        with patch.object(release_module, "CRAEvidenceClient") as client_class:
            result = CliRunner().invoke(
                cli,
                [
                    "release", "--product", "p", "--version", "1.0", "--state", "approved",
                    "--release-anyway", "--reason", "a long enough reason",
                ],
                env=BASE_ENV,
            )
        assert result.exit_code == 2
        assert "only valid with --state released" in result.output
        client_class.assert_not_called()

    def test_default_release_sends_no_override(self):
        """Catches a default release sending a release-anyway request."""
        result, call = _release_cli([])
        assert result.exit_code == 0, result.output
        assert call.call_args.kwargs["release_anyway_reason"] is None

    def test_recorded_override_is_reported(self):
        """Catches the release_anyway_recorded confirmation not being shown."""
        response = {
            "new_state": "released",
            "release_anyway_recorded": True,
            "coverage_gaps": GAPS,
        }
        result, _ = _release_cli(
            ["--release-anyway", "--reason", "scanner outage, approved by QA"], response
        )
        assert result.exit_code == 0, result.output
        assert "Released anyway: your reason and the scan problems were recorded" in _flat(
            result.output
        )
        assert "Recorded with the release:" in result.output
        assert "Coverage gaps: 12 package(s) not checked" in result.output

    def test_not_needed_override_is_reported(self):
        """Catches a False confirmation being shown as a recorded override."""
        result, _ = _release_cli(
            ["--release-anyway", "--reason", "scanner outage, approved by QA"],
            {"new_state": "released", "release_anyway_recorded": False},
        )
        assert result.exit_code == 0, result.output
        assert "No scan problem blocked this release" in result.output
        assert "Released anyway:" not in result.output

    def test_older_server_without_confirmation_is_flagged(self):
        """Catches an absent confirmation being read as a recorded override."""
        result, _ = _release_cli(
            ["--release-anyway", "--reason", "scanner outage, approved by QA"],
            {"new_state": "released"},
        )
        assert result.exit_code == 0, result.output
        assert "did not confirm that the release-anyway reason was recorded" in _flat(
            result.output
        )

    def test_default_release_output_unchanged_on_older_server(self):
        """Catches new lines appearing for an older server and a default release."""
        result, _ = _release_cli([])
        assert result.exit_code == 0, result.output
        assert "release-anyway" not in result.output
        assert "Released anyway" not in result.output
        assert "Coverage gaps" not in result.output


class TestReleaseStateClientForm:
    def _client(self, monkeypatch, captured):
        from httpx import Response

        from cra_evidence_cli.client import CRAEvidenceClient
        from cra_evidence_cli.config import CRAEvidenceConfig

        class _AsyncClient:
            def __init__(self, *_, **__):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                return None

            async def post(self, url, **kwargs):
                captured["url"] = url
                captured.update(kwargs)
                return Response(200, json={"new_state": "released"})

        monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", _AsyncClient)
        return CRAEvidenceClient(CRAEvidenceConfig(api_key="cra_test", url="http://localhost"))

    @pytest.mark.asyncio
    async def test_override_is_sent_as_form_fields(self, monkeypatch):
        """Catches the override sent as JSON or under other field names."""
        captured: dict = {}
        client = self._client(monkeypatch, captured)
        await client.set_release_state(
            product="p", version="1.0", state="released",
            release_anyway_reason="scanner outage, approved by QA",
        )
        assert captured["url"] == "http://localhost/api/v1/ci/release-state"
        assert "json" not in captured
        assert captured["data"]["release_anyway"] == "true"
        assert captured["data"]["release_anyway_reason"] == "scanner outage, approved by QA"

    @pytest.mark.asyncio
    async def test_default_request_is_unchanged(self, monkeypatch):
        """Catches a default release request gaining release-anyway fields."""
        captured: dict = {}
        client = self._client(monkeypatch, captured)
        await client.set_release_state(product="p", version="1.0", state="released")
        assert captured["data"] == {"product": "p", "version": "1.0", "state": "released"}
