"""
Unit tests for the sbomqs_check helper.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cra_evidence_cli.exceptions import CRAEvidenceError
from cra_evidence_cli.sbomqs_check import (
    SBOMQS_TIMEOUT_SECONDS,
    discover_sbomqs,
    format_summary,
    run_sbomqs,
)


def _payload(avg_score: float, scores: list[dict] | None = None) -> str:
    return json.dumps(
        {
            "files": [
                {
                    "file_name": "/tmp/sbom.cdx.json",  # noqa: S108
                    "num_components": 107,
                    "avg_score": avg_score,
                    "scores": scores
                    if scores is not None
                    else [
                        {
                            "feature": "comp_with_supplier",
                            "score": 0,
                            "max_score": 10,
                            "ignored": False,
                        },
                        {
                            "feature": "comp_with_name",
                            "score": 10,
                            "max_score": 10,
                            "ignored": False,
                        },
                    ],
                }
            ]
        }
    )


class TestDiscoverSbomqs:
    def test_returns_path_when_present(self):
        with patch("cra_evidence_cli.sbomqs_check.shutil.which") as which:
            which.return_value = "/usr/local/bin/sbomqs"
            assert discover_sbomqs() == "/usr/local/bin/sbomqs"

    def test_raises_with_install_hint_when_missing(self):
        with patch("cra_evidence_cli.sbomqs_check.shutil.which") as which:
            which.return_value = None
            with pytest.raises(CRAEvidenceError) as exc:
                discover_sbomqs()
            assert "sbomqs binary not found" in str(exc.value)
            assert "go install github.com/interlynk-io/sbomqs" in str(exc.value)
            assert exc.value.exit_code == 2


class TestRunSbomqs:
    def _run(self, *, returncode=0, stdout="", stderr="", which="/usr/bin/sbomqs"):
        with patch("cra_evidence_cli.sbomqs_check.shutil.which") as mock_which, patch(
            "cra_evidence_cli.sbomqs_check.subprocess.run"
        ) as mock_run:
            mock_which.return_value = which
            mock_run.return_value = MagicMock(
                returncode=returncode, stdout=stdout, stderr=stderr
            )
            return run_sbomqs(Path("/tmp/sbom.cdx.json")), mock_run  # noqa: S108

    def test_parses_score_and_components(self):
        result, mock_run = self._run(stdout=_payload(4.79))
        assert result.num_components == 107
        assert result.score_out_of_100 == pytest.approx(47.9, abs=0.01)
        assert result.file_name == "/tmp/sbom.cdx.json"  # noqa: S108
        # Subprocess invoked with bsi-v2.0 standard and JSON output
        args = mock_run.call_args.args[0]
        assert "score" in args
        assert "-c" in args
        assert "bsi-v2.0" in args
        assert "--json" in args

    def test_worst_features_sorted_lowest_first(self):
        scores = [
            {"feature": "comp_with_name", "score": 10, "max_score": 10, "ignored": False},
            {"feature": "comp_with_supplier", "score": 0, "max_score": 10, "ignored": False},
            {"feature": "comp_with_version", "score": 8, "max_score": 10, "ignored": False},
            {"feature": "sbom_with_signature", "score": 0, "max_score": 10, "ignored": False},
            {"feature": "comp_with_executable_uri", "score": 0, "max_score": 10, "ignored": False},
            # Ignored features must be excluded
            {"feature": "comp_with_source_code_hash", "score": 0, "max_score": 10, "ignored": True},
        ]
        result, _ = self._run(stdout=_payload(4.0, scores))
        worst = [f.feature for f in result.worst_features]
        assert len(worst) == 3
        assert "comp_with_source_code_hash" not in worst
        # All three worst are 0/10 - order is stable but undefined among ties
        for w in worst:
            assert w in {
                "comp_with_supplier",
                "sbom_with_signature",
                "comp_with_executable_uri",
            }

    def test_nonzero_exit_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(returncode=1, stderr="bad sbom")
        assert "sbomqs exited 1" in str(exc.value)
        assert "bad sbom" in str(exc.value)

    def test_non_json_output_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout="not json")
        assert "non-JSON" in str(exc.value)

    def test_missing_files_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout=json.dumps({"files": []}))
        assert "no scored files" in str(exc.value)

    def test_missing_avg_score_raises(self):
        payload = json.dumps({"files": [{"num_components": 1, "scores": []}]})
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout=payload)
        assert "avg_score" in str(exc.value)

    def test_timeout_raises(self):
        with patch("cra_evidence_cli.sbomqs_check.shutil.which") as mock_which, patch(
            "cra_evidence_cli.sbomqs_check.subprocess.run"
        ) as mock_run:
            mock_which.return_value = "/usr/bin/sbomqs"
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd="sbomqs", timeout=SBOMQS_TIMEOUT_SECONDS
            )
            with pytest.raises(CRAEvidenceError) as exc:
                run_sbomqs(Path("/tmp/sbom.cdx.json"))  # noqa: S108
            assert "timed out" in str(exc.value)


class TestFormatSummary:
    def test_summary_has_score_and_components(self):
        result, _ = TestRunSbomqs()._run(stdout=_payload(4.79))
        text = format_summary(result)
        assert "sbomqs bsi-v2.0: 47.9/100" in text
        assert "107 components" in text

    def test_summary_includes_worst(self):
        result, _ = TestRunSbomqs()._run(stdout=_payload(4.79))
        text = format_summary(result)
        assert "worst:" in text
        assert "0/10" in text
