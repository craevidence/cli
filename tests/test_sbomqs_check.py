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


def _payload(total_score: float, sections: list[dict] | None = None) -> str:
    return json.dumps(
        {
            "report_name": "BSI TR-03183-2 v2.0.0 Compliance Report",
            "run": {"file_name": "/tmp/sbom.cdx.json"},  # noqa: S108
            "summary": {
                "total_score": total_score,
                "max_score": 10,
                "required_elements_score": total_score,
                "additional_elements_score": 10,
                "optional_elements_score": 0,
            },
            "sections": sections
            if sections is not None
            else [
                {
                    "section_title": "Required SBOM fields",
                    "element_id": "SBOM",
                    "required": True,
                    "score": 5,
                },
                {
                    "section_title": "Required component fields",
                    "element_id": "pkg-a-1.0.0",
                    "required": True,
                    "score": 0,
                },
                {
                    "section_title": "Required component fields",
                    "element_id": "pkg-b-2.0.0",
                    "required": True,
                    "score": 0,
                },
                {
                    "section_title": "Optional component fields",
                    "element_id": "pkg-a-1.0.0",
                    "required": False,
                    "score": 10,
                },
            ],
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
            assert "go install github.com/interlynk-io/sbomqs/v2@v2.0.11" in str(exc.value)
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
        # Two distinct component element ids; the document-level "SBOM" row
        # and the repeated pkg-a row must not inflate the count.
        assert result.num_components == 2
        assert result.score_out_of_100 == pytest.approx(47.9, abs=0.01)
        assert result.file_name == "/tmp/sbom.cdx.json"  # noqa: S108
        # Subprocess invoked with the BSI TR-03183-2 v2 compliance report
        # and JSON output
        args = mock_run.call_args.args[0]
        assert "compliance" in args
        assert "--bsi-v2" in args
        assert "--json" in args
        assert "score" not in args

    def test_worst_features_aggregate_sections_lowest_first(self):
        def section(title: str, element_id: str, score: int, required: bool = True) -> dict:
            return {
                "section_title": title,
                "element_id": element_id,
                "required": required,
                "score": score,
            }

        sections = [
            section("SBOM formats", "SBOM", 10),
            section("Level of Detail", "SBOM", 0),
            section("Required SBOM fields", "SBOM", 5),
            section("Required component fields", "pkg-a-1.0.0", 0),
            section("Required component fields", "pkg-b-2.0.0", 4),
            section("Additional SBOM fields", "SBOM", 10, required=False),
        ]
        result, _ = self._run(stdout=_payload(4.0, sections))
        worst = [(f.feature, f.score) for f in result.worst_features]
        assert len(worst) == 3
        # Lowest average ratio first: Level of Detail 0/10, then the
        # component-field average 2/10, then Required SBOM fields 5/10.
        assert worst[0] == ("Level of Detail", 0.0)
        assert worst[1] == ("Required component fields", 2.0)
        assert worst[2] == ("Required SBOM fields", 5.0)
        for f in result.worst_features:
            assert f.max_score == 10.0

    @pytest.mark.parametrize(
        "section_titles",
        [
            [
                "Additional components fields",
                "Additional sboms fields",
                "Definition of SBOM",
                "Level of Detail",
                "Optional components fields",
                "Optional sboms fields",
                "Required component fields",
                "Required components fields",
                "Required sboms fields",
                "SBOM formats",
            ],
            [
                "Additional component fields",
                "Additional SBOM fields",
                "Definition of SBOM",
                "Level of Detail",
                "Optional component fields",
                "Optional SBOM fields",
                "Required component fields",
                "Required SBOM fields",
                "SBOM formats",
            ],
        ],
        ids=["v1.3.0", "v2.0.11"],
    )
    def test_parses_validated_section_title_variants(self, section_titles):
        sections = [
            {
                "section_title": title,
                "element_id": "pkg-a-1.0.0",
                "score": index,
            }
            for index, title in enumerate(section_titles)
        ]
        result, _ = self._run(stdout=_payload(4.0, sections))
        assert result.num_components == 1
        assert {feature.feature for feature in result.worst_features}.issubset(
            set(section_titles)
        )

    def test_nonzero_exit_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(returncode=1, stderr="bad sbom")
        assert "sbomqs exited 1" in str(exc.value)
        assert "bad sbom" in str(exc.value)

    def test_non_json_output_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout="not json")
        assert "non-JSON" in str(exc.value)

    def test_missing_summary_raises(self):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout=json.dumps({"sections": []}))
        assert "missing object 'summary'" in str(exc.value)

    def test_non_numeric_total_score_raises(self):
        payload = json.dumps(
            {
                "summary": {"total_score": "high", "max_score": 10},
                "sections": [
                    {"section_title": "SBOM formats", "element_id": "SBOM", "score": 10}
                ],
            }
        )
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout=payload)
        assert "summary.total_score" in str(exc.value)

    @pytest.mark.parametrize(
        ("summary", "message"),
        [
            ({"total_score": 5}, "summary.max_score"),
            ({"total_score": 5, "max_score": 0}, "greater than zero"),
            ({"total_score": 11, "max_score": 10}, "outside the report score range"),
            ({"total_score": True, "max_score": 10}, "summary.total_score"),
        ],
    )
    def test_invalid_summary_score_shape_raises(self, summary, message):
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(
                stdout=json.dumps(
                    {
                        "summary": summary,
                        "sections": [
                            {
                                "section_title": "SBOM formats",
                                "element_id": "SBOM",
                                "score": 10,
                            }
                        ],
                    }
                )
            )
        assert message in str(exc.value)

    @pytest.mark.parametrize(
        ("sections", "message"),
        [
            (None, "missing array 'sections'"),
            ([], "must not be empty"),
            (["not-an-object"], "sections[0]' must be an object"),
            ([{"section_title": "", "element_id": "SBOM", "score": 0}], "section_title"),
            (
                [{"section_title": "SBOM formats", "element_id": "SBOM"}],
                "sections[0].score",
            ),
            (
                [{"section_title": "SBOM formats", "element_id": "SBOM", "score": 11}],
                "outside the report score range",
            ),
            (
                [{"section_title": "SBOM formats", "element_id": 7, "score": 10}],
                "element_id' must be text",
            ),
        ],
    )
    def test_invalid_section_shape_raises(self, sections, message):
        payload = json.dumps(
            {"summary": {"total_score": 8.0, "max_score": 10}, "sections": sections}
        )
        with pytest.raises(CRAEvidenceError) as exc:
            self._run(stdout=payload)
        assert message in str(exc.value)

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
        assert "2 components" in text

    def test_summary_includes_worst(self):
        result, _ = TestRunSbomqs()._run(stdout=_payload(4.79))
        text = format_summary(result)
        assert "worst:" in text
        assert "0/10" in text
