"""
Tests for read-only evidence discovery output formatting.
"""

from io import StringIO

from rich.console import Console

from cra_evidence_cli.commands import evidence as evidence_module
from cra_evidence_cli.commands.evidence import (
    format_documents_output,
    format_hboms_output,
    format_inventory_output,
    format_static_analysis_output,
    format_vex_output,
)


def _capture_console(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        evidence_module,
        "console",
        Console(file=output, force_terminal=False, width=160),
    )
    return output


def test_format_hboms_json(monkeypatch):
    output = _capture_console(monkeypatch)

    format_hboms_output(
        [
            {
                "id": "hbom-1",
                "filename": "board.hbom.json",
                "format": "cyclonedx_json",
                "component_count": 4,
                "quality_score": 90,
                "created_at": "2026-05-20T10:00:00Z",
            }
        ],
        "json",
    )

    assert '"filename": "board.hbom.json"' in output.getvalue()
    assert '"component_count": 4' in output.getvalue()


def test_format_vex_text_empty(monkeypatch):
    output = _capture_console(monkeypatch)

    format_vex_output([], "text")

    assert "No VEX documents found" in output.getvalue()


def test_format_static_analysis_text_with_summary_and_findings(monkeypatch):
    output = _capture_console(monkeypatch)

    format_static_analysis_output(
        {
            "summary": {
                "total_results": 1,
                "critical_count": 0,
                "error_count": 1,
                "warning_count": 0,
                "note_count": 0,
                "none_count": 0,
                "suppressed_count": 0,
                "unsuppressed_count": 1,
                "files_affected": 1,
                "unique_rules": 1,
            },
            "findings": [
                {
                    "severity": "error",
                    "tool_name": "CodeQL",
                    "rule_id": "py/sql-injection",
                    "file_path": "app.py",
                    "start_line": 42,
                    "suppressed": False,
                    "message": "Unsafe query",
                }
            ],
        },
        "text",
    )

    rendered = output.getvalue()
    assert "Static Analysis Summary" in rendered
    assert "py/sql-injection" in rendered
    assert "app.py:42" in rendered


def test_format_documents_json_only_inventory_metadata(monkeypatch):
    output = _capture_console(monkeypatch)

    format_documents_output(
        {
            "documents": {"risk_assessment": True},
            "document_artifacts": [
                {
                    "id": "doc-1",
                    "doc_type": "risk_assessment",
                    "filename": "risk.pdf",
                    "review_status": "approved",
                }
            ],
            "artifact_inventory": None,
        },
        "json",
    )

    rendered = output.getvalue()
    assert '"risk_assessment": true' in rendered
    assert '"filename": "risk.pdf"' in rendered


def test_document_artifact_metadata_strips_download_url():
    status = {
        "document_artifacts": [
            {
                "id": "doc-1",
                "doc_type": "risk_assessment",
                "filename": "risk.pdf",
                "review_status": "approved",
                "gemara_source_download_url": "/api/v1/documents/doc-1/gemara-source/download",
            }
        ]
    }

    metadata = evidence_module._document_artifact_metadata(status)

    assert metadata == [
        {
            "id": "doc-1",
            "doc_type": "risk_assessment",
            "filename": "risk.pdf",
            "review_status": "approved",
        }
    ]


def test_format_inventory_text_shows_missing_scope(monkeypatch):
    output = _capture_console(monkeypatch)

    format_inventory_output(
        {
            "artifact_inventory": {
                "hbom": {
                    "included": False,
                    "required_scope": "hardware:read",
                }
            },
            "documents": {},
        },
        "text",
    )

    rendered = output.getvalue()
    assert "HBOM" in rendered
    assert "requires hardware:read" in rendered
