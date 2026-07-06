"""Tests for compare command output formatting: JSON, text with changes, and edge cases."""

import json
from io import StringIO

import pytest
from rich.console import Console

from cra_evidence_cli.commands import compare as compare_module
from cra_evidence_cli.commands.compare import format_compare_output


@pytest.fixture
def compare_response():
    """A comparison response with changes."""
    return {
        "product": {"id": "prod-123", "name": "My Product", "slug": "my-product"},
        "version_a": {
            "number": "1.0.0",
            "cra_status": "incomplete",
            "release_state": "released",
        },
        "version_b": {
            "number": "2.0.0",
            "cra_status": "ready",
            "release_state": "released",
        },
        "summary": {
            "added": 15,
            "removed": 3,
            "modified": 8,
            "unchanged": 120,
        },
        "changes": {
            "added": [
                {"name": "lodash", "version": "4.17.21"},
                {"name": "express", "version": "4.18.0"},
            ],
            "removed": [
                {"name": "moment", "version": "2.29.0"},
            ],
            "modified": [
                {
                    "name": "react",
                    "old_version": "17.0.2",
                    "new_version": "18.2.0",
                },
            ],
        },
        "vulnerability_diff": {
            "new": 2,
            "fixed": 5,
        },
    }


@pytest.fixture
def compare_response_empty():
    """A comparison response with no changes."""
    return {
        "product": {"id": "prod-123", "name": "My Product", "slug": "my-product"},
        "version_a": {
            "number": "1.0.0",
            "cra_status": "ready",
            "release_state": "released",
        },
        "version_b": {
            "number": "1.0.1",
            "cra_status": "ready",
            "release_state": "released",
        },
        "summary": {
            "added": 0,
            "removed": 0,
            "modified": 0,
            "unchanged": 100,
        },
        "changes": {
            "added": [],
            "removed": [],
            "modified": [],
        },
        "vulnerability_diff": None,
    }


class TestCompareOutput:
    """Tests for compare output formatting."""

    def test_json_output(self, compare_response, monkeypatch):
        """JSON format serialises the full response payload."""
        out = StringIO()
        monkeypatch.setattr(
            compare_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_compare_output(compare_response, "json")
        rendered = out.getvalue()
        parsed = json.loads(rendered)
        assert parsed["version_a"]["number"] == "1.0.0"
        assert parsed["version_b"]["number"] == "2.0.0"
        assert parsed["summary"]["added"] == 15

    def test_text_output_with_changes(self, compare_response, monkeypatch):
        """Text format renders version numbers and added/removed/modified sections."""
        out = StringIO()
        monkeypatch.setattr(
            compare_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_compare_output(compare_response, "text")
        rendered = out.getvalue()
        assert "1.0.0" in rendered
        assert "2.0.0" in rendered
        assert "lodash" in rendered
        assert "moment" in rendered
        assert "react" in rendered

    def test_text_output_no_changes(self, compare_response_empty, monkeypatch):
        """Text format renders zero-change summary with both version numbers."""
        out = StringIO()
        monkeypatch.setattr(
            compare_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_compare_output(compare_response_empty, "text")
        rendered = out.getvalue()
        assert "1.0.0" in rendered
        assert "1.0.1" in rendered
        assert "100" in rendered

    def test_text_output_minimal(self, monkeypatch):
        """Empty dict renders a Version Comparison heading without raising."""
        out = StringIO()
        monkeypatch.setattr(
            compare_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        format_compare_output({}, "text")
        rendered = out.getvalue()
        assert "Version Comparison" in rendered

    def test_text_output_many_changes(self, monkeypatch):
        """Text output truncates lists longer than 10 and shows a 'more' hint."""
        out = StringIO()
        monkeypatch.setattr(
            compare_module,
            "console",
            Console(file=out, force_terminal=False, width=160, color_system=None),
        )
        data = {
            "version_a": {"number": "1.0"},
            "version_b": {"number": "2.0"},
            "summary": {"added": 25, "removed": 0, "modified": 0, "unchanged": 100},
            "changes": {
                "added": [
                    {"name": f"pkg-{i}", "version": f"{i}.0.0"} for i in range(25)
                ],
            },
        }
        format_compare_output(data, "text")
        rendered = out.getvalue()
        assert "pkg-0" in rendered
        assert "15 more" in rendered
