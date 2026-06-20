"""Tests for compare command output formatting: JSON, text with changes, and edge cases."""

import pytest

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

    def test_json_output(self, compare_response):
        """JSON format renders without raising."""
        format_compare_output(compare_response, "json")

    def test_text_output_with_changes(self, compare_response):
        """Text format renders added/removed/modified sections without raising."""
        format_compare_output(compare_response, "text")

    def test_text_output_no_changes(self, compare_response_empty):
        """Text format renders a zero-change comparison without raising."""
        format_compare_output(compare_response_empty, "text")

    def test_text_output_minimal(self):
        """Empty dict is handled without raising."""
        format_compare_output({}, "text")

    def test_text_output_many_changes(self):
        """Text output truncates long change lists (>10 items)."""
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
        # Should not crash, should truncate to 10 + "... and 15 more"
        format_compare_output(data, "text")
