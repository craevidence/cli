"""Shared review markers for generated local outputs."""

from __future__ import annotations

from typing import Any

DISCLAIMER_TEXT = "Review before use."

# Watermark for generated drafts/scaffolds the user is expected to complete.
DRAFT_WATERMARK = "draft / review before use"

DISCLAIMER_MARKER = "review before use"


def advisory_block() -> dict[str, Any]:
    """Machine-readable review note for json/sarif output."""
    return {"disclaimer": DISCLAIMER_TEXT}


def assert_disclaimer_present(rendered: str) -> None:
    """Guard that a generated artifact carries a review marker."""
    if DISCLAIMER_MARKER not in rendered.lower():
        message = "review marker missing from rendered output"
        raise AssertionError(message)
