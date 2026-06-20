"""Tests for shared review notes in local machine output."""

from __future__ import annotations

import json

import pytest

from cra_evidence_cli.local.disclaimer import (
    DISCLAIMER_MARKER,
    advisory_block,
    assert_disclaimer_present,
)
from cra_evidence_cli.local.models import LocalCheckResult
from cra_evidence_cli.local.report import render


def test_advisory_block_shape() -> None:
    block = advisory_block()
    assert DISCLAIMER_MARKER in block["disclaimer"].lower()
    assert set(block) == {"disclaimer"}


def test_assert_disclaimer_present_passes_and_fails() -> None:
    assert_disclaimer_present(f"prefix {DISCLAIMER_MARKER} suffix")
    with pytest.raises(AssertionError):
        assert_disclaimer_present("no disclaimer here")


def _empty_result() -> LocalCheckResult:
    return LocalCheckResult(
        target="x",
        target_type="sbom",
        sbom_path=None,
        components=[],
        findings=[],
        dimensions=[],
        coverage=[],
        provenance={},
        attributions=[],
        sources_consulted=[],
    )


@pytest.mark.parametrize("fmt", ["text", "markdown"])
def test_check_human_formats_do_not_print_review_marker(fmt: str) -> None:
    rendered = render(_empty_result(), fmt)
    assert DISCLAIMER_MARKER not in rendered.lower()


def test_check_json_and_sarif_carry_advisory_field() -> None:
    data = json.loads(render(_empty_result(), "json"))
    assert DISCLAIMER_MARKER in data["advisory"]["disclaimer"].lower()

    sarif = json.loads(render(_empty_result(), "sarif"))
    props = sarif["runs"][0]["tool"]["driver"]["properties"]
    assert DISCLAIMER_MARKER in props["advisory"]["disclaimer"].lower()
