"""
Tests for `craevidence ra review` and `craevidence ra finalize`.

Command-level tests follow the CliRunner + patched CRAEvidenceClient/asyncio.run
pattern used by test_ra_command.py. Client-level tests follow test_client.py's
FakeAsyncClient pattern (a stub replacing httpx.AsyncClient that captures the
posted JSON body).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from httpx import Response

from cra_evidence_cli.cli import cli
from cra_evidence_cli.client import CRAEvidenceClient
from cra_evidence_cli.exceptions import APIError, AuthenticationError
from tests.test_plain_language_guard import _line_violations

REPO_ROOT = Path(__file__).resolve().parent.parent

BASE_ENV = {
    "CRA_EVIDENCE_API_KEY": "test_key_123",
    "CRA_EVIDENCE_URL": "http://localhost:8000",
}


# Fixture payloads (server response shapes: CIReviewCycleOpenResponse /
# CIReviewDispositionResponse / CIReviewFinalizeResponse)

# --non-interactive reads via GET .../delta only (never the open-cycle POST),
# so these fixtures use the delta response shape (CIReviewCycleDeltaResponse:
# preview/id/digest/state/items/resolution), not the open-cycle POST shape.
NON_INTERACTIVE_UNRESOLVED = {
    "preview": False,
    "id": "cycle-2",
    "digest": "b" * 64,
    "state": "open",
    "items": [
        {
            "item_id": "release_question:architecture",
            "kind": "release_question",
            "title": "Did the architecture change in this release?",
            "detail": {"category": "architecture", "hint": "New or changed interfaces."},
            "severity": "attention",
        }
    ],
    "resolution": {
        "resolved_count": 0,
        "total": 1,
        "unresolved_item_ids": ["release_question:architecture"],
    },
}

NON_INTERACTIVE_RESOLVED = {
    "preview": False,
    "id": "cycle-3",
    "digest": "c" * 64,
    "state": "open",
    "items": [
        {
            "item_id": "release_question:architecture",
            "kind": "release_question",
            "title": "Did the architecture change in this release?",
            "detail": {"category": "architecture", "hint": "New or changed interfaces."},
            "severity": "attention",
        }
    ],
    "resolution": {"resolved_count": 1, "total": 1, "unresolved_item_ids": []},
}

# A preview delta (no cycle open yet) with unresolved items: every previewed
# item would need a decision if a cycle were opened now.
NON_INTERACTIVE_PREVIEW_UNRESOLVED = {
    "preview": True,
    "id": None,
    "digest": "p" * 64,
    "state": None,
    "items": [
        {
            "item_id": "component_added:pkg:pypi/foo@1.0.0",
            "kind": "component_added",
            "title": "Component added: foo",
            "detail": {"name": "foo"},
            "severity": "attention",
        }
    ],
    "resolution": None,
}

OPEN_CYCLE_SINGLE_ITEM = {
    "id": "cycle-4",
    "digest": "d" * 64,
    "state": "open",
    "items": [
        {
            "item_id": "component_added:pkg:pypi/foo@1.0.0",
            "kind": "component_added",
            "title": "Component added: foo",
            "detail": {
                "name": "foo",
                "purl": "pkg:pypi/foo@1.0.0",
                "version": "1.0.0",
                "supplier": None,
            },
            "severity": "attention",
        }
    ],
    "resolution": {
        "resolved_count": 0,
        "total": 1,
        "unresolved_item_ids": ["component_added:pkg:pypi/foo@1.0.0"],
    },
    "created": True,
}

DISPOSITION_RESPONSE = {
    "id": "disp-1",
    "cycle_id": "cycle-4",
    "item_id": "component_added:pkg:pypi/foo@1.0.0",
    "revision": 1,
    "disposition": "accepted",
    "justification": "reviewed, fine",
    "principal_kind": "api_key",
    "created_at": "2026-07-30T00:00:00Z",
    "resolution": {"resolved_count": 1, "total": 1, "unresolved_item_ids": []},
}

# A supersession opens a genuinely NEW cycle (new id, new digest); the same
# item can still be unresolved in it, which is what forces a real second POST
# so the test can prove that POST carries the refreshed id/digest, not the
# stale one from before the 409.
OPEN_CYCLE_SINGLE_ITEM_REFRESHED = {
    "id": "cycle-6",
    "digest": "h" * 64,
    "state": "open",
    "items": [
        {
            "item_id": "component_added:pkg:pypi/foo@1.0.0",
            "kind": "component_added",
            "title": "Component added: foo",
            "detail": {"name": "foo"},
            "severity": "attention",
        }
    ],
    "resolution": {
        "resolved_count": 0,
        "total": 1,
        "unresolved_item_ids": ["component_added:pkg:pypi/foo@1.0.0"],
    },
    "created": True,
}

DISPOSITION_RESPONSE_AFTER_REFRESH = {
    "id": "disp-2",
    "cycle_id": "cycle-6",
    "item_id": "component_added:pkg:pypi/foo@1.0.0",
    "revision": 1,
    "disposition": "accepted",
    "justification": "reviewed, fine",
    "principal_kind": "api_key",
    "created_at": "2026-07-30T00:05:00Z",
    "resolution": {"resolved_count": 1, "total": 1, "unresolved_item_ids": []},
}

GET_DELTA_OPEN_CYCLE = {
    "preview": False,
    "id": "cycle-9",
    "digest": "f" * 64,
    "state": "open",
    "items": [],
    "resolution": {"resolved_count": 3, "total": 3, "unresolved_item_ids": []},
}

GET_DELTA_PREVIEW = {
    "preview": True,
    "id": None,
    "digest": "g" * 64,
    "state": None,
    "items": [],
    "resolution": None,
}

FINALIZE_RESULT = {
    "assessment_id": "assess-1",
    "assessment_status": "signed_off",
    "assessment_review_status": "reviewed",
    "cycle_id": "cycle-9",
    "cycle_state": "resolved",
}


def _fresh_side_effects(run_side_effects):
    """Deep-copy every non-exception side effect.

    The module-level fixture payloads below (OPEN_CYCLE_SINGLE_ITEM, etc.) are
    plain dict literals shared by reference across many test functions. The
    command under test treats a cycle dict as its own (it may rebind fields
    while walking a review), so handing out the same object to every test
    that asks for it would let one test's run leak state into the next.
    Exceptions are passed through as-is; deep-copying an exception instance
    buys nothing and Mock.side_effect only cares that it is an exception.
    """
    return [
        effect if isinstance(effect, BaseException) else copy.deepcopy(effect)
        for effect in run_side_effects
    ]


def _invoke_review(
    run_side_effects,
    args,
    *,
    input_text: str | None = None,
    interactive: bool = False,
    output_format: str | None = None,
):
    runner = CliRunner()
    root_args = ["--output", output_format] if output_format else []

    with (
        patch("cra_evidence_cli.commands.ra.CRAEvidenceClient") as mock_client_cls,
        patch("cra_evidence_cli.commands.ra.asyncio.run") as mock_run,
        patch("cra_evidence_cli.commands.ra.is_interactive", return_value=interactive),
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_run.side_effect = _fresh_side_effects(run_side_effects)
        result = runner.invoke(
            cli,
            [*root_args, "ra", "review", *args],
            env=BASE_ENV,
            input=input_text,
        )
    return result, mock_client


def _invoke_finalize(run_side_effects, args, output_format: str | None = None):
    runner = CliRunner()
    root_args = ["--output", output_format] if output_format else []

    with (
        patch("cra_evidence_cli.commands.ra.CRAEvidenceClient") as mock_client_cls,
        patch("cra_evidence_cli.commands.ra.asyncio.run") as mock_run,
    ):
        mock_client_cls.return_value = MagicMock()
        mock_run.side_effect = _fresh_side_effects(run_side_effects)
        result = runner.invoke(
            cli, [*root_args, "ra", "finalize", *args], env=BASE_ENV
        )
    return result




class TestRaReviewNonInteractive:
    def test_unresolved_exits_28(self):
        result, mock_client = _invoke_review(
            [NON_INTERACTIVE_UNRESOLVED],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 28, result.output
        mock_client.get_ra_delta.assert_called_once_with(
            product="my-product", version="1.2.3"
        )
        mock_client.record_ra_disposition.assert_not_called()
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_all_resolved_exits_0(self):
        result, mock_client = _invoke_review(
            [NON_INTERACTIVE_RESOLVED],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_not_called()
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_preview_unresolved_exits_28(self):
        """No cycle open yet (preview=true): every previewed item counts as
        needing a decision, and nothing is opened just to report that."""
        result, mock_client = _invoke_review(
            [NON_INTERACTIVE_PREVIEW_UNRESOLVED],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 28, result.output
        mock_client.record_ra_disposition.assert_not_called()
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_no_review_needed_exits_0(self):
        """A 404 for a missing risk assessment (details.resource_type ==
        "Risk assessment") from the delta GET means nothing is flagged for
        review right now; --non-interactive never opens a cycle to find
        that out."""
        result, mock_client = _invoke_review(
            [
                APIError(
                    "This version has no risk assessment; there is nothing "
                    "to review.",
                    status_code=404,
                    error_details={"resource_type": "Risk assessment"},
                )
            ],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 0, result.output
        assert "no changes to assess" in result.output
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_unknown_version_404_propagates(self):
        """A 404 for an unknown product/version (details.resource_type ==
        "Version") is a real error, not "nothing to review": it must fail
        loudly rather than being reported as exit 0."""
        result, mock_client = _invoke_review(
            [
                APIError(
                    "Version '1.2.3' not found for product 'my-product'.",
                    status_code=404,
                    error_details={"resource_type": "Version"},
                )
            ],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 3, result.output
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_empty_items_exits_0(self):
        """Defensive: a delta with no items at all is treated the same as no review needed."""
        empty_delta = {
            "preview": True,
            "id": None,
            "digest": "0" * 64,
            "state": None,
            "items": [],
            "resolution": None,
        }
        result, mock_client = _invoke_review(
            [empty_delta],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
        )
        assert result.exit_code == 0, result.output
        assert "no changes to assess" in result.output
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_json_output_includes_disclaimer(self):
        result, mock_client = _invoke_review(
            [NON_INTERACTIVE_UNRESOLVED],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
            output_format="json",
        )
        assert result.exit_code == 28, result.output
        # result.output mixes stdout+stderr (Click 8.2+); the pending notice
        # for --output json is deliberately routed to stderr so stdout stays
        # pure JSON, so parsing must use result.stdout, not result.output.
        parsed = json.loads(result.stdout)
        assert parsed["review"]["unresolved_item_ids"] == ["release_question:architecture"]
        assert parsed["advisory"]["disclaimer"]
        assert "review item" in result.stderr
        assert result.stdout.strip() != ""
        mock_client.open_ra_review_cycle.assert_not_called()

    def test_non_interactive_never_calls_record_disposition_even_on_tty(self):
        """The flag forces non-interactive regardless of TTY autodetection."""
        result, mock_client = _invoke_review(
            [NON_INTERACTIVE_UNRESOLVED],
            ["--product", "my-product", "--version", "1.2.3", "--non-interactive"],
            interactive=True,  # is_interactive() would say yes; --non-interactive wins
        )
        assert result.exit_code == 28, result.output
        mock_client.record_ra_disposition.assert_not_called()
        mock_client.open_ra_review_cycle.assert_not_called()




class TestRaReviewInteractive:
    def test_records_disposition_and_forwards_payload(self):
        result, mock_client = _invoke_review(
            [OPEN_CYCLE_SINGLE_ITEM, DISPOSITION_RESPONSE],
            ["--product", "my-product", "--version", "1.2.3"],
            input_text="a\nreviewed, fine\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_called_once_with(
            product="my-product",
            version="1.2.3",
            cycle_id="cycle-4",
            expected_digest="d" * 64,
            item_id="component_added:pkg:pypi/foo@1.0.0",
            disposition="accepted",
            justification="reviewed, fine",
        )

    def test_skip_leaves_item_unresolved_and_records_nothing(self):
        result, mock_client = _invoke_review(
            [OPEN_CYCLE_SINGLE_ITEM],
            ["--product", "my-product", "--version", "1.2.3"],
            input_text="s\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_not_called()

    def test_not_relevant_requires_a_reason(self):
        """Empty justification for 'not relevant' re-prompts instead of submitting."""
        result, mock_client = _invoke_review(
            [OPEN_CYCLE_SINGLE_ITEM, DISPOSITION_RESPONSE],
            ["--product", "my-product", "--version", "1.2.3"],
            # blank line is rejected, then a real reason is given
            input_text="n\n\nnot applicable to this build\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_called_once_with(
            product="my-product",
            version="1.2.3",
            cycle_id="cycle-4",
            expected_digest="d" * 64,
            item_id="component_added:pkg:pypi/foo@1.0.0",
            disposition="not_affected",
            justification="not applicable to this build",
        )

    def test_release_question_yes_records_added_risk(self):
        cycle = {
            **OPEN_CYCLE_SINGLE_ITEM,
            "items": [
                {
                    "item_id": "release_question:architecture",
                    "kind": "release_question",
                    "title": "Did the architecture change in this release?",
                    "detail": {"category": "architecture", "hint": "hint"},
                    "severity": "attention",
                }
            ],
            "resolution": {
                "resolved_count": 0,
                "total": 1,
                "unresolved_item_ids": ["release_question:architecture"],
            },
        }
        result, mock_client = _invoke_review(
            [cycle, DISPOSITION_RESPONSE],
            ["--product", "my-product", "--version", "1.2.3"],
            input_text="y\nnew interface added, assessed as risk-42\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_called_once_with(
            product="my-product",
            version="1.2.3",
            cycle_id="cycle-4",
            expected_digest="d" * 64,
            item_id="release_question:architecture",
            disposition="added_risk",
            justification="new interface added, assessed as risk-42",
        )

    def test_release_question_no_records_accepted_without_justification(self):
        cycle = {
            **OPEN_CYCLE_SINGLE_ITEM,
            "items": [
                {
                    "item_id": "release_question:architecture",
                    "kind": "release_question",
                    "title": "Did the architecture change in this release?",
                    "detail": {"category": "architecture", "hint": "hint"},
                    "severity": "attention",
                }
            ],
            "resolution": {
                "resolved_count": 0,
                "total": 1,
                "unresolved_item_ids": ["release_question:architecture"],
            },
        }
        result, mock_client = _invoke_review(
            [cycle, DISPOSITION_RESPONSE],
            ["--product", "my-product", "--version", "1.2.3"],
            input_text="n\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        mock_client.record_ra_disposition.assert_called_once_with(
            product="my-product",
            version="1.2.3",
            cycle_id="cycle-4",
            expected_digest="d" * 64,
            item_id="release_question:architecture",
            disposition="accepted",
            justification=None,
        )

    def test_409_supersede_refetches_and_new_digest_used_for_next_post(self):
        """A 409 on the disposition POST refreshes the cycle and re-prompts
        for the still-unresolved item; the follow-up POST must carry the
        refreshed cycle id and digest, not the stale ones from before the
        409."""
        result, mock_client = _invoke_review(
            [
                OPEN_CYCLE_SINGLE_ITEM,
                APIError("stale digest", status_code=409),
                OPEN_CYCLE_SINGLE_ITEM_REFRESHED,
                DISPOSITION_RESPONSE_AFTER_REFRESH,
            ],
            ["--product", "my-product", "--version", "1.2.3"],
            # First attempt (rejected with 409), then the re-prompt after refresh.
            input_text="a\nreviewed, fine\na\nreviewed, fine\n",
            interactive=True,
        )
        assert result.exit_code == 0, result.output
        assert mock_client.open_ra_review_cycle.call_count == 2
        assert "refreshed" in result.stderr

        assert mock_client.record_ra_disposition.call_count == 2
        first_call, second_call = mock_client.record_ra_disposition.call_args_list
        assert first_call.kwargs["cycle_id"] == "cycle-4"
        assert first_call.kwargs["expected_digest"] == "d" * 64
        assert second_call.kwargs["cycle_id"] == "cycle-6"
        assert second_call.kwargs["expected_digest"] == "h" * 64




class TestRaFinalize:
    def test_happy_path(self):
        result = _invoke_finalize(
            [GET_DELTA_OPEN_CYCLE, FINALIZE_RESULT],
            ["--product", "my-product", "--version", "1.2.3"],
        )
        assert result.exit_code == 0, result.output
        assert "marked reviewed" in result.output

    def test_json_output(self):
        result = _invoke_finalize(
            [GET_DELTA_OPEN_CYCLE, FINALIZE_RESULT],
            ["--product", "my-product", "--version", "1.2.3"],
            output_format="json",
        )
        assert result.exit_code == 0, result.output
        # result.output mixes stdout+stderr (Click 8.2+, includes any
        # UserWarning from validate_config); parse the pure stdout stream.
        parsed = json.loads(result.stdout)
        assert parsed["finalize"]["cycle_state"] == "resolved"
        assert parsed["advisory"]["disclaimer"]

    def test_403_passthrough(self):
        """The server's own detail is surfaced verbatim (only the API key is masked)."""
        result = _invoke_finalize(
            [
                GET_DELTA_OPEN_CYCLE,
                AuthenticationError(
                    "Only organisation administrators or owners can finalize a "
                    "risk-assessment review."
                ),
            ],
            ["--product", "my-product", "--version", "1.2.3"],
        )
        assert result.exit_code == 2, result.output
        assert "Only organisation administrators or owners" in result.output

    def test_no_open_cycle_errors(self):
        result = _invoke_finalize(
            [GET_DELTA_PREVIEW],
            ["--product", "my-product", "--version", "1.2.3"],
        )
        assert result.exit_code == 1, result.output
        assert "nothing to finalize" in result.output


# Client methods: POST payload shape (cycle_id/digest/item_id forwarded) and
# the not_affected client-side guard


class _FakeAsyncClient:
    def __init__(self, timeout):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class TestClientMethods:
    @pytest.mark.asyncio
    async def test_open_ra_review_cycle_posts_product_version(self, test_config, monkeypatch):
        client = CRAEvidenceClient(test_config)
        captured = {}

        class FakeClient(_FakeAsyncClient):
            async def post(self, url, headers, json):
                captured["url"] = url
                captured["json"] = json
                return Response(
                    status_code=201,
                    json={
                        "id": "cycle-1",
                        "digest": "a" * 64,
                        "state": "open",
                        "effective_at": "2026-07-30T00:00:00Z",
                        "delta_schema_version": 1,
                        "source_catalog_version": "ra-delta-catalog-1",
                        "items": [],
                        "pinned_evidence": {},
                        "resolution": {
                            "resolved_count": 0,
                            "total": 0,
                            "unresolved_item_ids": [],
                        },
                        "created": True,
                    },
                )

        monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeClient)

        result = await client.open_ra_review_cycle(product="my-product", version="1.2.3")

        assert result["id"] == "cycle-1"
        assert captured["url"] == (
            "https://api.test.craevidence.com/api/v1/ci/risk-assessment/review-cycles"
        )
        assert captured["json"] == {"product": "my-product", "version": "1.2.3"}

    @pytest.mark.asyncio
    async def test_record_ra_disposition_posts_payload(self, test_config, monkeypatch):
        client = CRAEvidenceClient(test_config)
        captured = {}

        class FakeClient(_FakeAsyncClient):
            async def post(self, url, headers, json):
                captured["url"] = url
                captured["json"] = json
                return Response(
                    status_code=201,
                    json={
                        "id": "disp-1",
                        "cycle_id": json["cycle_id"],
                        "item_id": json["item_id"],
                        "revision": 1,
                        "disposition": json["disposition"],
                        "justification": json.get("justification"),
                        "principal_kind": "api_key",
                        "created_at": "2026-07-30T00:00:00Z",
                        "resolution": {
                            "resolved_count": 1,
                            "total": 1,
                            "unresolved_item_ids": [],
                        },
                    },
                )

        monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeClient)

        result = await client.record_ra_disposition(
            product="my-product",
            version="1.2.3",
            cycle_id="cycle-1",
            expected_digest="a" * 64,
            item_id="component_added:pkg:pypi/foo@1.0.0",
            disposition="accepted",
            justification="looked fine",
        )

        assert result["disposition"] == "accepted"
        assert captured["url"] == (
            "https://api.test.craevidence.com/api/v1/ci/risk-assessment/review"
        )
        assert captured["json"] == {
            "product": "my-product",
            "version": "1.2.3",
            "cycle_id": "cycle-1",
            "expected_digest": "a" * 64,
            "item_id": "component_added:pkg:pypi/foo@1.0.0",
            "disposition": "accepted",
            "justification": "looked fine",
        }

    @pytest.mark.asyncio
    async def test_record_ra_disposition_not_affected_requires_justification(
        self, test_config, monkeypatch
    ):
        """Client-side guard: rejected before any network call is attempted."""
        client = CRAEvidenceClient(test_config)

        def _unexpected_async_client(timeout):
            msg = "must not contact the network without a justification"
            raise AssertionError(msg)

        monkeypatch.setattr(
            "cra_evidence_cli.client.httpx.AsyncClient", _unexpected_async_client
        )

        with pytest.raises(APIError) as exc_info:
            await client.record_ra_disposition(
                product="my-product",
                version="1.2.3",
                cycle_id="cycle-1",
                expected_digest="a" * 64,
                item_id="component_added:pkg:pypi/foo@1.0.0",
                disposition="not_affected",
                justification="   ",
            )

        assert exc_info.value.status_code == 422

    @pytest.mark.asyncio
    async def test_finalize_ra_review_posts_cycle_id(self, test_config, monkeypatch):
        client = CRAEvidenceClient(test_config)
        captured = {}

        class FakeClient(_FakeAsyncClient):
            async def post(self, url, headers, json):
                captured["url"] = url
                captured["json"] = json
                return Response(
                    status_code=200,
                    json={
                        "assessment_id": "assess-1",
                        "assessment_status": "signed_off",
                        "assessment_review_status": "reviewed",
                        "cycle_id": json["cycle_id"],
                        "cycle_state": "resolved",
                    },
                )

        monkeypatch.setattr("cra_evidence_cli.client.httpx.AsyncClient", FakeClient)

        result = await client.finalize_ra_review(
            product="my-product", version="1.2.3", cycle_id="cycle-1"
        )

        assert result["cycle_state"] == "resolved"
        assert captured["url"] == (
            "https://api.test.craevidence.com/api/v1/ci/risk-assessment/finalize"
        )
        assert captured["json"] == {
            "product": "my-product",
            "version": "1.2.3",
            "cycle_id": "cycle-1",
        }

    @pytest.mark.asyncio
    async def test_get_ra_delta_uses_retry_helper(self, test_config):
        client = CRAEvidenceClient(test_config)
        client._request_with_retry = AsyncMock(
            return_value=Response(
                status_code=200,
                json={
                    "preview": True,
                    "id": None,
                    "digest": "a" * 64,
                    "state": None,
                    "effective_at": "2026-07-30T00:00:00Z",
                    "delta_schema_version": 1,
                    "source_catalog_version": "ra-delta-catalog-1",
                    "items": [],
                    "pinned_evidence": {},
                    "resolution": None,
                },
            )
        )

        result = await client.get_ra_delta(product="my-product", version="1.2.3")

        assert result["preview"] is True
        client._request_with_retry.assert_awaited_once_with(
            "GET",
            "https://api.test.craevidence.com/api/v1/ci/risk-assessment/delta",
            params={"product": "my-product", "version": "1.2.3"},
        )



_NEW_OR_CHANGED_FILES = [
    "cra_evidence_cli/commands/ra.py",
    "cra_evidence_cli/client.py",
    "cra_evidence_cli/exceptions.py",
    "docs/account-commands.md",
    "README.md",
    "CHANGELOG.md",
    "tests/test_ra_review_command.py",
    "tests/test_ra_command.py",
]


def test_plain_language_guard_self_check_new_files():
    """Direct self-check independent of git tracking (see test_plain_language_guard.py
    for the repo-wide sweep, which only covers files once they are git-tracked)."""
    offenders: dict[str, list[str]] = {}
    for rel in _NEW_OR_CHANGED_FILES:
        path = REPO_ROOT / rel
        text = path.read_text(encoding="utf-8")
        bad = []
        for line in text.splitlines():
            bad.extend(_line_violations(rel, line))
        if bad:
            offenders[rel] = bad
    assert offenders == {}, offenders


def test_no_em_dashes_in_new_files():
    # Built from a Unicode escape, not a literal character, so this very
    # assertion string cannot trip the check against its own source file.
    em_dash = "\u2014"
    for rel in _NEW_OR_CHANGED_FILES:
        target = REPO_ROOT / rel
        text = target.read_text(encoding="utf-8")
        assert em_dash not in text, f"em dash found in {rel}"


def test_no_disallowed_verdict_words_in_ra_command():
    """Honesty wording: reviewed/recorded, never compliant/passed, for review-cycle output."""
    text = (REPO_ROOT / "cra_evidence_cli/commands/ra.py").read_text(encoding="utf-8")
    lowered = text.lower()
    assert "compliant" not in lowered
    assert "passed" not in lowered
