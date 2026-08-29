"""Tests for the release workflow-run source anchor."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "verify_release_run_anchor.py"
_spec = importlib.util.spec_from_file_location("verify_release_run_anchor", _MODULE_PATH)
vra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vra)

TAG = "v4.3.0"
SHA = "96c1484778dc7d9c68a79f60b7a7801f4f31313d"
WORKFLOW = ".github/workflows/ci.yml"


def _run(**overrides: object) -> dict[str, object]:
    run: dict[str, object] = {
        "id": 33260494947,
        "event": "release",
        "head_branch": TAG,
        "head_sha": SHA,
        "path": WORKFLOW,
        "status": "completed",
        "conclusion": "failure",
    }
    run.update(overrides)
    return run


def _find(payload: object) -> int:
    return vra.find_anchor(
        payload,
        tag=TAG,
        source_sha=SHA,
        workflow_path=WORKFLOW,
    )


def test_exact_release_event_is_the_anchor():
    assert _find({"total_count": 1, "workflow_runs": [_run()]}) == 33260494947


@pytest.mark.parametrize(
    "override",
    [
        {"event": "workflow_dispatch"},
        {"head_branch": "v4.2.0"},
        {"head_sha": "0" * 40},
        {"path": ".github/workflows/other.yml"},
        {"status": "in_progress"},
        {"id": 0},
        {"id": "33260494947"},
    ],
)
def test_nonmatching_run_is_rejected(override):
    with pytest.raises(vra.AnchorError, match="found 0"):
        _find({"total_count": 1, "workflow_runs": [_run(**override)]})


def test_missing_anchor_is_rejected():
    with pytest.raises(vra.AnchorError, match="found 0"):
        _find({"total_count": 0, "workflow_runs": []})


def test_ambiguous_anchors_are_rejected():
    with pytest.raises(vra.AnchorError, match="found 2"):
        _find({"total_count": 2, "workflow_runs": [_run(), _run(id=7)]})


@pytest.mark.parametrize("payload", [{}, [], [None], {"workflow_runs": None}])
def test_invalid_response_shape_is_rejected(payload):
    with pytest.raises(vra.AnchorError, match="invalid shape"):
        _find(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"total_count": 2, "workflow_runs": [_run()]},
        {"total_count": "1", "workflow_runs": [_run()]},
        {"workflow_runs": [_run()]},
    ],
)
def test_incomplete_response_is_rejected(payload):
    with pytest.raises(vra.AnchorError, match="incomplete"):
        _find(payload)


def test_workflow_uses_the_anchor_with_least_privilege():
    workflow_path = _MODULE_PATH.parent.parent / ".github" / "workflows" / "ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["validate-release"]

    assert job["permissions"] == {"actions": "read", "contents": "read"}
    resolver = next(
        step["run"]
        for step in job["steps"]
        if step.get("name") == "Resolve and validate the release to publish"
    )
    assert "scripts/verify_release_run_anchor.py" in resolver
    assert 'source_anchor="release event run ${release_run_id}"' in resolver
