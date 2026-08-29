"""Verify that one GitHub release workflow run anchors a release source."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


class AnchorError(Exception):
    """The workflow-run response did not contain one exact release anchor."""


def find_anchor(
    payload: object,
    *,
    tag: str,
    source_sha: str,
    workflow_path: str,
) -> int:
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        message = "workflow-run response has an invalid shape"
        raise AnchorError(message)
    runs = payload["workflow_runs"]
    total_count = payload.get("total_count")
    if not isinstance(total_count, int) or total_count != len(runs):
        message = "workflow-run response is incomplete"
        raise AnchorError(message)

    matches = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("event") == "release"
        and run.get("head_branch") == tag
        and run.get("head_sha") == source_sha
        and run.get("path") == workflow_path
        and run.get("status") == "completed"
        and isinstance(run.get("id"), int)
        and run["id"] > 0
    ]
    if len(matches) != 1:
        message = f"expected exactly one completed release-event anchor, found {len(matches)}"
        raise AnchorError(message)
    return matches[0]["id"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("response", type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-path", required=True)
    args = parser.parse_args(argv)

    try:
        payload = json.loads(args.response.read_text(encoding="utf-8"))
        run_id = find_anchor(
            payload,
            tag=args.tag,
            source_sha=args.source_sha,
            workflow_path=args.workflow_path,
        )
    except (AnchorError, OSError, json.JSONDecodeError) as exc:
        print(f"release-event anchor verification failed: {exc}", file=sys.stderr)
        return 1

    print(run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
