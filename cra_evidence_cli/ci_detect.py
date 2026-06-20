"""
CI Environment Auto-Detection Module

Automatically detects CI/CD environment and extracts metadata like
commit SHA, branch name, pipeline ID, and repository information.

Supports:
- GitHub Actions
- GitLab CI
- Jenkins
- Azure DevOps Pipelines
- CircleCI
- Bitbucket Pipelines

For unsupported CI platforms, use CRA_* environment variables:
- CRA_COMMIT_SHA
- CRA_BRANCH
- CRA_PIPELINE_ID
- CRA_REPOSITORY
"""

import os
from dataclasses import dataclass


@dataclass
class CIMetadata:
    """Metadata extracted from CI environment."""

    ci_provider: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    pipeline_id: str | None = None
    repository: str | None = None
    pr_number: str | None = None

    def is_detected(self) -> bool:
        """Check if any CI metadata was detected."""
        return self.ci_provider is not None or any(
            [self.commit_sha, self.branch, self.pipeline_id, self.repository]
        )

    def to_dict(self) -> dict[str, str | None]:
        """Serialise fields to a plain dict."""
        return {
            "ci_provider": self.ci_provider,
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "pipeline_id": self.pipeline_id,
            "repository": self.repository,
            "pr_number": self.pr_number,
        }


def _detect_github_actions() -> CIMetadata | None:
    """Detect GitHub Actions environment."""
    if os.getenv("GITHUB_ACTIONS") != "true":
        return None

    # GITHUB_REF_NAME is clean (e.g., "main"), GITHUB_REF has prefix (e.g., "refs/heads/main")
    branch = os.getenv("GITHUB_REF_NAME")
    pr_number: str | None = None
    if not branch:
        # Fallback: parse GITHUB_REF
        ref = os.getenv("GITHUB_REF", "")
        if ref.startswith("refs/heads/"):
            branch = ref[11:]  # Strip "refs/heads/"
        elif ref.startswith("refs/tags/"):
            branch = ref[10:]  # Strip "refs/tags/"
        elif ref.startswith("refs/pull/"):
            # PR: refs/pull/123/merge -> extract PR number
            parts = ref.split("/")
            if len(parts) >= 3:
                pr_number = parts[2]
            branch = ref

    return CIMetadata(
        ci_provider="github",
        commit_sha=os.getenv("GITHUB_SHA"),
        branch=branch,
        pipeline_id=os.getenv("GITHUB_RUN_ID"),
        repository=os.getenv("GITHUB_REPOSITORY"),
        pr_number=pr_number,
    )


def _detect_gitlab_ci() -> CIMetadata | None:
    """Detect GitLab CI environment."""
    if os.getenv("GITLAB_CI") != "true":
        return None

    # CI_COMMIT_BRANCH is set for branch pipelines, CI_COMMIT_REF_NAME for all
    branch = os.getenv("CI_COMMIT_BRANCH") or os.getenv("CI_COMMIT_REF_NAME")

    return CIMetadata(
        ci_provider="gitlab",
        commit_sha=os.getenv("CI_COMMIT_SHA"),
        branch=branch,
        pipeline_id=os.getenv("CI_PIPELINE_ID"),
        repository=os.getenv("CI_PROJECT_PATH"),
        pr_number=os.getenv("CI_MERGE_REQUEST_IID"),
    )


def _detect_jenkins() -> CIMetadata | None:
    """Detect Jenkins environment."""
    if not os.getenv("JENKINS_URL"):
        return None

    # GIT_BRANCH typically includes remote prefix: "origin/main"
    branch = os.getenv("GIT_BRANCH", "")
    if branch.startswith("origin/"):
        branch = branch[7:]  # Strip "origin/"

    return CIMetadata(
        ci_provider="jenkins",
        commit_sha=os.getenv("GIT_COMMIT"),
        branch=branch or None,
        pipeline_id=os.getenv("BUILD_ID"),
        repository=os.getenv("GIT_URL"),
        pr_number=os.getenv("CHANGE_ID"),  # Jenkins GitHub Branch Source plugin
    )


def _detect_azure_devops() -> CIMetadata | None:
    """Detect Azure DevOps Pipelines environment."""
    if os.getenv("TF_BUILD") != "True":
        return None

    # BUILD_SOURCEBRANCH has prefix: "refs/heads/main"
    branch = os.getenv("BUILD_SOURCEBRANCH", "")
    if branch.startswith("refs/heads/"):
        branch = branch[11:]  # Strip "refs/heads/"
    elif branch.startswith("refs/pull/"):
        # PR: refs/pull/123/merge
        pass

    return CIMetadata(
        ci_provider="azure",
        commit_sha=os.getenv("BUILD_SOURCEVERSION"),
        branch=branch or None,
        pipeline_id=os.getenv("BUILD_BUILDID"),
        repository=os.getenv("BUILD_REPOSITORY_NAME"),
        pr_number=os.getenv("SYSTEM_PULLREQUEST_PULLREQUESTID"),
    )


def _detect_circleci() -> CIMetadata | None:
    """Detect CircleCI environment."""
    if os.getenv("CIRCLECI") != "true":
        return None

    return CIMetadata(
        ci_provider="circleci",
        commit_sha=os.getenv("CIRCLE_SHA1"),
        branch=os.getenv("CIRCLE_BRANCH"),
        pipeline_id=os.getenv("CIRCLE_BUILD_NUM"),
        repository=os.getenv("CIRCLE_PROJECT_REPONAME"),
        pr_number=os.getenv("CIRCLE_PR_NUMBER"),
    )


def _detect_bitbucket() -> CIMetadata | None:
    """Detect Bitbucket Pipelines environment."""
    if not os.getenv("BITBUCKET_BUILD_NUMBER"):
        return None

    return CIMetadata(
        ci_provider="bitbucket",
        commit_sha=os.getenv("BITBUCKET_COMMIT"),
        branch=os.getenv("BITBUCKET_BRANCH"),
        pipeline_id=os.getenv("BITBUCKET_BUILD_NUMBER"),
        repository=os.getenv("BITBUCKET_REPO_FULL_NAME"),
        pr_number=os.getenv("BITBUCKET_PR_ID"),
    )


def _detect_generic_env() -> CIMetadata:
    """
    Fallback detection using CRA_* environment variables.

    Use these when running in an unsupported CI platform:
    - CRA_COMMIT_SHA
    - CRA_BRANCH
    - CRA_PIPELINE_ID
    - CRA_REPOSITORY
    """
    return CIMetadata(
        ci_provider=None,
        commit_sha=os.getenv("CRA_COMMIT_SHA"),
        branch=os.getenv("CRA_BRANCH"),
        pipeline_id=os.getenv("CRA_PIPELINE_ID"),
        repository=os.getenv("CRA_REPOSITORY"),
        pr_number=None,
    )


def detect_ci_environment() -> CIMetadata:
    """
    Detect CI environment and extract metadata.

    Detection order:
    1. GitHub Actions
    2. GitLab CI
    3. Jenkins
    4. Azure DevOps Pipelines
    5. CircleCI
    6. Bitbucket Pipelines
    7. Generic CRA_* environment variables (fallback)

    Returns:
        CIMetadata with detected values (may have None fields if not detected)
    """
    detectors = [
        _detect_github_actions,
        _detect_gitlab_ci,
        _detect_jenkins,
        _detect_azure_devops,
        _detect_circleci,
        _detect_bitbucket,
    ]

    for detector in detectors:
        result = detector()
        if result is not None:
            return result

    return _detect_generic_env()


def _validate_metadata(metadata: dict) -> dict:
    """
    Validate and sanitize CI metadata values before use.

    - commit_sha: must be hex-only, max 64 chars; set to None if invalid.
    - branch, repository, pipeline_id: truncated to 256 chars max.
    """
    import re

    validated = dict(metadata)

    # Validate commit_sha: hex characters only, max 64 chars
    commit_sha = validated.get("commit_sha")
    if commit_sha is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{1,64}", commit_sha):
            validated["commit_sha"] = None

    # Truncate string fields to 256 chars
    for field in ("branch", "repository", "pipeline_id"):
        value = validated.get(field)
        if value is not None:
            validated[field] = value[:256]

    return validated


def merge_ci_metadata(
    cli_commit: str | None = None,
    cli_branch: str | None = None,
    cli_pipeline_id: str | None = None,
    cli_repository: str | None = None,
    cli_repo_path: str | None = None,
    auto_detect: bool = True,
) -> dict[str, str | None]:
    """
    Merge CLI-provided values with auto-detected CI metadata.

    Priority order: CLI flags > auto-detected values

    Args:
        cli_commit: Commit SHA from CLI flag
        cli_branch: Branch name from CLI flag
        cli_pipeline_id: Pipeline ID from CLI flag
        cli_repository: Repository from CLI flag
        cli_repo_path: Repository subdirectory (monorepo) from CLI flag
        auto_detect: Whether to auto-detect CI environment (default True)

    Returns:
        Dictionary with merged metadata (ready to pass to API client)
    """
    if auto_detect:
        ci_metadata = detect_ci_environment()
    else:
        ci_metadata = CIMetadata()  # Empty metadata

    # repo_path: explicit CLI value wins; otherwise try git
    # rev-parse --show-prefix from CWD. Returns the empty string for
    # "repo root", which is distinct from None ("not in a git checkout"
    # or detection unavailable).
    detected_repo_path = (
        cli_repo_path if cli_repo_path is not None else _detect_repo_path()
    )

    raw = {
        "commit_sha": cli_commit or ci_metadata.commit_sha,
        "branch": cli_branch or ci_metadata.branch,
        "pipeline_id": cli_pipeline_id or ci_metadata.pipeline_id,
        "repository": cli_repository or ci_metadata.repository,
        "repo_path": detected_repo_path,
        "pr_number": ci_metadata.pr_number,
    }
    return _validate_metadata(raw)


def _detect_repo_path() -> str | None:
    """Return the relative path of CWD inside its git repo, or None.

    Uses ``git rev-parse --show-prefix``:
      - returns "" if CWD is the repo root
      - returns "packages/firmware" if CWD is packages/firmware
      - returns None if not in a git checkout / git unavailable
    """
    import shutil
    import subprocess

    if shutil.which("git") is None:
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-prefix"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    prefix = result.stdout.strip().rstrip("/")
    return prefix  # may be "" for root, never None on success
