"""Tests for CI environment detection: all supported platforms and merge logic."""

import os
from unittest.mock import patch

from cra_evidence_cli.ci_detect import (
    CIMetadata,
    _detect_azure_devops,
    _detect_bitbucket,
    _detect_circleci,
    _detect_generic_env,
    _detect_github_actions,
    _detect_gitlab_ci,
    _detect_jenkins,
    detect_ci_environment,
    merge_ci_metadata,
)


class TestCIMetadata:
    """Tests for CIMetadata dataclass."""

    def test_empty_metadata_not_detected(self):
        """is_detected() returns False when all fields are None."""
        metadata = CIMetadata()

        assert metadata.is_detected() is False

    def test_metadata_with_provider_detected(self):
        """is_detected() returns True when ci_provider is set."""
        metadata = CIMetadata(ci_provider="github")

        assert metadata.is_detected() is True

    def test_metadata_with_commit_detected(self):
        """is_detected() returns True when only commit_sha is set."""
        metadata = CIMetadata(commit_sha="abc123")

        assert metadata.is_detected() is True

    def test_to_dict(self):
        """to_dict() returns all six fields keyed by name."""
        metadata = CIMetadata(
            ci_provider="github",
            commit_sha="abc123",
            branch="main",
            pipeline_id="12345",
            repository="org/repo",
            pr_number="42",
        )

        result = metadata.to_dict()

        assert result["ci_provider"] == "github"
        assert result["commit_sha"] == "abc123"
        assert result["branch"] == "main"
        assert result["pipeline_id"] == "12345"
        assert result["repository"] == "org/repo"
        assert result["pr_number"] == "42"


class TestGitHubActionsDetection:
    """Tests for GitHub Actions detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when GITHUB_ACTIONS is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_github_actions()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates all CIMetadata fields from GITHUB_* vars."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": "abc123def456",
            "GITHUB_REF_NAME": "main",
            "GITHUB_RUN_ID": "12345678",
            "GITHUB_REPOSITORY": "my-org/my-repo",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_github_actions()

        assert result is not None
        assert result.ci_provider == "github"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "main"
        assert result.pipeline_id == "12345678"
        assert result.repository == "my-org/my-repo"

    def test_branch_parsed_from_ref(self):
        """Strips 'refs/heads/' prefix from GITHUB_REF when GITHUB_REF_NAME is absent."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REF": "refs/heads/feature-branch",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_github_actions()

        assert result.branch == "feature-branch"

    def test_tag_parsed_from_ref(self):
        """Strips 'refs/tags/' prefix from GITHUB_REF."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REF": "refs/tags/v1.0.0",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_github_actions()

        assert result.branch == "v1.0.0"


class TestGitLabCIDetection:
    """Tests for GitLab CI detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when GITLAB_CI is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_gitlab_ci()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates all CIMetadata fields from CI_* vars."""
        env_vars = {
            "GITLAB_CI": "true",
            "CI_COMMIT_SHA": "abc123def456",
            "CI_COMMIT_BRANCH": "main",
            "CI_PIPELINE_ID": "98765",
            "CI_PROJECT_PATH": "group/project",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_gitlab_ci()

        assert result is not None
        assert result.ci_provider == "gitlab"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "main"
        assert result.pipeline_id == "98765"
        assert result.repository == "group/project"


class TestJenkinsDetection:
    """Tests for Jenkins detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when JENKINS_URL is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_jenkins()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates CIMetadata and strips 'origin/' prefix from GIT_BRANCH."""
        env_vars = {
            "JENKINS_URL": "https://jenkins.example.com/",
            "GIT_COMMIT": "abc123def456",
            "GIT_BRANCH": "origin/main",
            "BUILD_ID": "123",
            "GIT_URL": "https://github.com/org/repo.git",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_jenkins()

        assert result is not None
        assert result.ci_provider == "jenkins"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "main"  # "origin/" stripped
        assert result.pipeline_id == "123"


class TestAzureDevOpsDetection:
    """Tests for Azure DevOps Pipelines detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when TF_BUILD is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_azure_devops()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates CIMetadata and strips 'refs/heads/' prefix from BUILD_SOURCEBRANCH."""
        env_vars = {
            "TF_BUILD": "True",
            "BUILD_SOURCEVERSION": "abc123def456",
            "BUILD_SOURCEBRANCH": "refs/heads/main",
            "BUILD_BUILDID": "456",
            "BUILD_REPOSITORY_NAME": "my-repo",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_azure_devops()

        assert result is not None
        assert result.ci_provider == "azure"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "main"  # "refs/heads/" stripped
        assert result.pipeline_id == "456"


class TestCircleCIDetection:
    """Tests for CircleCI detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when CIRCLECI is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_circleci()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates all CIMetadata fields from CIRCLE_* vars."""
        env_vars = {
            "CIRCLECI": "true",
            "CIRCLE_SHA1": "abc123def456",
            "CIRCLE_BRANCH": "develop",
            "CIRCLE_BUILD_NUM": "789",
            "CIRCLE_PROJECT_REPONAME": "my-project",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_circleci()

        assert result is not None
        assert result.ci_provider == "circleci"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "develop"
        assert result.pipeline_id == "789"


class TestBitbucketDetection:
    """Tests for Bitbucket Pipelines detection."""

    def test_not_detected_when_env_missing(self):
        """Returns None when BITBUCKET_BUILD_NUMBER is absent."""
        with patch.dict(os.environ, {}, clear=True):
            result = _detect_bitbucket()

        assert result is None

    def test_detected_with_full_env(self):
        """Populates all CIMetadata fields from BITBUCKET_* vars."""
        env_vars = {
            "BITBUCKET_BUILD_NUMBER": "42",
            "BITBUCKET_COMMIT": "abc123def456",
            "BITBUCKET_BRANCH": "main",
            "BITBUCKET_REPO_FULL_NAME": "workspace/repo",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_bitbucket()

        assert result is not None
        assert result.ci_provider == "bitbucket"
        assert result.commit_sha == "abc123def456"
        assert result.branch == "main"
        assert result.pipeline_id == "42"


class TestGenericEnvDetection:
    """Tests for generic CRA_* env var detection."""

    def test_detects_cra_env_vars(self):
        """Reads CRA_COMMIT_SHA, CRA_BRANCH, CRA_PIPELINE_ID, CRA_REPOSITORY into CIMetadata."""
        env_vars = {
            "CRA_COMMIT_SHA": "generic123",
            "CRA_BRANCH": "custom-branch",
            "CRA_PIPELINE_ID": "custom-123",
            "CRA_REPOSITORY": "custom/repo",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = _detect_generic_env()

        assert result.ci_provider is None  # Generic detection
        assert result.commit_sha == "generic123"
        assert result.branch == "custom-branch"
        assert result.pipeline_id == "custom-123"
        assert result.repository == "custom/repo"


class TestDetectCIEnvironment:
    """Tests for main detect_ci_environment function."""

    def test_priority_github_over_generic(self):
        """GitHub Actions wins when both GITHUB_ACTIONS and CRA_* vars are present."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": "github123",
            "CRA_COMMIT_SHA": "generic123",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = detect_ci_environment()

        assert result.ci_provider == "github"
        assert result.commit_sha == "github123"

    def test_fallback_to_generic(self):
        """Falls back to CRA_* vars when no known CI provider is detected."""
        env_vars = {
            "CRA_COMMIT_SHA": "generic123",
            "CRA_BRANCH": "main",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = detect_ci_environment()

        assert result.ci_provider is None
        assert result.commit_sha == "generic123"


class TestMergeCIMetadata:
    """Tests for merge_ci_metadata function."""

    def test_cli_overrides_detected(self):
        """Explicit CLI commit/branch beats auto-detected GITHUB_* values."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": "abc123def456abc123def456abc123def456abc1",
            "GITHUB_REF_NAME": "detected-branch",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = merge_ci_metadata(
                cli_commit="aabbccdd11223344aabbccdd11223344aabbccdd",
                cli_branch="cli-branch",
            )

        assert result["commit_sha"] == "aabbccdd11223344aabbccdd11223344aabbccdd"
        assert result["branch"] == "cli-branch"

    def test_detected_used_when_cli_missing(self):
        """Auto-detected GITHUB_* values are used when no CLI flags are provided."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": "abc123def456abc123def456abc123def456abc1",
            "GITHUB_REF_NAME": "detected-branch",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = merge_ci_metadata()

        assert result["commit_sha"] == "abc123def456abc123def456abc123def456abc1"
        assert result["branch"] == "detected-branch"

    def test_auto_detect_disabled(self):
        """auto_detect=False yields None commit_sha even when GITHUB_SHA is set."""
        env_vars = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SHA": "abc123def456abc123def456abc123def456abc1",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            result = merge_ci_metadata(auto_detect=False)

        # Should not use detected values
        assert result["commit_sha"] is None

    def test_repo_path_passed_through(self):
        """Explicit cli_repo_path is returned unchanged in repo_path."""
        result = merge_ci_metadata(cli_repo_path="packages/my-package")

        assert result["repo_path"] == "packages/my-package"


class TestRepoPathAutoDetect:
    """Auto-detection of repo_path via `git rev-parse --show-prefix`.

    Multi-repo support depends on this - without correct repo_path
    detection, monorepo subdirs would silently auto-attribute to one
    big root component (or trigger a monorepo collision error from the
    server).
    """

    def _run_git(self, cwd, *args):
        import subprocess
        subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=str(cwd),
            check=True,
            capture_output=True,
        )

    def test_root_returns_empty_string(self, tmp_path, monkeypatch):
        """At repo root, --show-prefix returns "" (canonical root)."""
        import shutil
        if shutil.which("git") is None:
            import pytest
            pytest.skip("git not installed")

        repo = tmp_path / "repo"
        repo.mkdir()
        self._run_git(repo, "init", "-q")
        # Set identity so commits don't fail on hosts without global config.
        self._run_git(repo, "config", "user.email", "t@e.test")
        self._run_git(repo, "config", "user.name", "t")
        monkeypatch.chdir(repo)

        from cra_evidence_cli.ci_detect import _detect_repo_path
        assert _detect_repo_path() == ""

    def test_subdir_returns_relative_path(self, tmp_path, monkeypatch):
        """Inside packages/firmware, returns 'packages/firmware'."""
        import shutil
        if shutil.which("git") is None:
            import pytest
            pytest.skip("git not installed")

        repo = tmp_path / "repo"
        sub = repo / "packages" / "firmware"
        sub.mkdir(parents=True)
        self._run_git(repo, "init", "-q")
        self._run_git(repo, "config", "user.email", "t@e.test")
        self._run_git(repo, "config", "user.name", "t")
        monkeypatch.chdir(sub)

        from cra_evidence_cli.ci_detect import _detect_repo_path
        assert _detect_repo_path() == "packages/firmware"

    def test_outside_git_returns_none(self, tmp_path, monkeypatch):
        """Outside any git checkout, returns None (not '')."""
        outside = tmp_path / "not-a-repo"
        outside.mkdir()
        monkeypatch.chdir(outside)

        from cra_evidence_cli.ci_detect import _detect_repo_path
        assert _detect_repo_path() is None

    def test_git_unavailable_returns_none(self, tmp_path, monkeypatch):
        """If `git` isn't on PATH, returns None - never raises."""
        import shutil as _shutil
        monkeypatch.setattr(_shutil, "which", lambda _: None)
        monkeypatch.chdir(tmp_path)

        from cra_evidence_cli.ci_detect import _detect_repo_path
        assert _detect_repo_path() is None

    def test_merge_uses_auto_detected_repo_path(self, tmp_path, monkeypatch):
        """When --repo-path is omitted, merge_ci_metadata uses the
        git-detected value rather than dropping to None."""
        import shutil
        if shutil.which("git") is None:
            import pytest
            pytest.skip("git not installed")

        repo = tmp_path / "repo"
        sub = repo / "services" / "api"
        sub.mkdir(parents=True)
        self._run_git(repo, "init", "-q")
        self._run_git(repo, "config", "user.email", "t@e.test")
        self._run_git(repo, "config", "user.name", "t")
        monkeypatch.chdir(sub)

        # Strip any inherited CI env so the auto-detect path is what
        # gets exercised, not a CI provider's vars.
        for key in list(os.environ):
            if any(
                key.startswith(prefix)
                for prefix in (
                    "GITHUB_", "GITLAB_", "CI_", "JENKINS_", "BUILD_",
                    "AZURE_", "CIRCLE", "BITBUCKET",
                )
            ):
                monkeypatch.delenv(key, raising=False)

        result = merge_ci_metadata()
        assert result["repo_path"] == "services/api"

    def test_explicit_overrides_auto_detect(self, tmp_path, monkeypatch):
        """Explicit --repo-path beats git auto-detection."""
        import shutil
        if shutil.which("git") is None:
            import pytest
            pytest.skip("git not installed")

        repo = tmp_path / "repo"
        sub = repo / "services" / "api"
        sub.mkdir(parents=True)
        self._run_git(repo, "init", "-q")
        self._run_git(repo, "config", "user.email", "t@e.test")
        self._run_git(repo, "config", "user.name", "t")
        monkeypatch.chdir(sub)

        result = merge_ci_metadata(cli_repo_path="manual/override")
        assert result["repo_path"] == "manual/override"
