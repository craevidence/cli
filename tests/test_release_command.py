"""Tests for the release command: release state contract and Click validation."""

from click.testing import CliRunner

from cra_evidence_cli.commands.release import RELEASE_STATES, set_release_state


class TestReleaseStates:
    """Tests that CLI release states match the public API contract."""

    def test_valid_states_match_api_contract(self):
        """CLI RELEASE_STATES must match accepted release state values."""
        expected = [
            "draft",
            "pending_review",
            "approved",
            "released",
            "deprecated",
            "end_of_life",
        ]
        assert RELEASE_STATES == expected

    def test_no_legacy_states(self):
        """'testing' and 'archived' are absent from RELEASE_STATES."""
        assert "testing" not in RELEASE_STATES
        assert "archived" not in RELEASE_STATES

    def test_state_count(self):
        """RELEASE_STATES contains exactly 6 entries."""
        assert len(RELEASE_STATES) == 6


class TestReleaseCommand:
    """Tests for the release CLI command."""

    def test_rejects_invalid_state(self):
        """Command rejects states not in RELEASE_STATES."""
        runner = CliRunner()
        result = runner.invoke(
            set_release_state,
            ["--product", "test", "--version", "1.0", "--state", "testing"],
            obj={"config": None, "verbose": False},
            catch_exceptions=False,
        )
        # Click should reject "testing" as an invalid choice
        assert result.exit_code != 0

    def test_rejects_archived_state(self):
        """Command rejects the legacy 'archived' state."""
        runner = CliRunner()
        result = runner.invoke(
            set_release_state,
            ["--product", "test", "--version", "1.0", "--state", "archived"],
            obj={"config": None, "verbose": False},
            catch_exceptions=False,
        )
        assert result.exit_code != 0

    def test_accepts_end_of_life(self):
        """Command accepts 'end_of_life' (the replacement for 'archived')."""
        # We can't run the full command without a server, but we can verify
        # click accepts the choice by checking it doesn't fail on validation
        runner = CliRunner()
        result = runner.invoke(
            set_release_state,
            ["--product", "test", "--version", "1.0", "--state", "end_of_life"],
            obj={"config": None, "verbose": False},
            catch_exceptions=True,
        )
        # Should fail on config validation, NOT on click choice validation
        # (exit code 2 = click usage error for bad choice, other codes = our code ran)
        assert result.exit_code != 2 or "Invalid value for '--state'" not in result.output
