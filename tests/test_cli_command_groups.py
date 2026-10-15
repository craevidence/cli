"""Guard: the removed distributor command group stays removed.

Two narrow checks. The first fails if `distributor` is registered on `cli`
again, whether through `cli.add_command` or the `commands` package import. The
second fails if `cra_evidence_cli.commands.distributor` can be imported again.

What this does not do: it does not detect a differently named command that
targets a removed route, and it does not analyse endpoints. Those need their own
check when there is a scenario for one.
"""

from __future__ import annotations

from cra_evidence_cli.cli import cli

REMOVED_COMMANDS = {"distributor"}


def test_removed_commands_are_not_registered() -> None:
    registered = set(cli.commands.keys())
    reintroduced = registered & REMOVED_COMMANDS
    assert reintroduced == set(), (
        f"Command(s) with no server interface are registered again: {sorted(reintroduced)}"
    )


def test_distributor_module_is_gone() -> None:
    import importlib

    module = "cra_evidence_cli.commands.distributor"
    try:
        importlib.import_module(module)
    except ModuleNotFoundError as exc:
        # Only this module being absent proves the removal. A bare
        # ModuleNotFoundError would also be raised by a restored module whose
        # own import of something else failed, and that would let this test
        # pass while the module existed again.
        if exc.name != module:
            raise
        return
    msg = (
        f"{module} was re-created; its client methods targeted "
        "/api/v1/distributor/verifications, which the server no longer serves."
    )
    raise AssertionError(msg)


def test_verbose_version_omits_invalid_origins_without_echoing_credentials(monkeypatch):
    from click.testing import CliRunner

    from cra_evidence_cli.config import CRAEvidenceConfig

    for url in (
        "https://user:PRIVATE_MARKER@example.test",
        "https://example.test?key=PRIVATE_MARKER",
        "https://example.test/#PRIVATE_MARKER",
    ):
        monkeypatch.setattr(
            "cra_evidence_cli.cli.load_config",
            lambda captured_url=url, **_: CRAEvidenceConfig(url=captured_url),
        )
        result = CliRunner().invoke(cli, ["--verbose", "version"])
        assert result.exit_code == 0, result.output
        assert "craevidence version" in result.output
        assert "PRIVATE_MARKER" not in result.output
        assert "API URL:" not in result.output


def test_verbose_version_displays_normalized_valid_origin(monkeypatch):
    from click.testing import CliRunner

    from cra_evidence_cli.config import CRAEvidenceConfig

    monkeypatch.setattr(
        "cra_evidence_cli.cli.load_config",
        lambda **_: CRAEvidenceConfig(url="https://API.EXAMPLE.TEST:443/"),
    )
    result = CliRunner().invoke(cli, ["--verbose", "version"])
    assert result.exit_code == 0, result.output
    assert "API URL: https://api.example.test" in result.output


def test_help_and_version_import_without_the_posix_lock_module():
    """Catches eager import of a platform-only dependency by local startup."""
    import subprocess
    import sys

    script = """
import sys
sys.modules["fcntl"] = None
from click.testing import CliRunner
from cra_evidence_cli.cli import cli
from cra_evidence_cli.config import CRAEvidenceConfig
import importlib
module = importlib.import_module("cra_evidence_cli.cli")
module.load_config = lambda **_: CRAEvidenceConfig()
for args in (["--help"], ["version"], ["upload-sbom", "--help"]):
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 0, result.output
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
