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
