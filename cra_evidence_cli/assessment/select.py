"""A dependency-free multi-select prompt for the scaffold flow.

Renders a numbered checklist with the recommended items pre-checked and lets the
user toggle entries by number or range. It works on any terminal and over a
pipe. When the session is not interactive (no TTY, or a CI run), it keeps the
recommended defaults and says so, so a pipeline never blocks waiting for input.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable

import click


def _parse_tokens(raw: str, count: int) -> set[int]:
    """Parse '1,3-5 7' into a set of 1-based indices within range."""
    indices: set[int] = set()
    for token in raw.replace(",", " ").split():
        if "-" in token:
            lo, _, hi = token.partition("-")
            if lo.isdigit() and hi.isdigit():
                for value in range(int(lo), int(hi) + 1):
                    if 1 <= value <= count:
                        indices.add(value)
        elif token.isdigit():
            value = int(token)
            if 1 <= value <= count:
                indices.add(value)
    return indices


def is_interactive() -> bool:
    """True when both stdin and stdout are attached to a terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def multiselect(
    title: str,
    options: list[tuple[str, str]],
    recommended: Iterable[str],
    *,
    interactive: bool | None = None,
) -> set[str]:
    """Return the chosen option ids.

    options: list of (id, label). recommended: ids pre-checked.
    interactive: force the mode; None auto-detects the terminal.
    """
    ids = [option_id for option_id, _ in options]
    selected = {option_id for option_id in ids if option_id in set(recommended)}
    if not options:
        return selected

    if interactive is None:
        interactive = is_interactive()
    if not interactive:
        click.echo(
            f"{title}: non-interactive session, keeping {len(selected)} recommended item(s).",
            err=True,
        )
        return selected

    click.echo(title, err=True)
    click.echo(
        "  Toggle by number or range (e.g. 1,3-5). 'a' all, 'n' none, Enter to confirm.",
        err=True,
    )
    while True:
        for index, (option_id, label) in enumerate(options, start=1):
            mark = "x" if option_id in selected else " "
            click.echo(f"  [{mark}] {index}. {label}", err=True)
        try:
            raw = click.prompt("  selection", default="", show_default=False).strip()
        except (click.Abort, EOFError):
            click.echo("  input closed, keeping current selection.", err=True)
            return selected
        if raw == "":
            return selected
        lowered = raw.lower()
        if lowered == "a":
            selected = set(ids)
            continue
        if lowered == "n":
            selected = set()
            continue
        for index in _parse_tokens(raw, len(options)):
            option_id = ids[index - 1]
            if option_id in selected:
                selected.discard(option_id)
            else:
                selected.add(option_id)
