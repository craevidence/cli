"""Shared styles for human terminal output."""

from __future__ import annotations

from rich.markup import escape

STYLE_BLOCKER = "red bold"
STYLE_ERROR = "red"
STYLE_LABEL = "cyan"
STYLE_MUTED = "dim"
STYLE_OK = "green"
STYLE_REVIEW = "yellow"
STYLE_TITLE = "bold"


def label(text: object) -> str:
    return f"[{STYLE_LABEL}]{escape(str(text))}:[/{STYLE_LABEL}]"


def muted(text: object) -> str:
    return f"[{STYLE_MUTED}]{escape(str(text))}[/{STYLE_MUTED}]"


def result(text: object, style: str) -> str:
    return f"[{style}]{escape(str(text))}[/{style}]"


def severity_style(severity: object, count: int | None = None) -> str:
    if count is not None and count <= 0:
        return STYLE_OK
    lowered = str(severity).lower()
    if lowered == "critical":
        return STYLE_BLOCKER
    if lowered in {"high", "medium"}:
        return STYLE_REVIEW
    if lowered in {"low", "negligible"}:
        return STYLE_MUTED
    return "white"


def status_style(status: object) -> str:
    lowered = str(status).lower().replace("_", "-")
    if lowered in {"ready", "trusted", "valid", "passed", "complete", "completed", "met"}:
        return STYLE_OK
    if lowered in {
        "pending",
        "needs-review",
        "review-needed",
        "valid-untrusted",
        "unknown",
        "not-applicable",
    }:
        return STYLE_REVIEW
    if lowered in {"failed", "invalid", "error", "not-ready", "not-met", "blocked"}:
        return STYLE_ERROR
    return "white"
