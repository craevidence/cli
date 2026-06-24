"""Best-effort product-type detection from a project directory.

Scans for the marker files each template declares (build configs, manifests) and
returns the best-matching template id. This only suggests a starting point: the
developer confirms the product type, and detection never silently picks a
template on its own.
"""

from __future__ import annotations

import os
from pathlib import Path

from cra_evidence_cli.assessment.templates import Template, list_templates

_MAX_DEPTH = 2
_SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", "dist", "build", ".tox"}


def _collect_names(root: Path) -> set[str]:
    """Collect file names and shallow relative paths under root, bounded depth."""
    names: set[str] = set()
    root = root if root.is_dir() else root.parent
    for current, dirs, files in os.walk(root):
        rel = Path(current).relative_to(root)
        depth = len(rel.parts)
        if depth >= _MAX_DEPTH:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            names.add(name)
            names.add(str(rel / name).replace(os.sep, "/"))
    return names


def _score(template: Template, names: set[str]) -> int:
    """Strong weight for declared marker files, weak weight for shared manifests."""
    score = 0
    for marker in template.detect_files:
        leaf = marker.rsplit("/", 1)[-1]
        if marker in names or leaf in names:
            score += 2
    for manifest in template.detect_manifests:
        if manifest in names:
            score += 1
    return score


def detect_template(path: Path) -> str | None:
    """Return the highest-scoring template id for a directory, or None on no/tie signal."""
    names = _collect_names(path)
    if not names:
        return None
    ranked = sorted(
        ((_score(template, names), template.id) for template in list_templates()),
        reverse=True,
    )
    if not ranked or ranked[0][0] == 0:
        return None
    if len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
        return None  # ambiguous, do not guess
    return ranked[0][1]
