"""Render the bundled rule pack metadata as a markdown table.

Output is written to stdout. Redirect to a file or paste into the README.

Usage: python scripts/generate_rule_docs.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
RULES_ROOT = REPO_ROOT / "cra_evidence_cli" / "local" / "rules"


def _origin(meta: dict) -> str:
    if "author" in meta:
        return str(meta["author"])
    if "origin" in meta:
        return str(meta["origin"])
    return ""


def main() -> None:
    rule_files = sorted(RULES_ROOT.rglob("*.yaml"))
    if not rule_files:
        sys.stderr.write("No rule files found under " + str(RULES_ROOT) + "\n")
        sys.exit(1)

    rows: list[dict] = []
    for f in rule_files:
        with open(f) as fh:
            data = yaml.safe_load(fh)
        r = data["rules"][0]
        meta = r.get("metadata", {})
        rows.append(
            {
                "id": r["id"],
                "languages": ", ".join(r.get("languages", [])),
                "severity": r.get("severity", ""),
                "confidence": meta.get("confidence", ""),
                "cwe": "; ".join(str(c).split(":")[0] for c in meta.get("cwe", [])),
                "owasp": "; ".join(str(o).split(" ")[0] for o in meta.get("owasp", [])),
                "origin": _origin(meta),
            }
        )

    col_widths = {
        "id": max(len("id"), max(len(r["id"]) for r in rows)),
        "languages": max(len("languages"), max(len(r["languages"]) for r in rows)),
        "severity": max(len("severity"), max(len(r["severity"]) for r in rows)),
        "confidence": max(len("confidence"), max(len(r["confidence"]) for r in rows)),
        "cwe": max(len("cwe"), max(len(r["cwe"]) for r in rows)),
        "owasp": max(len("owasp"), max(len(r["owasp"]) for r in rows)),
        "origin": max(len("origin"), max(len(r["origin"]) for r in rows)),
    }

    cols = ["id", "languages", "severity", "confidence", "cwe", "owasp", "origin"]

    def _row(cells: dict[str, str]) -> str:
        return "| " + " | ".join(cells[c].ljust(col_widths[c]) for c in cols) + " |"

    header = _row({c: c for c in cols})
    separator = "| " + " | ".join("-" * col_widths[c] for c in cols) + " |"

    print(header)
    print(separator)
    for r in rows:
        print(_row(r))


if __name__ == "__main__":
    main()
