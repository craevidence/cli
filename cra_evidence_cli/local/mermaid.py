"""Deterministic Mermaid flowchart parser.

Parses a subset of Mermaid ``graph`` / ``flowchart`` syntax into plain Python
dataclasses.  No network access, no subprocess, no LLM, no external
dependencies -- only the Python standard library.

Supported constructs
--------------------
- ``graph`` / ``flowchart`` headers with optional direction (TD, LR, ...).
- Node declarations with all common shape wrappers:
  ``[default]``, ``(round)``, ``([stadium])``, ``[[subroutine]]``,
  ``[(datastore)]``, ``((circle))``, ``{decision}``, ``>flag]``, ``{hexagon}``.
- Edge connectors: ``-->``, ``---``, ``-.->``, ``-.-``, ``==>``, ``===``,
  ``--o``, ``--x``, and multi-dash variants.
- Inline edge labels via ``|label|`` or ``-- text -->`` syntax.
- Chained edges on a single line: ``A --> B --> C``.
- Subgraph trust-boundary blocks with quoted or bare ids and optional bracket
  titles.
- ``%%`` comment stripping (skips ``%%`` not inside brackets or quotes).
- ``%%{ ... }%%`` directive lines.
- Quoted node labels: ``id["My Label"]``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Public dataclasses


@dataclass
class MermaidNode:
    """A node extracted from a Mermaid diagram.

    ``id`` is the Mermaid identifier used in edge declarations.
    ``label`` is the human-readable text; defaults to ``id`` when omitted.
    ``shape`` is one of the recognised shape keywords (see module docstring).
    """

    id: str
    label: str
    shape: str


@dataclass
class MermaidEdge:
    """A directed edge extracted from a Mermaid diagram.

    ``label`` is ``None`` when the edge carries no annotation.
    """

    src: str
    dst: str
    label: str | None


@dataclass
class ParsedDiagram:
    """All structural information extracted from a single Mermaid diagram."""

    nodes: dict[str, MermaidNode] = field(default_factory=dict)
    edges: list[MermaidEdge] = field(default_factory=list)
    boundaries: dict[str, str] = field(default_factory=dict)
    node_boundary: dict[str, str] = field(default_factory=dict)


# Internal regex patterns

# Valid node identifier characters. Deliberately excludes '-' so a bare source id
# directly followed by a connector (the compact "A-->B" form, no spaces) is not
# swallowed into the id; node ids needing a hyphen can use a shape wrapper.
_ID_PAT = r"[A-Za-z0-9_.]+"

# Header line: ``graph TD``, ``flowchart LR``, etc.
_RE_HEADER = re.compile(
    r"^(graph|flowchart)(\s+(TB|TD|BT|RL|LR))?\s*$",
    re.IGNORECASE,
)

# Directive lines: ``%%{ ... }%%``
_RE_DIRECTIVE = re.compile(r"^%%\{.*\}%%\s*$")

# ``end`` keyword closing a subgraph.
_RE_END = re.compile(r"^end\s*$", re.IGNORECASE)

# Subgraph opening:
#   subgraph "Quoted Title" [Bracket Label]
#   subgraph bare_id [Bracket Label]
#   subgraph bare_id
_RE_SUBGRAPH = re.compile(
    r'^subgraph\s+(?:"([^"]+)"|(' + _ID_PAT + r'))(?:\s*\[([^\]]+)\])?\s*$',
    re.IGNORECASE,
)

# Edge connector variants (order matters: longer/more-specific first).
_CONNECTORS = [
    r"==+>",       # ==> / ===>
    r"===+",       # === (no arrow)
    r"-\.->",      # -.->
    r"-\.-",       # -.- (no arrow)
    r"--o",        # --o
    r"--x",        # --x
    r"--+>",       # --> / --->
    r"---+",       # --- (no arrow)
]
_CONN_RE = "(?:" + "|".join(_CONNECTORS) + ")"

# An endpoint is either:
#   id WITH an inline shape wrapper, or
#   just a bare id.
# We build a combined pattern that tries to capture the shape first.
#
# Shape wrappers (longer double-delimiters first):
#   id[(label)]   datastore
#   id((label))   circle
#   id([label])   stadium
#   id[[label]]   subroutine
#   id{label}     decision / hexagon  (hexagon needs {{}} but Mermaid uses {} too)
#   id>label]     flag
#   id(label)     round
#   id[label]     default

_LABEL_INNER = r'(?:"[^"]*"|[^\]\)\}]*)'  # content inside a shape wrapper

_SHAPE_WRAPPERS = (
    # (regex-suffix, shape-name)
    (r'\[\(' + _LABEL_INNER + r'\)\]', "datastore"),
    (r'\(\(' + _LABEL_INNER + r'\)\)', "circle"),
    (r'\(\[' + _LABEL_INNER + r'\]\)', "stadium"),
    (r'\[\[' + _LABEL_INNER + r'\]\]', "subroutine"),
    (r'\{' + _LABEL_INNER + r'\}', "decision"),
    (r'>' + _LABEL_INNER + r'\]', "flag"),
    (r'\(' + _LABEL_INNER + r'\)', "round"),
    (r'\[' + _LABEL_INNER + r'\]', "default"),
)

# Build a single regex for one endpoint: id + optional shape
_ENDPOINT_SHAPE_ALTERNATIVES = "|".join(
    rf"(?P<s{i}>{sfx})"
    for i, (sfx, _) in enumerate(_SHAPE_WRAPPERS)
)
_ENDPOINT_RE = re.compile(
    r"(?P<id>" + _ID_PAT + r")"
    r"(?:" + _ENDPOINT_SHAPE_ALTERNATIVES + r")?",
)

# Pipe label immediately after connector: ``|some label|``
_RE_PIPE_LABEL = re.compile(r"^\|([^|]*)\|")

# Inline-text connector: ``-- text -->`` or ``== text ==>``
# Captures: connector-start chars, label text, connector-end chars
_RE_INLINE_LABEL_CONN = re.compile(
    r"^(-{2,}|={2,})\s*([^>|]+?)\s*(--+>|==+>|--o|--x|---+|===+|-\.->|-\.-)\s*"
)


# Helper: strip trailing %% comment unless inside brackets/quotes

def _strip_comment(line: str) -> str:
    """Remove a trailing ``%%`` comment from a line.

    Skips ``%%`` sequences that appear inside ``[]``, ``()``, ``{}``, or
    double-quoted strings, because those are label content.
    """
    depth = 0
    in_quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if in_quote:
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth > 0:
                depth -= 1
        elif ch == "%" and i + 1 < len(line) and line[i + 1] == "%" and depth == 0 and not in_quote:
            return line[:i]
        i += 1
    return line


# Helper: parse a single endpoint token, returning (id, label, shape)

def _parse_endpoint(token: str) -> tuple[str, str, str]:
    """Parse an endpoint token into ``(node_id, label, shape)``.

    ``token`` is the raw text of one endpoint, such as ``GW[API Gateway]`` or
    just ``GW``.  Returns the node id, its label (falling back to the id), and
    the Mermaid shape name.
    """
    m = _ENDPOINT_RE.match(token.strip())
    if not m:
        # Cannot parse -- treat the whole token as a bare id.
        bare = token.strip()
        return bare, bare, "default"

    node_id = m.group("id")
    # Find which shape group matched.
    label: str | None = None
    shape = "default"
    for i, (_, shape_name) in enumerate(_SHAPE_WRAPPERS):
        grp = m.group(f"s{i}")
        if grp is not None:
            shape = shape_name
            # Extract the inner label content from the matched wrapper.
            # Strip the wrapper delimiters by looking at the shape suffix.
            # Simpler: re-extract the inner text using the known wrappers.
            label = _extract_label_from_wrapper(grp, shape_name)
            break

    if label is None:
        label = node_id
    return node_id, label, shape


def _extract_label_from_wrapper(wrapper: str, shape: str) -> str:
    """Strip shape delimiters and return the inner label text.

    ``wrapper`` is the matched wrapper string (e.g. ``[API Gateway]``).
    """
    # Map shape -> (prefix_chars, suffix_chars)
    delimiters: dict[str, tuple[str, str]] = {
        "datastore": ("[(", ")]"),
        "circle": ("((", "))"),
        "stadium": ("([", "])"),
        "subroutine": ("[[", "]]"),
        "decision": ("{", "}"),
        "flag": (">", "]"),
        "round": ("(", ")"),
        "default": ("[", "]"),
    }
    prefix, suffix = delimiters[shape]
    inner = wrapper
    if inner.startswith(prefix):
        inner = inner[len(prefix):]
    if inner.endswith(suffix):
        inner = inner[: -len(suffix)]
    # Strip surrounding quotes if present.
    inner = inner.strip()
    if inner.startswith('"') and inner.endswith('"') and len(inner) >= 2:
        inner = inner[1:-1]
    return inner


# Helper: split a line into edge segments

def _split_edge_line(line: str) -> list[tuple[str, str | None, str]]:
    """Split one line into a list of ``(src_token, label, dst_token)`` triples.

    Handles chained edges (``A --> B --> C``) by consuming the line left to
    right.  Returns an empty list when the line is not a recognised edge.
    """
    rest = line.strip()
    segments: list[tuple[str, str | None, str]] = []

    # Consume the source endpoint first.
    src_token, rest = _consume_endpoint(rest)
    if src_token is None:
        return []

    while rest:
        rest = rest.strip()
        if not rest:
            break

        # Try inline-text connector: ``-- text -->``
        inline_m = _RE_INLINE_LABEL_CONN.match(rest)
        if inline_m:
            edge_label: str | None = inline_m.group(2).strip() or None
            rest = rest[inline_m.end():].strip()
            dst_token, rest = _consume_endpoint(rest)
            if dst_token is None:
                break
            segments.append((src_token, edge_label, dst_token))
            src_token = dst_token
            continue

        # Try a plain connector (possibly followed by a pipe label).
        conn_m = re.match(r"^" + _CONN_RE, rest)
        if not conn_m:
            break
        rest = rest[conn_m.end():]

        # Optional pipe label after connector.
        pipe_m = _RE_PIPE_LABEL.match(rest.lstrip())
        if pipe_m:
            edge_label = pipe_m.group(1).strip() or None
            rest = rest.lstrip()[pipe_m.end():]
        else:
            edge_label = None

        rest = rest.strip()
        dst_token, rest = _consume_endpoint(rest)
        if dst_token is None:
            break

        segments.append((src_token, edge_label, dst_token))
        src_token = dst_token

    return segments


def _consume_endpoint(text: str) -> tuple[str | None, str]:
    """Extract a leading endpoint token from ``text``.

    Returns ``(token, remainder)`` where ``token`` is the raw endpoint text
    (id + optional shape wrapper) and ``remainder`` is the unconsumed tail.
    Returns ``(None, text)`` when no endpoint could be matched.
    """
    text = text.strip()
    if not text:
        return None, text

    m = _ENDPOINT_RE.match(text)
    if not m:
        return None, text

    end = m.end("id")

    # Check whether any shape group also matched.
    for i in range(len(_SHAPE_WRAPPERS)):
        grp = m.group(f"s{i}")
        if grp is not None:
            # The shape group starts immediately after the id.
            end = m.end(f"s{i}")
            break

    token = text[:end]
    remainder = text[end:]
    return token, remainder


# Helper: check if a line looks like a bare node declaration (no edge)

_RE_BARE_NODE = re.compile(r"^(" + _ID_PAT + r")(.*)$")


def _try_bare_node(line: str) -> tuple[str, str, str] | None:
    """Return ``(id, label, shape)`` if the line is a bare node declaration.

    Returns ``None`` if the line is not a valid bare node.
    """
    line = line.strip()
    m = _RE_BARE_NODE.match(line)
    if not m:
        return None
    node_id = m.group(1)
    rest = m.group(2).strip()
    if not rest:
        # Bare id with no shape wrapper.
        return node_id, node_id, "default"
    # Try to match a shape wrapper immediately.
    full = node_id + rest
    endpoint_m = _ENDPOINT_RE.match(full)
    if not endpoint_m:
        return None
    # Verify the entire string was consumed (no trailing junk).
    end = endpoint_m.end("id")
    for i in range(len(_SHAPE_WRAPPERS)):
        grp = endpoint_m.group(f"s{i}")
        if grp is not None:
            end = endpoint_m.end(f"s{i}")
            break
    if end != len(full):
        return None
    _, label, shape = _parse_endpoint(full)
    return node_id, label, shape


# Helper: split a line into top-level statements separated by ';'

def _split_statements(line: str) -> list[str]:
    """Split a line on top-level ``;`` separators (Mermaid statement separators).

    Mermaid allows several statements on one line, e.g. ``graph TD; A-->B; B-->C``.
    A ``;`` inside brackets, parentheses, braces, or double quotes is label
    content, not a separator.
    """
    parts: list[str] = []
    depth = 0
    in_quote = False
    start = 0
    for i, ch in enumerate(line):
        if in_quote:
            if ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth > 0:
                depth -= 1
        elif ch == ";" and depth == 0:
            parts.append(line[start:i])
            start = i + 1
    parts.append(line[start:])
    return parts


# Public API

def parse_mermaid(text: str) -> ParsedDiagram:
    """Parse a Mermaid ``graph`` / ``flowchart`` diagram string.

    Accepts arbitrary text; never raises.  Returns whatever structure could be
    extracted.  Unrecognised statements are silently ignored.
    """
    # Strip leading UTF-8 BOM.
    if text.startswith("﻿"):
        text = text[1:]

    diagram = ParsedDiagram()
    # Stack of (id, title) for open subgraph scopes.
    boundary_stack: list[tuple[str, str]] = []

    for raw_line in text.splitlines():
        # Strip directive lines early (%%{ ... }%%).
        if _RE_DIRECTIVE.match(raw_line.strip()):
            continue

        # Strip trailing comment then surrounding whitespace.
        cleaned = _strip_comment(raw_line).strip()
        if not cleaned or cleaned.startswith("%%"):
            continue

        # A single physical line may hold several ';'-separated statements.
        for statement in _split_statements(cleaned):
            statement = statement.strip()
            if statement:
                _process_statement(statement, diagram, boundary_stack)

    return diagram


def _process_statement(
    line: str, diagram: ParsedDiagram, boundary_stack: list[tuple[str, str]]
) -> None:
    """Apply one Mermaid statement to the diagram, mutating it in place."""
    # Header.
    if _RE_HEADER.match(line):
        return

    # Subgraph close.
    if _RE_END.match(line):
        if boundary_stack:
            boundary_stack.pop()
        return

    # Subgraph open.
    sg_m = _RE_SUBGRAPH.match(line)
    if sg_m:
        quoted_id = sg_m.group(1)   # present when ``"..."`` form
        bare_id = sg_m.group(2)     # present when bare-id form
        bracket_title = sg_m.group(3)
        sg_id = quoted_id if quoted_id is not None else bare_id
        if bracket_title is not None:
            sg_title = bracket_title.strip()
        elif quoted_id is not None:
            sg_title = quoted_id
        else:
            sg_title = sg_id
        boundary_stack.append((sg_id, sg_title))
        diagram.boundaries[sg_id] = sg_title
        return

    # Current boundary (innermost subgraph).
    current_boundary: str | None = boundary_stack[-1][0] if boundary_stack else None

    # Try to parse as an edge statement.
    segments = _split_edge_line(line)
    if segments:
        for src_tok, edge_label, dst_tok in segments:
            src_id, src_label, src_shape = _parse_endpoint(src_tok)
            dst_id, dst_label, dst_shape = _parse_endpoint(dst_tok)
            _register_node(diagram, src_id, src_label, src_shape)
            _register_node(diagram, dst_id, dst_label, dst_shape)
            if current_boundary is not None:
                diagram.node_boundary.setdefault(src_id, current_boundary)
                diagram.node_boundary.setdefault(dst_id, current_boundary)
            diagram.edges.append(MermaidEdge(src=src_id, dst=dst_id, label=edge_label))
        return

    # Try as a bare node declaration.
    result = _try_bare_node(line)
    if result is not None:
        node_id, label, shape = result
        _register_node(diagram, node_id, label, shape)
        if current_boundary is not None:
            diagram.node_boundary[node_id] = current_boundary
        return

    # Unrecognised statement -- skip silently.


def _register_node(diagram: ParsedDiagram, node_id: str, label: str, shape: str) -> None:
    """Insert or update a node in ``diagram.nodes``.

    The last non-bare (non-id-fallback) label/shape wins.  A bare-id label
    (``label == node_id``) does not overwrite an already-recorded real label.
    """
    if node_id not in diagram.nodes:
        diagram.nodes[node_id] = MermaidNode(id=node_id, label=label, shape=shape)
        return
    existing = diagram.nodes[node_id]
    # Update label only when the new label carries real information.
    if label != node_id:
        existing.label = label
    # Update shape only when the new declaration has an explicit wrapper.
    if shape != "default" or (shape == "default" and existing.shape == "default"):
        if label != node_id:
            existing.shape = shape
