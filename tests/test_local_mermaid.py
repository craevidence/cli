"""Tests for the Mermaid flowchart parser (cra_evidence_cli.local.mermaid)."""

from __future__ import annotations

import pytest

from cra_evidence_cli.local.mermaid import (
    MermaidEdge,
    MermaidNode,
    ParsedDiagram,
    parse_mermaid,
)

# Fixture: representative diagram

_DIAGRAM = """\
graph TD
  User[User] -->|HTTPS| GW[API Gateway]
  GW --> Auth[Auth Service]
  GW --> App[App Server]
  App --> DB[(Database)]
  App -->|metrics| Ext[Datadog]
  subgraph internal
    Auth
    App
    DB
  end
"""


@pytest.fixture
def parsed() -> ParsedDiagram:
    """Return the parsed representative diagram."""
    return parse_mermaid(_DIAGRAM)


# 1. Nodes -- labels and shapes


def test_all_expected_nodes_present(parsed: ParsedDiagram) -> None:
    """Every referenced node id appears in nodes."""
    expected = {"User", "GW", "Auth", "App", "DB", "Ext"}
    assert expected.issubset(parsed.nodes.keys()), (
        f"Missing node ids: {expected - parsed.nodes.keys()}"
    )


def test_node_labels(parsed: ParsedDiagram) -> None:
    """Node labels match the declared text in the diagram."""
    assert parsed.nodes["User"].label == "User"
    assert parsed.nodes["GW"].label == "API Gateway"
    assert parsed.nodes["Auth"].label == "Auth Service"
    assert parsed.nodes["App"].label == "App Server"
    assert parsed.nodes["DB"].label == "Database"
    assert parsed.nodes["Ext"].label == "Datadog"


def test_db_shape_is_datastore(parsed: ParsedDiagram) -> None:
    """DB declared with ``[(label)]`` wrapper resolves to the datastore shape."""
    assert parsed.nodes["DB"].shape == "datastore"


# 2. Edges


def test_edge_count(parsed: ParsedDiagram) -> None:
    """Exactly 5 edges are extracted from the representative diagram."""
    assert len(parsed.edges) == 5


def test_edge_pairs(parsed: ParsedDiagram) -> None:
    """All five (src, dst) pairs are present and correct."""
    pairs = {(e.src, e.dst) for e in parsed.edges}
    expected = {
        ("User", "GW"),
        ("GW", "Auth"),
        ("GW", "App"),
        ("App", "DB"),
        ("App", "Ext"),
    }
    assert pairs == expected


def test_https_edge_label(parsed: ParsedDiagram) -> None:
    """The User -> GW edge carries the label 'HTTPS'."""
    edge = next(e for e in parsed.edges if e.src == "User" and e.dst == "GW")
    assert edge.label == "HTTPS"


def test_metrics_edge_label(parsed: ParsedDiagram) -> None:
    """The App -> Ext edge carries the label 'metrics'."""
    edge = next(e for e in parsed.edges if e.src == "App" and e.dst == "Ext")
    assert edge.label == "metrics"


def test_unlabeled_edge_has_none_label(parsed: ParsedDiagram) -> None:
    """At least one edge has label None (unlabeled)."""
    none_labels = [e for e in parsed.edges if e.label is None]
    assert none_labels, "Expected at least one edge with label=None"


# 3. Subgraph / trust boundary


def test_boundary_internal_exists(parsed: ParsedDiagram) -> None:
    """The 'internal' subgraph is recorded in boundaries."""
    assert "internal" in parsed.boundaries
    assert parsed.boundaries["internal"] == "internal"


def test_nodes_inside_boundary(parsed: ParsedDiagram) -> None:
    """Auth, App, and DB are attributed to the 'internal' boundary."""
    assert parsed.node_boundary.get("Auth") == "internal"
    assert parsed.node_boundary.get("App") == "internal"
    assert parsed.node_boundary.get("DB") == "internal"


def test_nodes_outside_boundary(parsed: ParsedDiagram) -> None:
    """User, GW, and Ext are NOT attributed to any boundary."""
    assert "User" not in parsed.node_boundary
    assert "GW" not in parsed.node_boundary
    assert "Ext" not in parsed.node_boundary


# 4. Chained edges


def test_chained_edge_line() -> None:
    """A single chained line ``A --> B --> C`` yields two edges and three nodes."""
    result = parse_mermaid("graph TD\nA --> B --> C\n")
    pairs = {(e.src, e.dst) for e in result.edges}
    assert ("A", "B") in pairs
    assert ("B", "C") in pairs
    assert "A" in result.nodes
    assert "B" in result.nodes
    assert "C" in result.nodes


# 5. Quoted node label


def test_quoted_label() -> None:
    """A quoted label ``X["Hello World"]`` is stored without the quotes."""
    result = parse_mermaid('graph TD\nX["Hello World"]\n')
    assert "X" in result.nodes
    assert result.nodes["X"].label == "Hello World"


# 6. Comment and directive stripping


def test_comment_line_ignored() -> None:
    """A pure ``%% comment`` line contributes no nodes or edges."""
    diagram = "graph TD\n%% this is a comment\nA --> B\n"
    result = parse_mermaid(diagram)
    assert "A" in result.nodes
    assert "B" in result.nodes
    assert len(result.edges) == 1


def test_directive_line_ignored() -> None:
    """A ``%%{ init: ... }%%`` directive line is ignored."""
    diagram = "%%{init: {'theme': 'default'}}%%\ngraph TD\nA --> B\n"
    result = parse_mermaid(diagram)
    assert "A" in result.nodes
    assert "B" in result.nodes


def test_inline_comment_stripped() -> None:
    """Trailing ``%% comment`` on an edge line is stripped before parsing."""
    diagram = "graph TD\nA --> B %% this edge goes somewhere\n"
    result = parse_mermaid(diagram)
    assert ("A", "B") in {(e.src, e.dst) for e in result.edges}


# 7. Malformed / empty input


def test_empty_string_returns_empty_diagram() -> None:
    """An empty string returns an empty ParsedDiagram without raising."""
    result = parse_mermaid("")
    assert isinstance(result, ParsedDiagram)
    assert not result.nodes
    assert not result.edges
    assert not result.boundaries
    assert not result.node_boundary


def test_garbage_input_does_not_raise() -> None:
    """Arbitrary garbage text returns an empty-ish diagram without raising."""
    result = parse_mermaid("!@#$%^&*()\nnot mermaid\n\x00\xff")
    assert isinstance(result, ParsedDiagram)


def test_none_equivalent_whitespace_only() -> None:
    """Whitespace-only input returns an empty diagram."""
    result = parse_mermaid("   \n\n\t  \n")
    assert not result.nodes
    assert not result.edges


# 8. Subgraph title variants


def test_subgraph_quoted_name() -> None:
    """``subgraph "DMZ"`` records id='DMZ' and title='DMZ'."""
    diagram = 'graph TD\nsubgraph "DMZ"\n  A\nend\n'
    result = parse_mermaid(diagram)
    assert "DMZ" in result.boundaries
    assert result.boundaries["DMZ"] == "DMZ"
    assert result.node_boundary.get("A") == "DMZ"


def test_subgraph_bracket_title() -> None:
    """``subgraph zone [Public Zone]`` records id='zone', title='Public Zone'."""
    diagram = "graph TD\nsubgraph zone [Public Zone]\n  B\nend\n"
    result = parse_mermaid(diagram)
    assert "zone" in result.boundaries
    assert result.boundaries["zone"] == "Public Zone"
    assert result.node_boundary.get("B") == "zone"


# 9. Additional shape coverage


def test_round_shape() -> None:
    """``id(label)`` declares a round shape."""
    result = parse_mermaid("graph TD\nN(My Round Node)\n")
    assert "N" in result.nodes
    assert result.nodes["N"].shape == "round"
    assert result.nodes["N"].label == "My Round Node"


def test_circle_shape() -> None:
    """``id((label))`` declares a circle shape."""
    result = parse_mermaid("graph TD\nN((Circle))\n")
    assert result.nodes["N"].shape == "circle"
    assert result.nodes["N"].label == "Circle"


def test_stadium_shape() -> None:
    """``id([label])`` declares a stadium shape."""
    result = parse_mermaid("graph TD\nN([Stadium])\n")
    assert result.nodes["N"].shape == "stadium"


def test_subroutine_shape() -> None:
    """``id[[label]]`` declares a subroutine shape."""
    result = parse_mermaid("graph TD\nN[[Subroutine]]\n")
    assert result.nodes["N"].shape == "subroutine"


def test_decision_shape() -> None:
    """``id{label}`` declares a decision shape."""
    result = parse_mermaid("graph TD\nN{Decision?}\n")
    assert result.nodes["N"].shape == "decision"


def test_flag_shape() -> None:
    """``id>label]`` declares a flag shape."""
    result = parse_mermaid("graph TD\nN>Flag Label]\n")
    assert result.nodes["N"].shape == "flag"


# 10. Inline edge labels via ``-- text -->``


def test_inline_text_edge_label() -> None:
    """``A -- my label --> B`` extracts the inline text as the edge label."""
    result = parse_mermaid("graph TD\nA -- my label --> B\n")
    assert len(result.edges) == 1
    assert result.edges[0].label == "my label"
    assert result.edges[0].src == "A"
    assert result.edges[0].dst == "B"


# 11. Flowchart keyword acceptance


def test_flowchart_keyword_accepted() -> None:
    """``flowchart LR`` header is accepted and does not create a node."""
    result = parse_mermaid("flowchart LR\nX --> Y\n")
    assert "X" in result.nodes
    assert "Y" in result.nodes
    # Header must not appear as a node.
    assert "flowchart" not in result.nodes
    assert "LR" not in result.nodes


# 12. Diagram without header is parsed leniently


def test_no_header_still_parses() -> None:
    """A diagram with no header line still extracts edges and nodes."""
    result = parse_mermaid("A --> B\nB --> C\n")
    assert "A" in result.nodes
    assert "B" in result.nodes
    assert "C" in result.nodes
    assert len(result.edges) == 2


# 13. UTF-8 BOM is stripped


def test_utf8_bom_stripped() -> None:
    """A leading UTF-8 BOM does not prevent parsing."""
    bom = "﻿"
    result = parse_mermaid(f"{bom}graph TD\nA --> B\n")
    assert "A" in result.nodes
    assert "B" in result.nodes


# 14. Dataclass field names match the public interface exactly


def test_mermaid_node_fields() -> None:
    """MermaidNode has exactly the fields: id, label, shape."""
    node = MermaidNode(id="X", label="My Node", shape="default")
    assert node.id == "X"
    assert node.label == "My Node"
    assert node.shape == "default"


def test_mermaid_edge_fields() -> None:
    """MermaidEdge has exactly the fields: src, dst, label."""
    edge = MermaidEdge(src="A", dst="B", label="go")
    assert edge.src == "A"
    assert edge.dst == "B"
    assert edge.label == "go"


def test_parsed_diagram_fields() -> None:
    """ParsedDiagram has exactly the fields: nodes, edges, boundaries, node_boundary."""
    diag = ParsedDiagram()
    assert isinstance(diag.nodes, dict)
    assert isinstance(diag.edges, list)
    assert isinstance(diag.boundaries, dict)
    assert isinstance(diag.node_boundary, dict)


# 15. Compact (no-space) edges and ';'-separated statements


def test_compact_edges_without_spaces_parse() -> None:
    """The compact ``A-->B`` form (no spaces, bare source id) still produces edges."""
    diagram = parse_mermaid("graph TD\nA-->B\nB-->C[(DB)]")
    edges = [(e.src, e.dst) for e in diagram.edges]
    assert ("A", "B") in edges
    assert ("B", "C") in edges
    assert "C" in diagram.nodes


def test_semicolon_separated_statements_parse() -> None:
    """Several statements on one physical line, separated by ``;``."""
    diagram = parse_mermaid("graph TD; A[Client]-->B[API]; B-->C[(DB)]")
    assert [(e.src, e.dst) for e in diagram.edges] == [("A", "B"), ("B", "C")]
    assert sorted(diagram.nodes) == ["A", "B", "C"]


def test_semicolon_inside_label_is_not_a_separator() -> None:
    """A ``;`` inside a quoted label is content, not a statement separator."""
    diagram = parse_mermaid('graph TD; A["a; b"]-->B')
    assert diagram.nodes["A"].label == "a; b"
    assert ("A", "B") in [(e.src, e.dst) for e in diagram.edges]
