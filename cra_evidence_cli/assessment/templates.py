"""Bundled product-type starter templates.

Each template is a YAML data file shipped inside the package. A template carries
a product-type applicability default (which Part I(2) letters are typically
not-applicable for the class, each with a justification prompt), a curated set of
starter risks, and a curated set of starter controls. The risks and controls are
rendered into the same Gemara RiskCatalog / ControlCatalog shapes the existing
scaffold commands produce, so they validate and upload the same way.

Templates are starters, not assessments: every justification and implementation
field is a prompt for the developer to complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any

import yaml

from cra_evidence_cli.assessment.matrix import AssessmentMatrix, build_matrix
from cra_evidence_cli.assessment.requirements import is_waivable

_TEMPLATES_PACKAGE = "cra_evidence_cli.assessment"
_TEMPLATES_SUBDIR = "templates"


def _templates_dir():
    """The bundled templates directory as an importlib.resources traversable."""
    return files(_TEMPLATES_PACKAGE).joinpath(_TEMPLATES_SUBDIR)


class TemplateError(ValueError):
    """Raised when a bundled template is missing or malformed."""


@dataclass
class RiskItem:
    id: str
    title: str
    description: str
    group: str
    severity: str
    impact: str
    recommended: bool = True


@dataclass
class ControlItem:
    id: str
    title: str
    objective: str
    group: str
    recommended: bool = True


@dataclass
class Template:
    id: str
    title: str
    description: str
    detect_files: list[str] = field(default_factory=list)
    detect_manifests: list[str] = field(default_factory=list)
    not_applicable: dict[str, str] = field(default_factory=dict)
    how_applied: dict[str, str] = field(default_factory=dict)
    risks: list[RiskItem] = field(default_factory=list)
    controls: list[ControlItem] = field(default_factory=list)


_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _slug(value: str) -> str:
    out: list[str] = []
    prev_dash = False
    for ch in (value or "").lower():
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    return "".join(out).strip("-") or "product"


def _parse_template(template_id: str, data: Any) -> Template:
    if not isinstance(data, dict):
        msg = f"template {template_id!r} must be a YAML mapping."
        raise TemplateError(msg)
    if data.get("id") != template_id:
        msg = f"template file {template_id!r} declares id {data.get('id')!r}; they must match."
        raise TemplateError(msg)

    applicability = data.get("applicability") or {}
    not_applicable = applicability.get("not_applicable") or {}
    how_applied = applicability.get("how_applied") or {}
    if not isinstance(not_applicable, dict) or not isinstance(how_applied, dict):
        msg = f"template {template_id!r}: applicability blocks must be mappings."
        raise TemplateError(msg)
    bad = [key for key in not_applicable if not is_waivable(key)]
    if bad:
        msg = (
            f"template {template_id!r}: only Part I(2) keys may be not-applicable; "
            f"got {', '.join(sorted(bad))}."
        )
        raise TemplateError(msg)
    blank = [key for key, value in not_applicable.items() if not str(value).strip()]
    if blank:
        msg = (
            f"template {template_id!r}: not-applicable entries need a justification; "
            f"blank for {', '.join(sorted(blank))}."
        )
        raise TemplateError(msg)

    detect = data.get("detect") or {}
    risks = [_parse_risk(template_id, index, raw)
             for index, raw in enumerate(data.get("risks") or [])]
    controls = [_parse_control(template_id, index, raw)
                for index, raw in enumerate(data.get("controls") or [])]

    return Template(
        id=template_id,
        title=str(data.get("title") or template_id),
        description=str(data.get("description") or ""),
        detect_files=[str(item) for item in (detect.get("files") or [])],
        detect_manifests=[str(item) for item in (detect.get("manifests") or [])],
        not_applicable={str(k): str(v) for k, v in not_applicable.items()},
        how_applied={str(k): str(v) for k, v in how_applied.items()},
        risks=risks,
        controls=controls,
    )


def _parse_risk(template_id: str, index: int, raw: Any) -> RiskItem:
    if not isinstance(raw, dict):
        msg = f"template {template_id!r}: risks[{index}] must be a mapping."
        raise TemplateError(msg)
    severity = str(raw.get("severity") or "Medium")
    if severity not in _SEVERITIES:
        msg = f"template {template_id!r}: risks[{index}] severity {severity!r} is invalid."
        raise TemplateError(msg)
    return RiskItem(
        id=str(raw.get("id") or f"R{index + 1:02d}"),
        title=str(raw.get("title") or ""),
        description=str(raw.get("description") or ""),
        group=str(raw.get("group") or "general"),
        severity=severity,
        impact=str(raw.get("impact") or "[Describe the business, safety and compliance impact]"),
        recommended=bool(raw.get("recommended", True)),
    )


def _parse_control(template_id: str, index: int, raw: Any) -> ControlItem:
    if not isinstance(raw, dict):
        msg = f"template {template_id!r}: controls[{index}] must be a mapping."
        raise TemplateError(msg)
    return ControlItem(
        id=str(raw.get("id") or f"C{index + 1:02d}"),
        title=str(raw.get("title") or ""),
        objective=str(raw.get("objective") or "[Explain what this control achieves]"),
        group=str(raw.get("group") or "general"),
        recommended=bool(raw.get("recommended", True)),
    )


def list_templates() -> list[Template]:
    """Load every bundled template, sorted by id."""
    templates: list[Template] = []
    for resource in _templates_dir().iterdir():
        name = resource.name
        if not name.endswith(".yaml"):
            continue
        template_id = name[: -len(".yaml")]
        templates.append(_parse_template(template_id, yaml.safe_load(resource.read_text("utf-8"))))
    return sorted(templates, key=lambda template: template.id)


def template_ids() -> list[str]:
    return [template.id for template in list_templates()]


def load_template(template_id: str) -> Template:
    """Load one bundled template by id."""
    resource = _templates_dir() / f"{template_id}.yaml"
    if not resource.is_file():
        available = ", ".join(template_ids())
        msg = f"unknown template {template_id!r}. Available: {available}."
        raise TemplateError(msg)
    return _parse_template(template_id, yaml.safe_load(resource.read_text("utf-8")))


def build_applicability_matrix(template: Template, product: str | None) -> AssessmentMatrix:
    """Build the applicability matrix from a template's product-type defaults."""
    return build_matrix(
        product=product,
        template_id=template.id,
        not_applicable=template.not_applicable,
        how_applied=template.how_applied,
    )


def _author(org: str | None) -> dict[str, str]:
    return {"id": "security-team", "name": org or "Security Team", "type": "Human"}


def build_risk_catalog(
    template: Template, product: str | None, org: str | None, selected_ids: set[str]
) -> dict[str, Any]:
    """Render selected template risks into the Gemara RiskCatalog shape."""
    chosen = [risk for risk in template.risks if risk.id in selected_ids]
    slug = _slug(product or template.id)
    groups = _risk_groups(chosen)
    return {
        "title": f"{product or template.title} - Risk Catalog",
        "metadata": {
            "id": f"{slug}-risk-catalog",
            "type": "RiskCatalog",
            "gemara-version": "1.0.0",
            "description": f"Cybersecurity risk starter for a {template.title}.",
            "version": "1.0.0",
            "author": _author(org),
        },
        "groups": groups,
        "risks": [
            {
                "id": risk.id,
                "title": risk.title,
                "description": risk.description,
                "group": risk.group,
                "severity": risk.severity,
                "impact": risk.impact,
            }
            for risk in chosen
        ],
    }


def _risk_groups(risks: list[RiskItem]) -> list[dict[str, str]]:
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    rank_severity = {value: key for key, value in severity_rank.items()}
    groups: dict[str, int] = {}
    for risk in risks:
        groups[risk.group] = max(groups.get(risk.group, 0), severity_rank.get(risk.severity, 2))
    return [
        {
            "id": group,
            "title": group.replace("-", " ").title(),
            "description": f"Risks grouped under {group.replace('-', ' ')}.",
            "appetite": "Low",
            "max-severity": rank_severity.get(max_rank, "High"),
        }
        for group, max_rank in groups.items()
    ]


def merge_template_risks(doc: dict[str, Any], template: Template) -> dict[str, Any]:
    """Prepend a template's recommended risks (and groups) into a RiskCatalog doc.

    Used by the scaffold commands so '--template' layers product-type risks on top
    of the SBOM-seeded entries. All risk ids are renumbered to stay unique.
    """
    chosen = [risk for risk in template.risks if risk.recommended]
    if not chosen:
        return doc
    template_risks = [
        {
            "id": "",
            "title": risk.title,
            "description": risk.description,
            "group": risk.group,
            "severity": risk.severity,
            "impact": risk.impact,
        }
        for risk in chosen
    ]
    merged = template_risks + list(doc.get("risks", []))
    for index, risk in enumerate(merged, start=1):
        risk["id"] = f"R{index:02d}"
    doc["risks"] = merged
    existing = {group["id"] for group in doc.get("groups", [])}
    doc["groups"] = list(doc.get("groups", [])) + [
        group for group in _risk_groups(chosen) if group["id"] not in existing
    ]
    return doc


def build_control_catalog(
    template: Template, product: str | None, org: str | None, selected_ids: set[str]
) -> dict[str, Any]:
    """Render selected template controls into the Gemara ControlCatalog shape."""
    chosen = [control for control in template.controls if control.id in selected_ids]
    slug = _slug(product or template.id)
    group_ids = list(dict.fromkeys(control.group for control in chosen))
    return {
        "title": f"{product or template.title} - Control Catalog",
        "metadata": {
            "id": f"{slug}-control-catalog",
            "type": "ControlCatalog",
            "gemara-version": "1.0.0",
            "description": f"Security controls starter for a {template.title}.",
            "version": "1.0.0",
            "author": _author(org),
            "applicability-groups": [
                {
                    "id": "all-products",
                    "title": "All products",
                    "description": "Default applicability scope for this product.",
                }
            ],
        },
        "groups": [
            {
                "id": group,
                "title": group.replace("-", " ").title(),
                "description": f"Controls grouped under {group.replace('-', ' ')}.",
            }
            for group in group_ids
        ],
        "controls": [
            {
                "id": control.id,
                "title": control.title,
                "objective": control.objective,
                "group": control.group,
                "state": "Active",
                "assessment-requirements": [
                    {
                        "id": f"{control.id}-AR01",
                        "text": "[State the assessment requirement as a MUST statement]",
                        "applicability": ["all-products"],
                        "state": "Active",
                    }
                ],
            }
            for control in chosen
        ],
    }
