"""Committed config and exceptions files for the assessment gate.

Two optional, committed files, both auto-discovered in `.cra/` and overridable
with a flag:

  - the gate config (`.cra/assessment-gate.yaml`): which gap conditions block,
    and where the matrix and exceptions files live. Same strict-unknown-key
    discipline as the check policy file: a typo must not silently disable a gate.
  - the exceptions file (`.cra/assessment-exceptions.yaml`): per-requirement
    justifications. An entry can justify a Part I(2) not-applicable decision, or
    record that a mandatory duty is addressed elsewhere, without editing the
    generated matrix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cra_evidence_cli.assessment.requirements import CANONICAL_KEYS, is_waivable
from cra_evidence_cli.exceptions import ConfigurationError

DEFAULT_GATE_PATH = Path(".cra/assessment-gate.yaml")
DEFAULT_MATRIX_PATH = Path(".cra/assessment.yaml")
DEFAULT_EXCEPTIONS_PATH = Path(".cra/assessment-exceptions.yaml")

# Gap conditions the gate can block on.
CONDITION_MISSING_MANDATORY = "missing_mandatory"
CONDITION_UNJUSTIFIED_WAIVER = "unjustified_waiver"
FAIL_ON_CHOICES = (CONDITION_MISSING_MANDATORY, CONDITION_UNJUSTIFIED_WAIVER)

_GATE_ALLOWED_KEYS = {"fail_on", "matrix", "exceptions"}

EXCEPTIONS_KIND = "cra-assessment-exceptions"
EXCEPTIONS_SCHEMA_VERSION = 1
EXCEPTION_STATUSES = ("not_applicable", "addressed_elsewhere")


@dataclass
class GateConfig:
    """Parsed `.cra/assessment-gate.yaml`."""

    fail_on: tuple[str, ...] = FAIL_ON_CHOICES
    matrix_path: Path | None = None
    exceptions_path: Path | None = None
    source_path: Path | None = None


@dataclass
class ExceptionEntry:
    """One committed justification for a requirement."""

    key: str
    status: str
    justification: str


@dataclass
class ExceptionsFile:
    """Parsed `.cra/assessment-exceptions.yaml`, indexed by canonical key."""

    by_key: dict[str, ExceptionEntry] = field(default_factory=dict)
    source_path: Path | None = None


def load_gate_config(explicit_path: Path | None) -> GateConfig | None:
    """Load the gate config. Returns None when no file is present (auto-discovery miss)."""
    if explicit_path is not None:
        path = explicit_path
        if not path.exists():
            msg = f"Gate config file not found: {path}"
            raise ConfigurationError(msg)
    else:
        path = DEFAULT_GATE_PATH
        if not path.exists():
            return None

    data = _read_yaml_mapping(path)
    if data is None:
        return GateConfig(source_path=path)

    unknown = sorted(set(data) - _GATE_ALLOWED_KEYS)
    if unknown:
        msg = (
            f"Unknown key(s) in gate config {path}: {', '.join(unknown)}. "
            f"Allowed keys: {', '.join(sorted(_GATE_ALLOWED_KEYS))}."
        )
        raise ConfigurationError(msg)

    config = GateConfig(source_path=path)

    if "fail_on" in data and data["fail_on"] is not None:
        value = data["fail_on"]
        items = [value] if isinstance(value, str) else value
        if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
            msg = "Gate config 'fail_on' must be a string or a list of strings."
            raise ConfigurationError(msg)
        normalized = []
        for item in items:
            lowered = item.strip().lower()
            if lowered not in FAIL_ON_CHOICES:
                msg = (
                    f"Gate config 'fail_on' value {item!r} is invalid; "
                    f"expected any of {', '.join(FAIL_ON_CHOICES)}."
                )
                raise ConfigurationError(msg)
            normalized.append(lowered)
        config.fail_on = tuple(dict.fromkeys(normalized))

    if "matrix" in data and data["matrix"] is not None:
        config.matrix_path = Path(_require_str(data["matrix"], "matrix"))
    if "exceptions" in data and data["exceptions"] is not None:
        config.exceptions_path = Path(_require_str(data["exceptions"], "exceptions"))

    return config


def load_exceptions(explicit_path: Path | None) -> ExceptionsFile:
    """Load the exceptions file. An absent auto-discovered file yields an empty set."""
    if explicit_path is not None:
        path = explicit_path
        if not path.exists():
            msg = f"Exceptions file not found: {path}"
            raise ConfigurationError(msg)
    else:
        path = DEFAULT_EXCEPTIONS_PATH
        if not path.exists():
            return ExceptionsFile()

    data = _read_yaml_mapping(path)
    if data is None:
        return ExceptionsFile(source_path=path)

    if data.get("kind") != EXCEPTIONS_KIND:
        msg = f"Exceptions file {path} must have kind: {EXCEPTIONS_KIND}."
        raise ConfigurationError(msg)
    if data.get("schema_version") != EXCEPTIONS_SCHEMA_VERSION:
        msg = (
            f"Exceptions file {path} has unsupported schema_version "
            f"{data.get('schema_version')!r}; expected {EXCEPTIONS_SCHEMA_VERSION}."
        )
        raise ConfigurationError(msg)

    raw_list = data.get("exceptions") or []
    if not isinstance(raw_list, list):
        msg = f"Exceptions file {path}: 'exceptions' must be a list."
        raise ConfigurationError(msg)

    by_key: dict[str, ExceptionEntry] = {}
    for index, raw in enumerate(raw_list):
        if not isinstance(raw, dict):
            msg = f"Exceptions file {path}: exceptions[{index}] must be a mapping."
            raise ConfigurationError(msg)
        key = raw.get("key")
        if key not in CANONICAL_KEYS:
            msg = f"Exceptions file {path}: exceptions[{index}] has unknown key {key!r}."
            raise ConfigurationError(msg)
        status = _require_str(raw.get("status"), f"exceptions[{index}].status")
        if status not in EXCEPTION_STATUSES:
            msg = (
                f"Exceptions file {path}: exceptions[{index}] status {status!r} is invalid; "
                f"expected one of {', '.join(EXCEPTION_STATUSES)}."
            )
            raise ConfigurationError(msg)
        if status == "not_applicable" and not is_waivable(str(key)):
            msg = (
                f"Exceptions file {path}: exceptions[{index}] marks mandatory requirement "
                f"{key!r} not-applicable, which is not permitted. Use status "
                f"'addressed_elsewhere' to record how the duty is met."
            )
            raise ConfigurationError(msg)
        justification = _require_str(
            raw.get("justification"), f"exceptions[{index}].justification"
        ).strip()
        if not justification:
            msg = (
                f"Exceptions file {path}: exceptions[{index}] for {key!r} needs a "
                f"non-empty justification."
            )
            raise ConfigurationError(msg)
        if key in by_key:
            msg = f"Exceptions file {path}: duplicate exception for {key!r}."
            raise ConfigurationError(msg)
        by_key[str(key)] = ExceptionEntry(
            key=str(key), status=status, justification=justification
        )

    return ExceptionsFile(by_key=by_key, source_path=path)


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str):
        msg = f"'{label}' must be a string, got {type(value).__name__}."
        raise ConfigurationError(msg)
    return value


def _read_yaml_mapping(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Failed to read {path}: {exc}"
        raise ConfigurationError(msg) from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"Failed to parse {path}: {exc}"
        raise ConfigurationError(msg) from exc
    if data is None:
        return None
    if not isinstance(data, dict):
        msg = f"{path} must contain a YAML mapping at the top level, got {type(data).__name__}."
        raise ConfigurationError(msg)
    return data
