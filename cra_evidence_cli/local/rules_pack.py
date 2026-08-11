"""Metadata and inventory helpers for the bundled SAST rule pack."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

PACK_VERSION = "3.0.0"
TESTED_OPENGREP_VERSION = "1.26.0"

VALID_RULE_TIERS = frozenset({"default", "experimental"})


@dataclass(frozen=True)
class RulePackInventory:
    rule_tiers: dict[str, str]
    rule_languages: dict[str, str]

    @property
    def experimental_rule_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                rule_id
                for rule_id, tier in self.rule_tiers.items()
                if tier == "experimental"
            )
        )

    @property
    def experimental_only_languages(self) -> tuple[str, ...]:
        """Languages whose rules are all experimental, so a default run skips them.

        Derived from the pack rather than listed, so promoting a rule to the
        default tier cannot leave a message claiming its language is disabled.
        """
        with_default: set[str] = set()
        seen: set[str] = set()
        for rule_id, tier in self.rule_tiers.items():
            language = self.rule_languages[rule_id]
            seen.add(language)
            if tier == "default":
                with_default.add(language)
        return tuple(sorted(seen - with_default))

    def selection(
        self,
        *,
        include_experimental: bool,
        excluded_rule_ids: tuple[str, ...] = (),
    ) -> tuple[int, int, dict[str, int]]:
        excluded = set(excluded_rule_ids)
        default_count = 0
        experimental_count = 0
        language_counts: dict[str, int] = {}
        for rule_id, tier in self.rule_tiers.items():
            if rule_id in excluded or (tier == "experimental" and not include_experimental):
                continue
            if tier == "default":
                default_count += 1
            else:
                experimental_count += 1
            language = self.rule_languages[rule_id]
            language_counts[language] = language_counts.get(language, 0) + 1
        return default_count, experimental_count, dict(sorted(language_counts.items()))


def inspect_rule_pack(rules_root: Path) -> RulePackInventory:
    rule_tiers: dict[str, str] = {}
    rule_languages: dict[str, str] = {}
    for rule_path in sorted(rules_root.rglob("*.yaml")):
        document = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        rules = document.get("rules") if isinstance(document, dict) else None
        if not isinstance(rules, list) or len(rules) != 1:
            message = f"invalid bundled rule file: {rule_path}"
            raise ValueError(message)
        rule = rules[0]
        rule_id = rule.get("id")
        metadata = rule.get("metadata") or {}
        tier = metadata.get("tier")
        if not isinstance(rule_id, str) or tier not in VALID_RULE_TIERS:
            message = f"invalid bundled rule tier: {rule_path}"
            raise ValueError(message)
        if rule_id in rule_tiers:
            message = f"duplicate bundled rule id: {rule_id}"
            raise ValueError(message)
        rule_tiers[rule_id] = tier
        rule_languages[rule_id] = rule_path.relative_to(rules_root).parts[0]
    return RulePackInventory(rule_tiers, rule_languages)
