"""Canonical CRA Annex I essential-requirement registry.

The 22 canonical keys for the Annex I essential cybersecurity requirements:
Part I(1), the thirteen Part I(2) letters (a) to (m), and the eight Part II
vulnerability-handling duties. This is the single key scheme the matrix, the
templates, and the gate all reference.

Legal basis (CRA Article 13):
  - Article 13(3): the risk assessment indicates *whether* the Part I(2)
    requirements are applicable and how they are implemented, and indicates
    *how* the manufacturer applies Part I(1) and the Part II vulnerability
    handling requirements. So only Part I(2)(a) to (m) may be marked
    not-applicable; Part I(1) and every Part II duty are mandatory.
  - Article 13(4): where a requirement is not applicable, the manufacturer
    includes a clear justification in the technical documentation.

`waivable` is True only for the Part I(2) letters. `conditionality` records an
implementation condition that the Annex text itself states (for example "where
applicable" or a tailor-made business-user exception); a condition is not a
waiver and does not make a requirement not-applicable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Requirement:
    """One canonical Annex I essential requirement."""

    key: str
    annex_ref: str
    label: str
    part: str  # "I.1", "I.2", or "II"
    waivable: bool
    conditionality: str | None = None


REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "part_i_1", "Annex I Part I(1)", "Risk-appropriate cybersecurity", "I.1", False
    ),
    Requirement(
        "part_i_2_a", "Annex I Part I(2)(a)", "No known exploitable vulnerabilities", "I.2", True
    ),
    Requirement(
        "part_i_2_b", "Annex I Part I(2)(b)", "Secure by default configuration", "I.2", True,
        "Tailor-made business-user exception; product can be reset to its original state.",
    ),
    Requirement(
        "part_i_2_c", "Annex I Part I(2)(c)", "Security updates", "I.2", True,
        "Automatic updates where applicable, with a clear opt-out and update notification.",
    ),
    Requirement(
        "part_i_2_d", "Annex I Part I(2)(d)", "Protection from unauthorised access", "I.2", True,
    ),
    Requirement(
        "part_i_2_e", "Annex I Part I(2)(e)", "Confidentiality of data", "I.2", True,
    ),
    Requirement(
        "part_i_2_f", "Annex I Part I(2)(f)", "Integrity of data", "I.2", True,
    ),
    Requirement(
        "part_i_2_g", "Annex I Part I(2)(g)", "Data minimisation", "I.2", True,
    ),
    Requirement(
        "part_i_2_h", "Annex I Part I(2)(h)", "Availability of essential functions", "I.2", True,
    ),
    Requirement(
        "part_i_2_i", "Annex I Part I(2)(i)",
        "Minimise impact on other devices and networks", "I.2", True,
    ),
    Requirement(
        "part_i_2_j", "Annex I Part I(2)(j)", "Limit attack surface", "I.2", True,
    ),
    Requirement(
        "part_i_2_k", "Annex I Part I(2)(k)", "Exploitation mitigation", "I.2", True,
    ),
    Requirement(
        "part_i_2_l", "Annex I Part I(2)(l)", "Security logging and monitoring", "I.2", True,
        "Opt-out mechanism for the user.",
    ),
    Requirement(
        "part_i_2_m", "Annex I Part I(2)(m)", "Secure data and settings removal", "I.2", True,
        "Secure transfer applies where data can be transferred to other products or systems.",
    ),
    Requirement(
        "part_ii_1", "Annex I Part II(1)",
        "Identify and document vulnerabilities, including an SBOM", "II", False,
    ),
    Requirement(
        "part_ii_2", "Annex I Part II(2)", "Remediate vulnerabilities without delay", "II", False,
        "Security updates provided separately from feature updates where technically feasible.",
    ),
    Requirement(
        "part_ii_3", "Annex I Part II(3)", "Regular security testing and reviews", "II", False,
    ),
    Requirement(
        "part_ii_4", "Annex I Part II(4)",
        "Public disclosure of fixed vulnerabilities", "II", False,
        "Disclosure may be delayed in duly justified cases until users can apply the patch.",
    ),
    Requirement(
        "part_ii_5", "Annex I Part II(5)",
        "Coordinated vulnerability disclosure policy", "II", False,
    ),
    Requirement(
        "part_ii_6", "Annex I Part II(6)",
        "Facilitate vulnerability information sharing and a reporting contact", "II", False,
    ),
    Requirement(
        "part_ii_7", "Annex I Part II(7)", "Secure distribution of updates", "II", False,
        "Automatic distribution where applicable for security updates.",
    ),
    Requirement(
        "part_ii_8", "Annex I Part II(8)",
        "Timely free security updates with advisory messages", "II", False,
        "Tailor-made business-user free-of-charge exception.",
    ),
)

BY_KEY: dict[str, Requirement] = {req.key: req for req in REQUIREMENTS}
CANONICAL_KEYS: tuple[str, ...] = tuple(req.key for req in REQUIREMENTS)
WAIVABLE_KEYS: frozenset[str] = frozenset(req.key for req in REQUIREMENTS if req.waivable)
# Part I(1) plus every Part II duty: mandatory, never not-applicable.
MANDATORY_KEYS: tuple[str, ...] = tuple(req.key for req in REQUIREMENTS if not req.waivable)
PART_II_KEYS: tuple[str, ...] = tuple(req.key for req in REQUIREMENTS if req.part == "II")


def is_waivable(key: str) -> bool:
    """Return True if the requirement may be marked not-applicable (Part I(2) only)."""
    return key in WAIVABLE_KEYS
