"""
Serialization and formatting utilities for ThreatLens backend integration.
"""

import json
from typing import Any

from Integration.exceptions import SerializationError
from Integration.schemas import (
    ATTACK_NAME_ALIASES,
    ATTACK_PRIORITY,
    SEVERITY_BACKEND_MAP,
)


def serialize_evidence_to_text(evidence: list[dict[str, Any]]) -> str:
    """
    Format a list of evidence dictionaries into a clean text string.

    Complies with Django models.TextField and DRF serializers.CharField.
    Example output:
      "[SQLI-001] Suspicious SQL keyword combination; [SQLI-004] UNION-based pattern"
    """
    if not isinstance(evidence, list):
        raise SerializationError("evidence must be a list of dictionaries")

    entries = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        rule_id = item.get("rule_id", "RULE-UNKNOWN")
        desc = item.get("description", "").strip()
        detail = item.get("detail", "").strip()

        part = f"[{rule_id}] {desc}" if desc else f"[{rule_id}]"
        if detail:
            part += f" ({detail})"
        entries.append(part)

    return "; ".join(entries)


def serialize_evidence_to_json(evidence: list[dict[str, Any]]) -> str:
    """Serialize structured evidence list to JSON string for transport."""
    if not isinstance(evidence, list):
        raise SerializationError("evidence must be a list of dictionaries")
    return json.dumps(evidence)


def select_primary_attack_type(attack_types: list[str]) -> str:
    """
    Deterministically select a single primary attack type for backend Attack foreign key.

    When multiple detectors fire, the category with the highest security severity
    precedence in ATTACK_PRIORITY is selected as primary.
    """
    if not attack_types:
        return ""

    if len(attack_types) == 1:
        return attack_types[0]

    for candidate in ATTACK_PRIORITY:
        if candidate in attack_types:
            return candidate

    return attack_types[0]


def map_attack_name_to_backend(name: str) -> str:
    """Map internal attack name to the corresponding name in the backend Attack table."""
    return ATTACK_NAME_ALIASES.get(name, name)


def normalize_severity_to_backend(severity: str | None) -> str:
    """Map internal title-cased severity to lowercase Django choice ('low', 'medium', 'high', 'critical')."""
    if not severity:
        return "low"
    return SEVERITY_BACKEND_MAP.get(severity, severity.lower())

