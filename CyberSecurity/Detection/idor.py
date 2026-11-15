
from typing import Any


IDOR_RULES = {
    "IDOR-001": "Access to a resource was explicitly denied by authorization",
    "IDOR-002": "Resource ownership mismatch was explicitly reported",
}


def _no_detection() -> dict:
    return {
        "rule_detected": False,
        "attack_type": None,
        "severity": None,
        "confidence": 0.0,
        "evidence": [],
        "source": "security_rule",
    }


def detect_idor(event: dict) -> dict:
    """
    Identify explicit indicators of a broken access-control attempt.

    Expected optional fields:
      event["authorization"]["decision"]: "allow" or "deny"
      event["authorization"]["reason"]: "ownership_mismatch" or other text

    A denial alone is not proof of IDOR. Findings represent an explicit
    authorization mismatch signal supplied by upstream instrumentation.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    authorization: Any = event.get("authorization")

    if not isinstance(authorization, dict):
        return _no_detection()

    decision = authorization.get("decision")
    reason = authorization.get("reason")

    evidence = []

    if isinstance(decision, str) and decision.strip().lower() == "deny":
        evidence.append({
            "rule_id": "IDOR-001",
            "description": IDOR_RULES["IDOR-001"],
        })

    if (
        isinstance(reason, str)
        and reason.strip().lower() == "ownership_mismatch"
    ):
        evidence.append({
            "rule_id": "IDOR-002",
            "description": IDOR_RULES["IDOR-002"],
        })

    # Keep one evidence item per rule.
    unique_evidence = []
    seen_rule_ids = set()

    for item in evidence:
        if item["rule_id"] not in seen_rule_ids:
            unique_evidence.append(item)
            seen_rule_ids.add(item["rule_id"])

    if not unique_evidence:
        return _no_detection()

    return {
        "rule_detected": True,
        "attack_type": "Broken Access Control / IDOR Indicator",
        "severity": "High",
        "confidence": 0.0,
        "evidence": unique_evidence,
        "source": "security_rule",
    }
