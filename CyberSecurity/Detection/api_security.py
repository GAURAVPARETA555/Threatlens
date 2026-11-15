
from typing import Any


API_SECURITY_RULES = {
    "API-001": "API request explicitly rejected due to invalid authentication",
    "API-002": "API request explicitly rejected due to an invalid API key",
    "API-003": "API request explicitly rejected by rate limiting",
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


def detect_api_security(event: dict) -> dict:
    """
    Detect explicit API security enforcement indicators.

    Expected optional event fields:
      event["api_security"]["authentication_status"]
      event["api_security"]["api_key_status"]
      event["api_security"]["rate_limited"]

    This detector relies on trustworthy security telemetry.
    It does not independently validate credentials or prove an attack.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    api_security: Any = event.get("api_security")

    if not isinstance(api_security, dict):
        return _no_detection()

    evidence = []

    if api_security.get("authentication_status") == "rejected":
        evidence.append({
            "rule_id": "API-001",
            "description": API_SECURITY_RULES["API-001"],
        })

    if api_security.get("api_key_status") == "invalid":
        evidence.append({
            "rule_id": "API-002",
            "description": API_SECURITY_RULES["API-002"],
        })

    if api_security.get("rate_limited") is True:
        evidence.append({
            "rule_id": "API-003",
            "description": API_SECURITY_RULES["API-003"],
        })

    if not evidence:
        return _no_detection()

    return {
        "rule_detected": True,
        "attack_type": "API Security Indicator",
        "severity": "Medium",
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
    }
