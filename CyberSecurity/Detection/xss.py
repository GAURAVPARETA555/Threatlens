
import re
from typing import Any
from urllib.parse import unquote


XSS_RULES = {
    "XSS-001": "HTML script element pattern",
    "XSS-002": "HTML event-handler attribute pattern",
    "XSS-003": "JavaScript URI pattern",
}


# Limit input size to avoid spending excessive time on unexpectedly
# large request fields. This is not a substitute for request-size limits
# at the application or web-server level.
MAX_FIELD_LENGTH = 100_000
MAX_DECODE_PASSES = 2


def normalize_text(value: Any) -> str:
    """
    Convert request data to searchable text.

    Handles nested dictionaries/lists and common URL encoding.
    Does not execute or render supplied content.
    """

    if value is None:
        return ""

    if isinstance(value, dict):
        text = " ".join(
            f"{normalize_text(key)} {normalize_text(item)}"
            for key, item in value.items()
        )
    elif isinstance(value, (list, tuple)):
        text = " ".join(normalize_text(item) for item in value)
    else:
        text = str(value)

    text = text[:MAX_FIELD_LENGTH]

    for _ in range(MAX_DECODE_PASSES):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded

    return re.sub(r"\s+", " ", text).strip().lower()


def extract_request_data(event: dict) -> str:
    """
    Extract relevant request fields without changing the original event.
    """

    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    fields = ("path", "query", "body")
    parts = []

    for field in fields:
        value = event.get(field)
        if value is not None:
            parts.append(normalize_text(value))

    return " ".join(parts)


def detect_xss(event: dict) -> dict:
    """
    Detect common XSS-related input patterns.

    A match indicates suspicious input, not proof of a vulnerability
    or successful exploitation. Confidence remains 0.0 until a
    validated scoring method is established.
    """

    request_data = extract_request_data(event)
    evidence = []

    patterns = (
        ("XSS-001", re.compile(r"<\s*script\b", re.IGNORECASE)),
        (
            "XSS-002",
            re.compile(
                r"\bon(?:error|load|click|mouseover|focus|submit)\s*=",
                re.IGNORECASE,
            ),
        ),
        (
            "XSS-003",
            re.compile(r"\bjavascript\s*:", re.IGNORECASE),
        ),
    )

    for rule_id, pattern in patterns:
        if pattern.search(request_data):
            evidence.append({
                "rule_id": rule_id,
                "description": XSS_RULES[rule_id],
            })

    detected = bool(evidence)

    return {
        "attack_type": "Cross-Site Scripting (XSS)" if detected else None,
        "severity": "High" if detected else None,
        "confidence": 0.0,
        "evidence": evidence,
        "source": "security_rule",
        "rule_detected": detected,
    }
